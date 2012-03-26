def _authorize_anonymous(path):
    """Given the path part of an URL, return a boolean.
    """
    if path in ('/favicon.ico', '/robots.txt'): # special cases
        return True
    if path and path.startswith('/anonymous/'): # logging in
        return True
    return False

def inbound(request):
    """Authenticate from a cookie.
    """
    session = {}
    if 'session_id' in request.cookie:
        session_id = request.cookie['session_id'].value
        session = sessions.get(session_id, {})

    request.user = User(session)
    if not session:
        if not _authorize_anonymous(request.path.raw):
            raise Response(401) # use nice error messages for login form

def outbound(response):
    session = response.request.user.session
    if not session:                                 # user is anonymous
        if 'session_id' not in response.request.cookie:
            # no cookie in the request, don't set one on response
            return
        else:
            # expired cookie in the request, instruct browser to delete it
            response.cookie['session_id'] = '' 
            expires = 0
    else:                                           # user is authenticated
        response.headers.set('Expires', BEGINNING_OF_EPOCH) # don't cache
        response.cookie['session_id'] = session['_id']
        expires = session['expires'] = time.time() + TIMEOUT

    cookie = response.cookie['session_id']
    # I am not setting domain, because it is supposed to default to what we 
    # want: the domain of the object requested.
    #cookie['domain']
    cookie['path'] = '/'
    cookie['expires'] = rfc822.formatdate(expires)
    cookie['httponly'] = "Yes, please."

def startup(website):
    """Read in configuration.
    """
    global backend
    log.info('aspen.authentication.startup')
 
    
    # Backend
    # =======
    # For development offline we provide a stub backend that doesn't hit LDAP.

    if website.conf.aspen['auth_backend'] is MissedConnection:
        log.warning("auth backend not configured, using stub authentication")
        backend = StubBackend()
    else:
        log.info("ldap configured, using normal authentication")
        backend = ldap_

    
    # Start sync thread.
    # ==================
    # Once primed, we have an async thread to keep mongo in sync. So if we go
    # down hard, we lose a little bit of session state, plus whatever mongo
    # hadn't flushed to disk in time. Since we assume a one to one between http
    # and mongo, we only *read* from mongo on startup.

    spec = {'_id': {'$nin': sessions.keys()}}
    for session in dbs.ours.sessions.find(spec):
        sessions[session['_id']] = session

    Periodic(flush_sessions, seconds=5).start()
