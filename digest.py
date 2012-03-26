#  By Josh Goldoot
# version 0.01
#  Public domain.
# from http://www.autopond.com/digestauth.py

import random, time, re

try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5


class MalformedAuthenticationHeader(Exception): pass

## wrapper bits that currently use web.py

class WebPyHTTPProvider:

    def auth_header(self, default):
        import web
        return web.ctx.environ.get('HTTP_AUTHORIZATION', default)

    def user_agent(self):
        import web
        return web.ctx.environ['HTTP_USER_AGENT']

    def request_method(self):
        import web
        return web.ctx.environ['REQUEST_METHOD']

    def path_and_query(self):
        import web
        return web.ctx.fullpath

    def send400(self, html, extraheaders):
        import web
        web.ctx.status ='400 Bad Request'
        for k, v in extraheaders:
            web.header(k, v)
        return html        

    def send401(self, html, extraheaders):
        import web
        web.ctx.status = '401 Unauthorized'
        for k, v in extraheaders:
            web.header(k, v)
        return html        

    def send403(self, html, extraheaders):
        import web
        web.ctx.status = '403 Forbidden'
        for k, v in extraheaders:
            web.header(k, v)
        return html        


class DigestAuthWrapper(object):

    def __init__(self, *args, **kw):
        kw['HTTPProvider'] = WebPyHTTPProvider()
        self.auth = Auth(*args, **kw)

    def __call__(self, f):
        def wrapper(*args, **kw):
            authed, result = self.auth.authorized()
            if authed:
                return f(*args, **kw)
            return result
        return wrapper


## wrapper bits 

class AspenHTTPProvider:

    def set_request(self, request):
        self.request = request

    def auth_header(self, default):
        return self.request.headers.one('Authorization', default)

    def user_agent(self):
        return self.request.headers.one('User-Agent')

    def request_method(self):
        return self.request.method

    def path_and_query(self):
        return self.request.url

    def send400(self, html, extraheaders):
        raise Response(400, 'Bad Request', extraheaders)

    def send401(self, html, extraheaders):
        raise Response(401, 'Unauthorized', extraheaders)

    def send403(self, html, extraheaders):
        raise Response(403, 'Forbidden', extraheaders)


## allow test users

def test_HA1(username, realm):
    users = { 'guest':'guest',
            }
    password = users[username] 
    return H(':'.join([username, realm, password]))


## make a container that aspen will like

my_provider = AspenHTTPProvider()
my_auth = Auth(test_HA1, HTTPProvider=my_provider)

def inbound(request):
    global my_auth
    global my_provider
    my_provider.set_request(request)
    authed, response = my_auth.authorized()


## Fundamental utilities


class Storage(dict):
    """
    (from web.py)
    A Storage object is like a dictionary except `obj.foo` can be used
    in addition to `obj['foo']`.

        >>> o = storage(a=1)
        >>> o.a
        1
        >>> o['a']
        1
        >>> o.a = 2
        >>> o['a']
        2
        >>> del o.a
        >>> o.a
        Traceback (most recent call last):
            ...
        AttributeError: 'a'

    """
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError, k:
            raise AttributeError, k

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError, k:
            raise AttributeError, k

    def __repr__(self):
        return '<Storage ' + dict.__repr__(self) + '>'


## Actual authentication obj

class Auth(object):
    """A decorator class implementing digest authentication (RFC 2617)"""
    def __init__(self,  getHA1,  realm="Protected",  tolerateIE = True, redirectURL = '/newuser',  unauthHTML = None,  nonceSkip = 0,  lockTime = 20,  nonceLife = 180,  tries=3,  domain=[], HTTPProvider=None):
        """Creates a decorator specific to a particular web application. 
            getHA1: a function taking the arguments (username, realm), and returning digestauth.H(username:realm:password), or
                            throwing KeyError if no such user
            realm: the authentication "realm"
            tolerateIE: don't deny requests from Internet Explorer, even though it is standards uncompliant and kind of insecure
            redirectURL:  when user hits "cancel," they are redirected here
            unauthHTML:  the HTML that is sent to the user and displayed if they hit cancel (default is a redirect page to redirectURL)
            nonceSkip: tolerate skips in the nonce count, only up to this amount (useful if CSS or JavaScript is being loaded unbeknownst to your code)
            lockTime: number of seconds a user is locked out if they send a wrong password (tries) times
            nonceLife: number of seconds a nonce remains valid
            tries: number of tries a user gets to enter a correct password before the account is locked for lockTime seconds
            HTTPProvider: interface to HTTP protocol workings (see above code)
        """
        self.http = HTTPProvider
        if self.http is None:
            raise Exception("no HTTPProvider provided")
        self.getHA1,  self.realm,  self.tolerateIE,  self.nonceSkip = (getHA1,  realm,  tolerateIE,  nonceSkip)
        self.lockTime,  self.tries,  self.nonceLife,  self.domain = (lockTime,  tries - 1,  nonceLife,  domain)
        self.unauthHTML = unauthHTML or self.g401HTML.replace("$redirecturl",  redirectURL)
        self.outstandingNonces = NonceMemory()
        self.user_status = {}
        self.opaque = "%032x" % random.getrandbits(128)

    g401HTML = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="REFRESH" content="1; URL=$redirecturl" />
  <title></title>
</head>
<body>
</body>
</html>
"""

    def authorized(self):
        requestHeader = self.http.auth_header(None)
        if not requestHeader:
            # client has failed to include an authentication header; send a 401 response
            return False, self.send401UnauthorizedResponse()
        if requestHeader[0:7] != "Digest ":
            # client has attempted to use something other than Digest authenication; deny
            return False, self.denyBadRequest()
        reqHeaderDict = parseAuthHeader(requestHeader)
        if not self.directiveProper(reqHeaderDict, self.http.path_and_query()):
            # Something is wrong with the authentication header
            if reqHeaderDict.get('opaque',self.opaque) != self.opaque:
                # Didn't send back the correct "opaque;" probably, our server restarted.  Just send
                # them another authentication header with the correct opaque field.
                return False, self.send401UnauthorizedResponse()
            else:
                # Their header had a more fundamental problem.  Something is fishy.  Deny access.
                return False, self.denyBadRequest("Authorization Request Header does not conform to RFC 2617 section 3.2.2")
        # if user sent a "logout" nonce, make them type in the password again
        if len(reqHeaderDict.nonce) != 34:
            return False, self.send401UnauthorizedResponse()
        nonceReaction = self.outstandingNonces.nonceState(reqHeaderDict,  self.nonceSkip)
        if nonceReaction == 2:
            # Client sent a nonce we've never heard of before
            return False, self.denyBadRequest()
        if nonceReaction == 3:
            # Client sent an old nonce.  Give the client a new one, and ask to authenticate again before continuing.
            return False, self.send401UnauthorizedResponse(stale=True)
        username = reqHeaderDict.username
        status = self.user_status.get(username, (self.tries, 0))
        if status[0] < 1 and time.time() < status[1]:
            # User got the password wrong within the last (self.lockTime) seconds
            return False, self.denyForbidden()
        if status[0] < 1: 
            # User sent the wrong password, but more than (self.lockTime) seconds have passed, so give
            # them another try.  However, send a 401 header so user's browser prompts for a password
            # again.
            self.user_status[username] = (1, 0)
            return False, self.send401UnauthorizedResponse()
        if self.requestDigestValid(reqHeaderDict, self.http.request_method()):
            # User authenticated; forgive any past incorrect passwords and run the function we're decorating
            self.user_status[username] = (self.tries, 0)
            return True, None
        else:
            # User entered the wrong password.  Deduct one try, and lock account if necessary
            self.user_status[username] = (status[0] - 1, time.time() + self.lockTime)
            self.logIncorrectPassword(username,  reqHeaderDict)
            return False, self.send401UnauthorizedResponse()

    def logIncorrectPassword(self,  username,  reqHeaderDict):
        pass  # Do your own logging here

    def directiveProper(self,  reqHeaderDict, reqPath):
        """Verifies that the client's authentication header contained the required fields"""
        for variable in ['username','realm','nonce','uri','response','cnonce','nc']:
            if variable not in reqHeaderDict:
                return False
        # IE doesn't send "opaque" and does not include GET parameters in the Digest field
        standardsUncompliant = self.tolerateIE and ("MSIE" in self.http.user_agent())
        return reqHeaderDict['realm'] == self.realm \
            and (standardsUncompliant or reqHeaderDict.get('opaque','') == self.opaque) \
            and len(reqHeaderDict['nc']) == 8 \
            and (reqHeaderDict['uri'] == reqPath or (standardsUncompliant and "?" in reqPath and reqPath.startswith(reqHeaderDict['uri'])))

    def requestDigestValid(self, reqHeaderDict, reqMethod):
        """Checks to see if the client's request properly authenticates"""
        # Ask the application for the hash of A1 corresponding to this username and realm
        try:
            HA1 = self.getHA1(reqHeaderDict['username'], reqHeaderDict['realm'])
        except KeyError:
            # No such user
            return False
        qop = reqHeaderDict.get('qop','auth')
        A2 = "%s:%s" % (reqMethod, reqHeaderDict['uri'])
        # auth-int stuff would go here, but few browsers support it
        nonce = reqHeaderDict['nonce']
        # Calculate the response we should have received from the client
        correctAnswer = H("%s:%s" % (HA1, ":".join([nonce, reqHeaderDict['nc'], reqHeaderDict['cnonce'], qop, H(A2) ])))
        # Compare the correct response to what the client sent
        return reqHeaderDict['response'] == correctAnswer

    def send401UnauthorizedResponse(self, stale=False):
        nonce = self.outstandingNonces.getNewNonce(self.nonceLife)
        challengeList = [ "realm=%s" % quoteIt(self.realm), 
                                   self.domain and ('domain=%s' % quoteIt(" ".join(self.domain))) or '', 
                                   'qop="auth",nonce=%s,opaque=%s' % tuple(map(quoteIt, [nonce, self.opaque])), 
                                   stale and 'stale="true"' or '']
        extraheaders = [("WWW-Authenticate", "Digest " + ",".join(x for x in challengeList if x))]
        extraheaders += [("Content-Type","text/html")]
        self.http.send401(self.unauthHTML, extraheaders)
        return self.unauthHTML

    def denyBadRequest(self,  info=""):
        self.http.send400(info, [('Content-Type', 'text/html')])
        return "400 Bad Request" + info

    def denyForbidden(self):
        """Sent when user has entered an incorrect password too many times"""
        self.http.send403(self.unauthHTML, [('Content-Type', 'text/html')])
        return self.unauthHTML

    def _getValidAuthHeader(self):
        """returns valid dictionary of authorization header, or None"""
        requestHeader = self.http.auth_header(None)
        if not requestHeader:
            raise MalformedAuthenticationHeader()
        if requestHeader[0:7] != "Digest ":
            raise MalformedAuthenticationHeader()
        reqHeaderDict = parseAuthHeader(requestHeader)
        if not self.directiveProper(reqHeaderDict, self.http.path_and_query()):
            raise MalformedAuthenticationHeader()
        return reqHeaderDict

    def logout(self):
        """Cause user's browser to stop sending correct authentication requests until user re-enters password"""
        try:
            reqHeaderDict = self._getValidAuthHeader()
        except MalformedAuthenticationHeader:
            return
        if len(reqHeaderDict.nonce) == 34:
            # First time: send a 401 giving the user the fake "logout" nonce
            nonce = "%032x" % random.getrandbits(136)
            challengeList = [ "realm=%s" % quoteIt(self.realm), 
                               'qop="auth",nonce=%s,opaque=%s' % tuple(map(quoteIt, [nonce, self.opaque])), 
                                'stale="true"']
            extraheaders = [("WWW-Authenticate", "Digest " + ",".join(x for x in challengeList if x))]
            self.http.send401(None, extraheaders)

    def authUserName(self):
        """Returns the HTTP username, or None if not logged in."""
        try:
            reqHeaderDict = self._getValidAuthHeader()
        except MalformedAuthenticationHeader:
            return None
        if len(reqHeaderDict.nonce) != 34:
            return None
        nonceReaction = self.outstandingNonces.nonceState(reqHeaderDict,  self.nonceSkip)
        if nonceReaction in [ 2, 3 ] :
            # Client sent a nonce we've never heard of before
            # Client sent an old nonce.  Give the client a new one, and ask to authenticate again before continuing.
            return None
        return reqHeaderDict.username



def H(data):
    """Return a hex digest MD5 hash of the argument"""
    return md5(data).hexdigest()
def quoteIt(x):
    """Return the argument quoted, suitable for a quoted-string"""
    return '"%s"' % (x.replace("\\","\\\\").replace('"','\\"'))

## Code to parse the authentication header
parseAuthHeaderRE = re.compile(r"""
    (   (?P<varq>[a-z]+)="(?P<valueq>.+?)"(,|$)    )   # match variable="value", (terminated by a comma or end of line)
    |
    (   (?P<var>[a-z]+)=(?P<value>.+?)(,|$)    )          # match variable=value,  (same as above, but no quotes)
    """,  re.VERBOSE | re.IGNORECASE )
def parseAuthHeader(header):
    d = Storage()
    for m in parseAuthHeaderRE.finditer(header):
        g = m.groupdict()
        if g['varq'] and g['valueq']:
            d[g['varq']] = g['valueq'].replace(r'\"',  '"')
        elif g['var'] and g['value']:
            d[g['var']] = g['value']
    return d

class NonceMemory(dict):
    def getNewNonce(self,  lifespan = 180):
        while True:
            nonce = "%034x" % random.getrandbits(136)  # a random 136-bit zero-padded lowercase hex string
            if nonce not in self:
                break
        self[nonce] = (time.time() + lifespan, 1)
        return nonce
    def nonceState(self, reqHeaderDict,  nonceSkip = 1):
        """ 1 = nonce valid, proceed; 2 = nonce totally invalid;  3 = nonce requires refreshing """
        nonce = reqHeaderDict.get('nonce', None)
        expTime, nCount = self.get(nonce, (0,0) )
        if expTime == 0:
            # Client sent some totally unknown nonce -- reject
            return 2
        try:
            incoming_nc = int((reqHeaderDict['nc']), 16)
        except ValueError:
            return 2  # the "nc" field was deformed (not hexadecimal); reject
        if expTime == 1 or nCount > 1000 or expTime < time.time() or incoming_nc - nCount > nonceSkip:
            # Client sent good nonce, but it is too old, or the count has gotten screwed up; give them a new one
            del self[nonce]
            return 3
        self[nonce] = (expTime, incoming_nc + 1)
        return 1
