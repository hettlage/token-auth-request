"""An HTTP requests session for handling authentication."""

from datetime import datetime, timedelta
import json
import requests
from requests.auth import AuthBase


class TokenAuth(AuthBase):
    """Token-based authentication.

    Parameters
    ----------
    token : str
        The authentication token.

    """

    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['Authentication'] = 'Token {token}'.format(token=self.token)
        return r


class AuthSession:
    """An HTTP requests session which automatically handles token authentication.

    The session object exposes all the methods and fields exposed by the Session class of the requests library; see [
    1]_. Before making its first HTTP call, it gets an authentication token by sending the username and password to
    an authentication URL. The token and its expiry date are stored, and the token is sent in an Authentication HTTP
    header with all HTTP requests. If the token expires, a new one is requested before the next HTTP request is made.

    The username, password and token can be deleted by calling the `logout` method. You cannot make any further HTTP
    requests after doing this.

    This class is not intended for use in applications which require a high degree of security.

    Parameters
    ----------
    username : str
        The username for authentication.
    password : str
        The password for authentication.
    auth_url : str
        The URL for authenticating, i.e. for obtaining a token.

    References
    ----------
    .. [1] http://docs.python-requests.org/

    """

    http_methods = ['delete', 'get', 'head', 'options', 'patch', 'post', 'put', 'request']

    def __init__(self, username, password, auth_url):
        self._username = username
        self._password = password
        self._auth_url = auth_url
        self._token = None
        self._expiry_time = None
        self._session = requests.Session()
        self._logged_out = False
        self._auth_request_maker = lambda _username, _password: dict(username=_username, password=_password)
        self._auth_response_parser = lambda response: json.loads(response)
        self._no_authentication = False

    def auth_request_maker(self, request_maker):
        """Replace the function for creating the authentication request.

        By default it is assumed that the authentication expects a (JSON) object of the form

        {
            "username": "sipho",
            "password": "secret"
        }

        and this is what the authentication request sends. You may change this behaviour by passing your own custom
        function to this method. Your function must accept a username and password as its arguments and must return
        an object which can be turned intro a JSON string.

        For example, assume the server expects the user credentials to be sent as a JSON object like

        {
            "credentials": "sipho:secret"
        }

        Then you could add the following code after creating your authentication (and before making the first HTTP
        request):

        session.auth_request_maker(lambda u, p: '{}:{}'.format(u, p))

        Parameters
        ----------
        request_maker: callable
            The function for creating the request body from the username and password.

        """

        self._auth_request_maker = request_maker

    def auth_response_parser(self, response_parser):
        """Replace the function for parsing the response from an authentication request.

        By default it is assumed that the authentication request returns a response like

        {
            "token": "cghjw56ger",
            "expires_in": 5000
        }

        and the token and expiry time are obtained based on this assumption. You may change this behaviour by your own custom
        function to this method. This function must accept a string (the response body) as its only argument and must
        return a dictionary with keys `token` and `expires_in`.

        For example, assume the authentication just returns a string with the token (which never expires). Then you
        could add the following code after creating your authentication (and before making the first HTTP request):

        session.auth_response_parser(lambda response: dict(token=response, expires_in=100000))

        Parameters
        ----------
        response_parser : callable
            The function for parsing the response from an authentication request.

        """

        self._auth_response_parser = response_parser

    def logout(self):
        """Remove all authentication data.

        Any attempt to make HTTP requests after calling this method will result in an AuthException being raised.

        """

        self._username = None
        self._password = None
        self._token = None
        self._expiry_time = None
        self._logged_out = True

    @property
    def no_authentication(self):
        """Return boolean whether authentication is disabled.

         Returns
         -------
         no_auth : bool
             Whether authentication is disabled.

         """

        return self._no_authentication

    @no_authentication.setter
    def no_authentication(self, value):
        """Disable or enable authentication.

        If authentication is disabled, no token is requested and no Authorizatyion header is sent.

        Parameters
        ----------
        value : bool
            Whether to disable authentication.

        """

        self._no_authentication = value

    def __getattr__(self, item):
        """Get the item from the internal requests session, requiring a token first if need be.

        If a method corresponding to an HTTP verb is requested and there is no valid token, a token is requested from
        the authentication URL first.

        Parameters
        ----------
        item : str
            Property to return.

        Returns
        -------
        item : any
            The requested property.

        """

        session_property = getattr(self._session, item)

        if item not in AuthSession.http_methods:
            # this is not an HTTP request
            return session_property

        if self._logged_out:
            raise AuthException('No HTTP requests can be made after logging out')

        if self._has_valid_token():
            # there is a valid token
            return session_property

        self._authenticate()

        return session_property

    def _authenticate(self):
        """
        Request an authentication token and ensure it will be sent as an Authentication HTTP header.

        """

        if self.no_authentication:
            return

        payload = self._auth_request_maker(self._username, self._password)
        r = requests.post(self._auth_url, json=payload)

        # handle authentication failure
        if r.status_code != 200:
            if r.status_code == 401:
                raise AuthException('Unauthorized')
            raise Exception('Unknown error')

        data = self._auth_response_parser(r.text)
        self._token = data['token']
        self._expiry_time = datetime.now() + timedelta(seconds=data['expires_in'])

        self._session.auth = TokenAuth(self._token)

    def _has_valid_token(self):
        return self._token and self._expiry_time and datetime.now() <= self._expiry_time - timedelta(seconds=60)


class AuthException(Exception):
    """An authentication error.

    Parameters
    ----------
    message : str
        The error message.

    """

    def __init__(self, message):
        super(Exception, self).__init__(message)


def auth_session(username, password, auth_url):
    """Create an HTTP requests session instance which automatically handles token authentication.

    This method is not intended for use in applications which require a high degree of security.

    Parameters
    ----------
    username : str
        The username for authentication.
    password : str
        The password for authentication.
    auth_url : str
        The URL for authenticating, i.e. for obtaining a token.

    Returns
    -------
    session : AuthSession
        An HTTP requests session handling token authentication.

    """

    return AuthSession(username=username, password=password, auth_url=auth_url)
