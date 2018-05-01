import json
from datetime import datetime, timedelta
import httpretty
from httpretty import HTTPretty
from freezegun import freeze_time
import hypothesis.strategies as s
from hypothesis import given, settings
import pytest

from token_auth_request import auth_session, AuthException


USERNAME = 'tyhuk67'
PASSWORD = 'gh37xvfkk'
TOKEN_ONE = 'x5467ghwujk78'
TOKEN_TWO = 'jsgti35vftju6'
TOKEN_URI = 'http://token.salt.ac.za/'
DUMMY_URI = 'http://api.salt.ac.za/'


def token_response(token, expires_in):
    return json.dumps(dict(token=token, expires_in=expires_in))


@httpretty.httprettified
def test_initial_authentication_request():
    """A token is requested before the first HTTP request."""

    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 1000))
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')

    session = auth_session(USERNAME, PASSWORD, TOKEN_URI)
    session.get(DUMMY_URI)
    session.get(DUMMY_URI)

    # one token requst, two "normal" requests
    all_requests = HTTPretty.latest_requests
    assert len(all_requests) == 3

    # the first request requests a token (using POST with JSON)
    assert 'token' in all_requests[0].headers['Host']
    assert all_requests[0].headers['Content-Type'] == 'application/json'
    body = json.loads(all_requests[0].body)
    assert body['username'] == USERNAME
    assert body['password'] == PASSWORD

    # the second and third request are the ones the user wants to make
    assert 'token' not in all_requests[1].headers['Host']
    assert 'token' not in all_requests[2].headers['Host']


@httpretty.httprettified
def test_authentication_header_sent():
    """An authentication header is sent with every request."""

    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 1000))
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')

    session = auth_session(USERNAME, PASSWORD, TOKEN_URI)

    session.get(DUMMY_URI)
    session.get(DUMMY_URI)

    all_requests = HTTPretty.latest_requests
    token_header = 'Token {token}'.format(token=TOKEN_ONE)
    assert all_requests[-2].headers['Authentication'] == token_header
    assert all_requests[-1].headers['Authentication'] == token_header


@given(dt1=s.integers(min_value=0, max_value=540), dt2=s.integers(min_value=541))
@settings(deadline=None)
@httpretty.httprettified
def test_expired_token_is_requested_again(dt1, dt2):
    """If a token has expired, a new one is requested before the next HTTP request, and the new token is used
    henceforth."""

    httpretty.reset()
    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 600))
    session = auth_session(USERNAME, PASSWORD, TOKEN_URI)

    # initial token
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')
    start_time = datetime(2018, 5, 1, 17, 0, 0, 0)
    with freeze_time(start_time):
        session.get(DUMMY_URI)

    # initial token still valid
    httpretty.reset()
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')
    with freeze_time(start_time + timedelta(seconds=dt1)):
        session.get(DUMMY_URI)
    assert len(HTTPretty.latest_requests) == 1
    assert 'token' not in httpretty.last_request().headers['Host']

    # initial token not valid any longer
    httpretty.reset()
    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_TWO, 600))
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')
    with freeze_time(start_time + timedelta(seconds=dt2)):
        session.get(DUMMY_URI)
        session.get(DUMMY_URI)

    # three requests, as a new token is requested first
    all_requests = HTTPretty.latest_requests
    assert len(all_requests) == 3

    # the first request requests a token (using POST with JSON)
    assert 'token' in all_requests[0].headers['Host']
    assert all_requests[0].headers['Content-Type'] == 'application/json'
    body = json.loads(all_requests[0].body)
    assert body['username'] == USERNAME
    assert body['password'] == PASSWORD

    # the second and third request are the ones the user wants to make, and they use the new token
    assert 'token' not in all_requests[1].headers['Host']
    assert all_requests[1].headers['Authentication'] == 'Token {token}'.format(token=TOKEN_TWO)
    assert 'token' not in all_requests[2].headers['Host']
    assert all_requests[1].headers['Authentication'] == 'Token {token}'.format(token=TOKEN_TWO)


@httpretty.httprettified
def test_logout_removes_auth_data():
    """logout removes all authentication data"""

    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 1000))
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')

    session = auth_session(username=USERNAME, password=PASSWORD, auth_url=TOKEN_URI)

    session.get(DUMMY_URI)

    # authentication data has been set
    assert session._username is not None
    assert session._password is not None
    assert session._token is not None
    assert session._expiry_time is not None

    session.logout()

    # authentication data has been removed
    assert session._username is None
    assert session._password is None
    assert session._token is None
    assert session._expiry_time is None


@httpretty.httprettified
def test_401_results_in_auth_exception():
    """An AuthException is raised if the status code 401 is returned when a token is requested"""

    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 1000), status=401)
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')

    session = auth_session(username=USERNAME, password=PASSWORD, auth_url=TOKEN_URI)

    with pytest.raises(AuthException) as excinfo:
        session.get(DUMMY_URI)

    message = excinfo.value.args[0]
    assert 'Unauthorized' in message


@httpretty.httprettified
def test_no_requests_possible_after_logging_out():
    """An attempt to make an HTTP request after logging out results in an AuthException being raised"""

    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 1000))
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')

    session = auth_session(username=USERNAME, password=PASSWORD, auth_url=TOKEN_URI)

    session.get(DUMMY_URI)

    session.logout()

    with pytest.raises(AuthException) as excinfo:
        session.get(DUMMY_URI)

    message = excinfo.value.args[0]
    assert 'No HTTP requests can be made after logging out' in message


@httpretty.httprettified
@given(status=s.one_of(s.integers(min_value=100, max_value=199),
                       s.integers(min_value=201, max_value=400),
                       s.integers(min_value=402, max_value=599)))
def test_exception_for_status_other_than_200_or_401(status):
    """A generic exception is raised if the server returns a status code other than 200 or 401 when requesting a
     token."""

    httpretty.register_uri(httpretty.POST, TOKEN_URI, token_response(TOKEN_ONE, 1000), status=status)
    httpretty.register_uri(httpretty.GET, DUMMY_URI, 'some test response')

    session = auth_session(username=USERNAME, password=PASSWORD, auth_url=TOKEN_URI)

    with pytest.raises(Exception):
        session.get(DUMMY_URI)
