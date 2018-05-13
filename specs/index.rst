.. toctree::
   :maxdepth: 2

token-auth-request
==================

Introduction
------------

It often makes sense to pair a web-based API with a Python-based library for easy access. If the API use requires authentication, the library must be able to handle it. While this certainly can be achieved on an ad hoc basis, it seems more reasonable to encapsulate the authentication handling into a Python package of its own.

`token-auth-requests` does precisely that. It accepts a username and password and uses them to request an authentication token, which is used for subsequent HTTP calls. The token is stored, and a new token is automatically requested if the current one has expired.

Conceptual Solution
-------------------

The `token-auth-requests` package provides exactly one method, `auth_session`, which is called without arguments. It returns an object which has all the methods of the `requests <http://docs.python-requests.org/>`_ library's Session class. This object is called session in the following.

In addition it has various methods of its own.

`login(username, password, url)`:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before the login method is called, no authentication is done.

Once the login method has been called, whenever a method corresponding to an HTTP verb (i.e. DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT or a custom verb) is called on the session, the session will first check whether it has a non-expired authentication token. Here non-expired means that the expiry time is in the past or within the next minute. If it has not expired, it sends an HTTP request to the URL passed to the `auth_session`. This request must look as follows.

=====================  ============================================
Property               Value
=====================  ============================================
HTTP method            POST
Content-Type header    application/json
Payload                { username: username, password: password }
=====================  ============================================

The response is expected to look as follows.

=====================  =======================================
Property               Value
=====================  =======================================
HTTP status code       200
Content-Type header    application/json
Data                   { token: token, expires_in: seconds }
=====================  =======================================

For example, if the username and password passed to `auth_session` are `sipho` and `topsecret`, the token generated for the user is `abcd1234` and the token expires in 500 seconds, then the request should have the payload

.. code-block:: json

   {
       "username": "sipho",
       "password": "topsecret"
   }

and the response data should be

.. code-block:: json

   {
       "token": "abcd1234",
       "expires_in": 500
   }


Both the token and its expiry time are stored. After that, or if there was a non-expired token already, the token is added as an HTTP header with key `Authentication` and value `Token xyz` (where `xyz` denotes the token) to the session. For example, for the token above the header would look be

::
   Authentication: Token abcd1234

Only then is the actual HTTP method of the `requests` Session class called. All positional and keyword arguments are passed on as is.

If the server uses other formats for the authentication data and token, the session can be customised to handle these, as described below.

The session exposes some public methods in addition to those of the requests Session class.

logout()
~~~~~~~~

 The `logout` method, removes the username, password, authentication URL, token and expiry time. No authentication will be done any longer until the login method is used to authenticate again.

 auth_request_maker(func)
 ~~~~~~~~~~~~~~~~~~~~~~~~

 The `auth_request_maker` method replaces the default function for creating the object to be of the POST request for getting the token. The function must accept a username and password as its arguments, and it must return an object which can be sent as JSON.

 auth_response_parser(func)
 ~~~~~~~~~~~~~~~~~~~~~~~~~~

 The `auth_response_parser` replaces the default function for parsing the response body of the POST request for getting a token. It must accept a string as its only argument, and it must return a dictionary with `token` and `expires_in` as keys.

 The property `no_authentication` can be used to disable authentication. If authentication is disabled, no authentication request is made. The Authentication header still may be sent with HTTP requests, but this not necessarily the case.

The package also defines an exception type `AuthException`. An `AuthException` should be raised if the server replies with a 401 error when a token is requested, or if an HTTP request is made after the object's `logout` method has been called.

Tests
-----

The package must pass the following tests.

* After calling `login` with a correct username and password, the first time one of the HTTP verb methods is called on the returned object, a POST request to the given URL is made with the username and password passed as a JSON string. Assuming the token has not expired, further calls don't make such a request.
* After calling `login` with a correct username and password, assuming the token has not expired, all subsequent HTTP requests (after the initial request for a token) have an Authentication header with the correct string.
* If an HTTP request is made and the current token's expiry time is less than one minute in the future, a new token is requested and subsequent HTTP requests use the new token in the Authentication header.
* The logout method removes username, password, token and expiry date.
* No token is requested after the `logout` method is called.
* No Authentication header is sent after the `logout` method is called.
* An AuthException is raised if the server replies with a 401 error when a token is requested.
* An exception is raised if the server replies with a status code other than 200 or 401.
* `auth_request_maker` changes the function for making the body of an authentication request.
* `auth_response_parser` changes the function for parsing the response of an authentication request.

Implementation
--------------

The `auth_session` method returns an instance of a class `AuthSession`. This class implements the `__getattr__` method. If authentication is used, it checks whether the argument is a `requests` Session corresponding to an HTTP verb. It then checks whether there is a non-expired token and, if so, calls the method on `_session`. Otherwise, it tries to get a token from the server, adds the token as an HTTP header to `_session` and then calls the method on `_session`.

The `login` method sets the username, password and token URL. 

The `logout` sets the username, password, authentication URL, token and expiry_time to `None`.
