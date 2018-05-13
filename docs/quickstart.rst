Quickstart
==========

This quickstart guide assumes that you have :doc:`installed <installation>` `token-auth-requests` already.

Making authenticated HTTP requests
----------------------------------

Let us assume we have an API server `api.wakanda.gov.wk`, which requires token based authentication for its API endpoints. It expects that along with your HTTP requests you send an HTTP header of the form

.. code-block:: http

   Authentication: Token abcd1234

where `abcd1234` is the authentication token. Hopefully the token returned by the server is a bit more secure, though. Let us assume further that the server provides a route `/token`, which expects you to send an object with your username and password as a JSON string:

.. code-block:: json

   {
       "username": "tchalla",
       "password": "WakandaForever"
   }

Then you may make your life easier by using `token-auth-requests`. (Your token based authentication server works slightly differently? Don't worry, we'll cover that case below.) This package essentially provides a method `auth_session`, which returns an HTTP requests session that supports token based authentication. This session has all the functionality of a `Session` object of the `requests <http://docs.python-requests.org/>`_ library.

To enable authentication, you need to call the session's `login` method with the username, password and URL for requesting an authentication token.

For example, if there is a GET route `/enemies` and a POST route `/save-the-world`, we could do the following.

.. code-block:: python

   session = auth_session()
   session.login(username='tchalla', password='WakandaForver', token_url='http://api.wakanda.gov.wk/token')

   # who are the enemies?
   r = session.get('http://api.wakanda.gov.wk/enemies')
   print(r.text)

   # get to work!
   r = session.post('http://api.wakanda.gov.wk/save-the-world')
   print(r.status_code)  # hopefully the status code is 200...

Refer to the `requests documentation <http://docs.python-requests.org/>`_ for all the cool stuff you can do. You don't have to worry about tokens or their expiry dates; they are taken care of automatically.

When you don't need authentication any longer, you may simply call the `logout` method.

.. code-block:: python
   
   session.logout()

Custom authentication requests and responses
--------------------------------------------

Of course chances are that your server does things differently. For example, it might expect an object with keys `user` and `passphrase`, and it might just return a string with the token. In this case the methods `auth_request_maker` and `auth_response_parser` come in handy, as they let you tweak the way request bodies are created and response bodies are parsed.

Let us stick to our example. We first define two helper functions.

.. code-block:: python
   
   def make_request(username, password):
       return {
          'user': username,
          'passphrase': password
       }
   
   def parse_response(response):
       return {
           'token': response,
           'expires_in': 10000000
       }

There is no way to tell the session that a token never expires, so we just choose a large value for the token's lifetime.

Having defined these functions, we can let our session know about them.

.. code-block:: python
   
   session = auth_session(username='tchalla', password='WakandaForver', token_url='http://api.wakanda.gov.wk/token')
   session.auth_request_maker(make_request)
   session.auth_response_parser(parse_response)

And voilà, authentication works fine now.

When things go boom in the night
--------------------------------

If you try to authenticate with a wrong username or password (and the server does the right thing and responds with a 401 status code), an `AuthException` is raised.

.. code-block:: python

   try:
       session = auth_session(username='tchalla', password='WakandaIsLost', token_url='http://api.wakanda.gov.wk/token')
   except AuthException as ae:
       print(ae.message)

In case the server replies with a status code other than 200 (OK) or 401 (Unauthorized), a more generic exception is raised.

Using `auth_session` in tests
-----------------------------

When testing functions that use an `auth_session`, authentication might be more of a hindrance than a blessing. In this case you should just not call the `login` method.


