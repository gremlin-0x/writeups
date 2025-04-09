# Lab: Exploiting an API endpoint using documentation [OWASP Zed Attack Proxy]

Launch `zaproxy` and open its built-in browser (a firefox icon in the toolbar).

Access the lab in it by pasting the lab URL in the browser URL field. 

Log in with credentials `wiener:peter` and update the email.

Look at the bottom pane in ZAP named and open __History__ tab, where you will see all requests made to the site. Find a request with _Method_ `PATCH` and _URL_ ending with `.../api/user/wiener`.

Right-click on it and click __Open in Requester Tab...__. A tab will appear on top, named __Requester__ with a request on the left and response on the right. Click _Send_ on the left and the response will return the credentials of the user:

_Response Headers:_
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 52
```

_Response Body:_
```
{"username":"wiener","email":"zaproxy@fakemail.com"}
```

On the left in the Request tab, remove the end part of the URL `/wiener` and send the request. It will return an error because there is no user identifier:

_Response Body:_
```
{"error":"Malformed URL: expecting an identifier"}
```

Now remove the `/user` part of the URL and resend the request. It will return the API documentation, which you can check if you right click on the response and click __Open URL in Browser__ > __Firefox__.

![API Documentation](psa_apitesting_ss01.png "API Documentation")

> The rest of the flow is the same as in the [original](README.md) write-up.
