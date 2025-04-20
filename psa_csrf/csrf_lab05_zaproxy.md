# Lab: CSRF where token is tied to non-session cookie

Open ZAP's browser, log in with credentials `wiener:peter`, submit the "Update email" form and find the `POST /my-account/change-email` request in the bottom pane of the interface under __History__ tab. 

Right click the request in question and select __Open/Resend with Request Editor__. Once it opens make sure to unset a _green circular arrow_ icon in the toolbar that reads __Follow redirect__ if you hover over it. 

Change `session` cookie value in the `Cookie` header to anything and send.

_Response:_

```
HTTP/1.1 302 Found
Location: /login
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 0
```

Now restore `session` cookie value and change `csrfKey` cookie value and send.

_Response body:_

```
"Invalid CSRF token"
```

When we tamper with `session` cookie, the application logs us out, but with `csrfKey` cookie, it only return and invalid CSRT token message. This suggests that `csrfKey` cookie isn't strictly tied to the `session` cookie.

> NOTE: Save the `csrfKey` cookie value and the value of `csrf` parameter from request body from the `wiener` session before proceeding.

Open incognito window on ZAP's browser and log in with credentials `carlos:montoya`. "Update email" here too, find the `POST /my-account/change-email` request in __History__, right-click it and select __Open in Requester Tab__. 

Replace the `csrfKey` cookie value and `csrf` parameter value from the request body with the ones saved from the `wiener` session in the original browser and click send.

_Response:_

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3516
```

The request is accepted. This means any user's `csrfKey` cookie and `csrf` parameter values can be used in any user's session to make a legitimate `POST` request to change email.

Back in the `wiener` session, in the original browser window perform any search on the homepage. Check the request in the __History__ tab.

_Response:_

```
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=search; Secure; HttpOnly
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3422
```

Notice that the search term appears in the `Set-Cookie` header in response headers as `LastSearchTerm=search`. This means we can inject cookies in other user's browsers, with no CSRF protection, through search function.

In browser, go to "My account" page again and in ZAP's interface toolbar click on the green circle icon, that reads "Set Break on All Requests and Responses". Perform an "Update email" request. A __Break__ tab will appear next to the __Requester__ tab. 

__Save__ the value of `csrfKey` cookie from the request headers and `csrf` parameter value from the request body. Now click the __Circle-slash__ icon in the toolbar near the break icon to drop this request.  

> The rest of the flow is the same as in the [original](README.md) write-up.
