# Lab: CSRF where token is not tied to user session [OWASP Zed Attack Proxy]

In ZAP's interface, navigate to the __Break__ tab or add one with a "+" sign next to Requester, Request, Response tabs on the top-right pane. 

In the toolbar at the top of the interface, there should be an icon of green light. If you hover over it a text appears _"Set break on all requests and responses"_. If you click it, it will turn red. We need it to be green for now. 

Open ZAP's built in browser and navigate to the lab page. Log in with credentials `wiener:peter` and fill in the email input. 

Before submitting, go back to ZAP and on the toolbar click to "Set break on all requests and responses". Go back to the web browser and submit the form. 

An intercepted request will automatically appear in the __Break__ tab you have activated earlier for this. Make note of the CSRF token in the request body. 

In the toolbar at the top of the interface, you will also see a "Circle-slash" icon. If you hover over it, it should show a text _"Bin request or response"_. Click it to drop this request. 

Click "Unset break on all requests and responses" in the toolbar and __go back__ to the lab's homepage in ZAP's built-in browser. 

Log in again, but this time as `carlos:montoya` and intercept a request of updating the email once again, just as above. 

Right click on the intercepted request in the __Break__ pane and select "__Open in Requester Tab__". In the request body replace the `csrf` parameter value with the one saved above from the previous session and click "Send".

_Response:_

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3522
```

Seems like this user can update their email with any valid CSRF token from any user. 

> The rest of the lab walkthrough is very similar to the original write-up. 
