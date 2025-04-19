# Lab: CSRF where token validation depends on request method [OWASP Zed Attack Proxy]

Open ZAP's built-in browser, navigate to the lab and log in with credentials `wiener:peter`

Submit the "Update email" form and find the associated request in the bottom pane of ZAP under __History__ tab. The request should have path `/my-account/change-email` and method `POST`

Right-click the request and select __Open in Requester Tab...__

_Request body:_

```
email=attacker%40fakemail.com&csrf=[[...token...]]
```

Change the `csrf` parameter to anything else and resend the request.

_Response body:_

```
"Invalid CSRF token"
```

This means that CSRF token was rejected by the server and the request didn't go through.

Now in the __Requester Tab__'s left pane where the Request is located, on the top bar there is a __Method__ dropdown. Click on it and select `GET`. This will convert this request method from `POST` to `GET`. Resend the request.

_Response:_

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3552
```

This means that the server doesn't verify CSRF token for the `GET` request the same way it does for the `POST` request. Now look back at the bottom pane of the ZAP interface and find this latest `GET` request you've sent. Right-click it and select __Copy URLs__. Use it in the following HTML template as a value of `action` attribute of the `<form>` tag:

> NOTE: If the copied URL has any query parameters (like `?email=email@email.com&csrf=asdasdh`) remove them before clicking "Store". Also, for me encoding `anything%40web-security-academt.net` didn't work, so I replaced it with `@` symbol in the HTML instead and succeeded. 

```
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

From the top bar of the lab web page click "Go to exploit server" and paste the resulting HTML into the "Body" section of the form, then click "Store".

Click "View exploit" to check if the exploit works by trying it on yourself. Check the resulting HTTP request and response in the bottom pane of ZAP's interface under the __History__ tab. You were also redirected to `/my-account?id=wiener` where you can see that your email has changed.

```
Your email is: anything@web-security-academy.net
```

Go back to the exploit server and change the email value in the HTML body (`<input>` tag) to anything but the above. Click "Store" and then "Deliver to victim" to solve the lab.
