# Lab: CSRF where token validation depends on token being present

Open ZAP's built in browser and navigate to the lab. Log in with credentials `wiener:peter`. 

Submit "Update email" form and find the request in the bottom pane of ZAP's interface under __History__ tab. The path should be `/my-account/change-email` and request method should be `POST`. 

_Request body:_

```
email=email@email.com&csrf=[[...token...]]
```

Right-click the request and select __Open in Requester Tab__. Change the `csrf` parameter value to anything and resend the request:

_Response body:_

```
"Invalid CSRF token"
```

The request has been rejected. Now if we delete `csrf` parameter from the request body entirely and resend it with request body: `email=email@email.com` it will be accepted.

_Response line:_

```
HTTP/1.1 200 OK
```

Now navigate back to the bottom pane of ZAP's interface, under __History__ tab, and find this latest request. Right-click it and select "Copy URLs". Use the URL in the following HTML template:

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
    document.forms[0].submit();
</script>
```

Edit the values of the attributes `name` and `value` in the second line to `email` and the desired email you want to try. 

Go to exploit server and paste the resulting HTML in the "Body" section of the form and click "Store".

Click "View exploit" to see if it works on your account. You will be redirected to a page where you'll see that your email has been changed.

Go back to the exploit server and change the `value` attribute in the second line of the HTML template to any other email than the one your account was changed to. Click "Deliver to victim" to solve the lab.
