# Lab: CSRF vulnerability with no defenses [OWASP Zed Attack Proxy]

Launch ZAP and its built-in browser and go to the lab. Log in with credentials `wiener:peter` and submit the "Update email" form.

In ZAP's bottom pane, in the __History__ tab you will see a `POST` request with a path `/my-account/change-email`. Right click it and select "Copy URLs". Use the URL in the following HTML template in the `<form>` tag's `action` attribute:

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

On the web page of the lab, click "Go to exploit server" and paste the resulting HTML into the __Body__ secion of the form.

Click "Store" and click "View exploit". Check the response of the resulting `POST` request to verify that the exploit works. Right-click it and select "Open/Resend with Request Editor..." 

Request body:

```
email=anything%2540web-security-academy.net
```

Now back to the exploit server, change the email in the body to anything but the above and click "Deliver exploit to victim" to solve the lab.
