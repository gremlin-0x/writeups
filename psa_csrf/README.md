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


