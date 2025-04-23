# Lab: SameSite Strict bypass via client-side redirect [OWASP Zed Attack Proxy]

Open ZAP's browser, navigate to the lab, log in with credentials `wiener:peter` and "Update email". 

On the bottom pane, under __History__ tab find the `POST /my-account/change-email` request, right-click it and select "Open/Resend with Request Editor". Notice, that there are no CSRF tokens in the request body or headers, so the site may be vulnerable to CSRF if you can bypass the SameSite cookie restrictions. 

```
...
Cookie: session=8eA7o0NoYNJAeB5bT6ZmbBAg6VKSdHhK
...

email=foo%40bar.com&submit=1
```

Under the __History__ tab, find `POST /login` request and double-click it. It will open up in top-right pane inside the __Request__ tab. Select the __Repsonse__ tab next to it. 

```
HTTP/1.1 302 Found
Location: /my-account?id=wiener
Set-Cookie: session=8eA7o0NoYNJAeB5bT6ZmbBAg6VKSdHhK; Secure; HttpOnly; SameSite=Strict
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 0
```

Observe, that the website explicitly specifies `SameSite=Strict` when setting session cookies. This prevents the browser from including these cookies in cross-site requests.

In the browser, navigate to one of the blog posts and post an arbitrary comment. In the __History__ pane on the bottom, the sequence of requests goes as follows:

- `GET /post/7` --- where you accessed the blog post's page.
- `POST /post/comment` --- where you posted a comment on the blog post.
- `GET /post/comment/confirmation?postId=7` --- where after posting the comment, you were sent to a confirmation page.
- `GET /resources/js/commentConfirmationRedirect.js` --- where a JS handler was called to redirect you back to the blog post from confirmation page.
- ` GET /post/7` --- where you were redirected back to the blog post.

Check the `/resources/js/commentConfirmationRedirect.js` code by right-clicking the request under __History__ tab and select "Open URL in System Browser". 

```javascript
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const url = new URL(window.location);
        const postId = url.searchParams.get("postId");
        window.location = blogPath + '/' + postId;
    }, 3000);
}
```

This code effectively uses `blogPath` to build a redirect URL, implying it to be equal to `/post` then retrieves `postId` query parameter from the URL, in this case from: `/post/comment/confirmation?postId=7` and adds `/` and `7` to the `/post`, so the final path to be redirected to is: `/post/7`.

Now in the __History__ tab right-click the `GET /post/comment/confirmation?postId=7` request and select "Copy URLs", paste it in the browser and change `postId` query parameter's value in the URL from `7` to `foo`. It sends you to the confirmation page again and then attempts to redirect you to `/post/foo`. 

Now, instead of `foo` try to inject a path traversal sequence to `postId` query parameter. In this case, let's try `7/../../my-account`.

> NOTE: See the explanation of how this path traversal sequence works in the [original](README.md) write-up. 

The browser normalizes this URL to `/my-account` and successfully takes you to `my-account` page. This confirms that you can use `postId` parameter to elicit a `GET` request for an arbitrary endpoint on the target site. 

In the browser, go to the exploit server and create a script that induces the viewer's browser to send the `GET` request you just tested:

```
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=7/../../my-account";
</script>
```

Place the above code in the "Body" section of the form in the exploit server's interface and click "Store". Then, click "View exploit". If it transferred you to the confirmation page and redirected you to the `/my-account` page from there, it works. 

Notice that the final `GET /my-account` request includes your authenticated `session` cookie and you still end up on your logged-in account page, even though the initial comment-submission request was initiated from an arbitrary __external__ (exploit server) site. 

Find `POST /my-account/change-email` request in the __History__ tab, right click it and select "Open in Requester Tab". In the toolbar of the Requester tab click the dropdown named "Method" and select `GET`. This will automatically convert your `POST` request to an equivalent `GET` request. Send the request. 

```
HTTP/1.1 302 Found
Location: /my-account
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 0
```

Observe that the endpoint allows you to change your email address using a `GET` request.

Go back to the exploit server and change the `postId` parameter in the exploit so that the redirect causes the browser to send this `GET` request for changing your email address:

```
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=7/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
</script>
```

Click "Store" and then click "Deliver exploit to victim" to solve the lab.
