# NoSQL injection [PortSwigger Academy]

<sup>This write-up covers the NoSQL injection section of Web Security Academy by PortSwigger.</sup>

## Types of NoSQL injection

NoSQL injection vulnerabilities generally fall into two categories: __syntax injection__, where the attacker breaks the structure of a NoSQL query to insert arbitrary input --- similar in concept to SQL injection but adapted to the diverse query languages and data formats used in NoSQL systems; and __operator injection__, where malicious input leverages NoSQL query operators to alter query logic. This topic outlines how to identify NoSQL vulnerabilities broadly, with a specific focus on exploiting them in MongoDB, the most widely used NoSQL database, and includes hands-on labs for practical experience. 

## NoSQL syntax injection

NoSQL injection vulnerabilities can often be identified by trying to disrupt the query syntax. This involves methodically testing each input field using special characters or fuzzing strings to see if they cause database errors or unexpected behavior, which would indicate insufficient input sanitization. If you're aware of the target database's query language, tailor your fuzzing accordingly with language-specific payloads. If not, use a broad set of fuzz strings to cover different possible NoSQL query syntaxes. 

### Detecting syntax injection in MongoDB

Imagine a shopping app that displays items by category. When a user selects the "Fizzy drinks" category, their browser sends a request like:

```
https://insecure-website.com/product/lookup?category=fizzy
```

The app then queries its MongoDB database using a condition like:

```mongodb
this.category == 'fizzy'
```

To test for potential NoSQL injection, you can try injecting a fuzz string into the `category` parameter. For MongoDB, an example fuzz string might be:

```
'"`{\r;$Foo}\n$Foo \xYZ
```

You would URL-encode this string and send it in a request like:

```
https://insecure-website.com/product/lookup?category=%27%22%60%7B%0D%0A%3B%24Foo%7D%0A%24Foo%20%5CXyz%00
```

If the response differs from the usual behavior, this might signal that the application fails to properly sanitize user input. 

> NOTE: NoSQL injection vulnerabilities can appear in different formats depending on how input is handled. In this case, input is passed via the URL, so the fuzz string is URL-encoded. But if the input were submitted as JSON, you'd need to format it differently, like:
```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

Adapt your testing approach based on how and where the application processes input. 

### Determining which characters are procesed

To find out which characters the application treats as part of its query syntax, you can test by injecting individual characters. For instance, submitting a single `'` might result in a MongoDB query like:

```mongodb
this.category == '''
```

If this alters the usual response, it could indicate that the `'` character disrupted the query, leading to a syntax error. To verify this, you can try submitting a properly escaped version of the input such as:

```mongodb
this.category == '\''
```

If this input is accepted without errors, it suggests that the application might not be properly sanitizing inputs and could be susceptible to injection attacks. 

### Confirming conditional behavior

Once you've identified a vulnerability, the next step is to check whether you can manipulate boolean conditions using NoSQL syntax.

To do this, send two requests --- one with a condition that evaluates to false and another that evaluates to true. For example, you could use `' && 0 && 'x` for false and `' && 1 &&'x` for true, like so:

- `https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x`
- `https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x`

If the application's behavior changes between these two requests, it suggests that the injected boolean logic is affecting the server-side query --- confirming that the input is influencing query execution. 

### Overriding existing conditions

Once you've confirmed that you can influence boolean conditions, you can attempt to override existing conditions to exploit the vulnerability. For instance, you can inject a JavaScript condition that always evaluates to true, such as `' || '1' == '1'`. This would result in a URL like:

```
https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%27%31%27%3d%3d%27%31
```

This would modify the MongoDB query to:

```mongodb
this.category == 'fizzy'||'1'=='1'
```

Since the injected condition is always true, the query will return all items, allowing you to view all products, including those in hidden or unknown categories.

> NOTE: Be cautious when injecting conditions that always evaluate to true into NoSQL queries. While it may seem harmless in the context of viewing data, applications often reuse request data in multiple queries. If it's used for operations like updating or deleting data, it could inadvertently lead to data loss. 

### Overriding existing conditions - Continued

You can also append a null character to the category value, as MongoDB may ignore any characters following a null character. This would cause the query to disregard any additional conditions. For example, if the query includes a restriction like: 

```mongodb
this.category == 'fizzy' && this.released = 1
```

The condition `this.released == 1` is intended to filter products that are released, excluding unreleased ones where `this.released == 0`.

An attacker could exploit this by crafting a URL such as:

```
https://insecure-website.com/product/lookup?category=fizzy'%00
```

This results in the following NoSQL query:

```mongodb
this.category == 'fizzy'\u0000' && this.released == 1
```

If MongoDB ignores everything after the null character, the `this.released == 1` condition is bypassed, allowing all products in the `fizzy` category, including unreleased ones, to be desplayed. 

### Lab: Detecting NoSQL injection

In Burp's browser access the lab and try any category under the product filter. Go to __Proxy__ > __HTTP history__ and right-click the category filter request `GET /filter?category=...` and select "Send to Repeater". 

if you submit `Lifestyle'` as value to `category=` parameter in the query and Send the request, a JavaScript error is returned:

```html
<p class=is-warning>
Command failed with error 139 (JSInterpreterFailure): &apos;SyntaxError: unterminated string literal :
functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25
&apos; on server 127.0.0.1:27017. The full response is {&quot;ok&quot;: 0.0, &quot;errmsg&quot;: &quot;SyntaxError: unterminated string literal :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n&quot;, &quot;code&quot;: 139, &quot;codeName&quot;: &quot;JSInterpreterFailure&quot;}
</p>
```

This indicates that the user input was not filtered or sanitized correctly. Submit a valid JavaScript payload in the value of the `category` query parameter:

```
GET /filter?category=Lifestyle'+' HTTP/2
```

And make sure to URL-encode the payload before sending the request (`Lifestyle'%2b'`). Notice that it doesn't cause the same error from above. This indicates that a form of server-side injection may be occurring. 

Identify whether you can inject boolean conditions to change the response. Insert a false condition in the category parameter, a URL-encoded equivalent of this: `Lifestyle' && 0 && 'x` would be `Lifestyle'+%26%26+0+%26%26+'x`. Notice that no products are retrieved. Now try the true condition, or a URL-encode equivalent of `Lifestyle' && 1 && 'x`. Notice that the products in the __Lifestyle__ category are retrieved.

Submit a boolean condition that always evaluates to true in the category parameter: `Lifestyle'||1||'`. Notice that the response contains products you couldn't otherwise find just browsing the site. 

Right-click the respose and select __Show respones in browser__, copy the URL and paste it in the browser. This solves the lab. 

> NOTE: Check out [walkthrough](nosql_lab01_zaproxy.md) of this lab in OWASP Zed Attack Proxy


