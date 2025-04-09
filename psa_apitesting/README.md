# API Testing [PortSwigger Academy]

<sup>This write-up covers the API Testing section of Web Security Academy by PortSwigger.</sup>

## API Recon

_Discover API's attack surface_ -- Find out as much information about API as possible.

_API endpoints_ -- These are locations where API receives requests about a specific resource on its server.

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



```bash
nmap -A 10.10.67.61 -oN general.scan
```

