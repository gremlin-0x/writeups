# Lab: Accidental exposure of private GraphQL fields [OWASP Zed Attack Proxy]

> NOTE: First things first, make sure you have a [GraphQL add-on installed and enabled on ZAP](https://www.zaproxy.org/blog/2020-08-28-introducing-the-graphql-add-on-for-zap/).

In ZAP's browser, navigate to the lab's page and attempt login as `admin:admin`. In the __History__ tab on ZAP's interface, you will see a `POST /graphql/v1` request with the body:

```graphql
{"query":"\n    mutation login($input: LoginInput!) {\n        login(input: $input) {\n            token\n            success\n        }\n    }","operationName":"login","variables":{"input":{"username":"admin","password":"admin"}}}
```

Which indicates that the login attempts are being sent as a GraphQL mutation containing both a username and password. Right-click this request and select "Copy URLs".

Go to __Import__ > __Import a GraphQL Schema__ and under the "Endpoint URL" input paste the URL you just copied. Click "Import". This will make a number of manual `POST /graphql/v1` requests that will all show up in __History__ panel. 

Make note of three consecutive requests where in the body a `getUser` query is sent with three different parameters: `id`, `username` and `password`:

```graphql
{"query":"query { getUser (id: 1) { id } } ","variables":{}}
```
```graphql
{"query":"query { getUser (id: 1) { password } } ","variables":{}}
```
```graphql
{"query":"query { getUser (id: 1) { username } } ","variables":{}}
```

The middle request in this list, returns a password to `administrator` user. But to make it certain, we can right-click the first request (`id`) and select "Open/Resend with Request Editor" and modify the request body, to this:

```graphql
{"query":"query { getUser (id: 1) { id\nusername\npassword } } ","variables":{}}
```

Click send and you should see a similar response to this:

```json
{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "[REDACTED]"
    }
  }
}
```

Log in to the website with these credentials, navigate to "Admin panel" and delete user `carlos` to solve the lab. 
