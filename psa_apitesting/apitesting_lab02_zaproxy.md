# Lab: Finding and exploiting an unused API endpoint

Turn on `zaproxy` and launch its built-in browser. Navigate to the lab.

Click view details on any product, my choice is __AbZorba Ball__.

In the bottom pane of `zaproxy` in __History__ tab, find a `GET` request with a URL ending with `/api/products/3/price`, right click on it and click __Open in Requester Tab...__.

Once Requester Tab opens, change HTTP method from `GET` to `OPTIONS` and click _Send_. The response will contain the following header:

```
Allow: GET, PATCH
```

Indicating that only `GET` and `PATCH` methods are allowed. Let's change the HTTP method from `OPTIONS` to `PATCH` then and send the request. 

_Response Body:_
```
"Unauthorized"
```

This indicates that we need to be authenticated to use HTTP method PATCH with this endpoint. Let's log in to the app with credentials `wiener:peter` and click _View details_ on the product __Lightweight "l33t" Leather Jacket__.

On the bottom pane, in __History__ tab, find a `GET` request with Path `/api/products/1/price`, right click on it and click __Open in Requester Tab...__

Once the Requester Tab opens, change its HTTP method from `GET` to `PATCH` and send the request.

_Response Body:_
```
{
  "type":"ClientError",
  "code":400,
  "error":"Only 'application/json' Content-Type is supported"
}
```

This error message specifies that `Content-Type` should only be `application/json`, as it's the only supported MIME type for this API. Let's add it to the request headers and append a `{}` to the object body as an empty JSON object. Send the request.

_Response Body:_
```
{
  "type":"ClientError",
  "code":400,
  "error":"'price' parameter missing in body"
}
```

The response tells us that this request will work if we add `price` parameter in the request body. Let's add `{"price":0}` to the request body and resend the request.

_Response Body:_
```
{
  "price":"$0.00"
}
```

This changes the price of this product to `$0.00`.

Now add the product to the cart and place the order to solve the lab.

> Return to the [original write-up](README.md).
