# Race conditions [PortSwigger Academy]

<sup>This write-up covers the Race conditions section of Web Security Academy by PortSwigger.</sup>

## Limit overrun race conditions

One of the most common types of race conditions allows attackers to bypass restrictions defined by an application's business logic. 

For instance, imagine an online shop that lets users apply a promo code for a one-time discount at checkout. The application might follow these general steps:

1. Verify that the promo code hasn't been used by the user yet.
2. Apply the discount to the total order amount.
3. Update the database to indicate that the code has now been used.

### Limit overrun race conditions - Continued

Ordinarily, the workflow prevents re-using a one-time promo code: a request checks whether the code has already been redeemed, and if the answer is __true__ the discount is refused.

But if a customer submits two discount-code requests almost simultaneously, both reach the server while it is still in a transient state where __`code_already_used = false`__.

Because the database flag is only updated at the end of each request, both threads pass the check and each applies the discount before the flag is set. This brief period --- the _race window_ ---  lets an attacker redeem the same “one‑time” code multiple times.

```mermaid
sequenceDiagram
    participant User
    participant Server

    Note over Server: Normal validation flow
    User->>Server: Request 1 - Submit discount code
    Server->>Server: Check if code_already_used == false
    alt Not used
        Server->>Server: Apply discount
        Server->>Server: Set code_already_used = true
    else Already used
        Server->>User: Reject - Invalid code
    end

    Note over Server: Race condition scenario
    par Request 1
        User->>Server: Request 1 - Submit discount code
        Server->>Server: Check if code_already_used == false
        Server->>Server: Apply discount
        Server->>Server: Set code_already_used = true
    and Request 2
        User->>Server: Request 2 - Submit discount code
        Server->>Server: Check if code_already_used == false
        Server->>Server: Apply discount
        Server->>Server: Set code_already_used = true
    end
    Note over Server: Race window allows duplicate discounts
```
