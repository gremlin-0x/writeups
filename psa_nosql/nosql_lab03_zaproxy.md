# Lab: Exploiting NoSQL injection to extract data [OWASP Zed Attack Proxy]

## _Brute-force section_

Log in as `wiener:peter` and find `GET /usr/lookup?user=wiener` request under __History__ tab with response body of:

```json
{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "role": "user"
}
```

Right-click it and select "Open in Requester Tab...". Right-click it there again and select "FUZZ...". 

Inside the Fuzzer interface, click Edit and replace the query value (`wiener`) with the following: `administrator' && this.password[0]=='a` and click Save. 

- Select the `0` inside `[0]` and under the Fuzz Locations click "Add..." and then "Add..." again. 
- In the dropdown select "Numberzz" instead of "Strings" and give the range From 0 To 7. 
- Click "Add" and then "OK".
- Once you're back to the request, select `a` in `=='a` and under the Fuzz Locations click "Add..." and then "Add..." again.
- Select "Strings" in the dropdown and enter the entire lowercase alphabet from `a` to `z` on new lines. 
- Click "Add" and then "OK".
- Start Fuzzer!

Sort by _Payloads_ column from lower to higher and then by _Size Resp. Body_ from higher to lower. You should get your password character by character under _Payloads_ column soon enough. 
