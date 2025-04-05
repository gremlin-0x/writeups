# Mr. Robot CTF [TryHackMe]

<sup>This write-up covers the steps to root Mr. Robot CTF machine on TryHackMe platform.</sup>

First let's scan the target:

```bash
nmap -p- --script=vuln $targ3t -oN general.scan -vv
```

This is understandably going to take a while, but we already see open ports `80` and `443` pop up in the scan: 

```
Discovered open port 443/tcp on 10.10.48.148
Discovered open port 80/tcp on 10.10.48.148
```

This means this machine has a web interface. Let's check it out:

```bash
firefox $targ3t
```

There is a command interface that encourages the users to interact with it. Before I play around with it, I'll put it through `feroxbuster` to see if it has anything hiding behind it:

```bash
feroxbuster -u http://$targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```


