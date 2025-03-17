# OverTheWire --- Bandit

### Level 0
The goal of this level is for you to log into the game using SSH. The host to which you need to connect is bandit.labs.overthewire.org, on port 2220. The username is bandit0 and the password is bandit0. Once logged in, go to the Level 1 page to find out how to beat Level 1.

First I'm going to define host and port above as variables in the shell, because I'm going to need them throughout this wargame. I'll the name the variable `h0st` and pass it value of `bandit.labs.overthewire.org`:
```
h0st=bandit.labs.overthewire.org
```
Next I'll do the same with the `p0rt` variable and value `2220`:
```
p0rt=2220
```
After that I'll log into the machine on this host and port with username `bandit0` and password `bandit0` using `ssh`:
```
ssh bandit0@$h0st -p $p0rt
```
Congratulations, you're in!

### Level 0 ---> 1
The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

List all the contents of the home directory:
```
ls ~
```
As we can see there is a `readme` file in the home directory. Let's see its contents:
```
cat ~/readme
```
The last line of the output shows the password. Let's save it on our local system:
```
scp -P $p0rt bandit0@$h0st:/home/bandit0/readme readme_copied
```
Now use this password to log in as user `bandit1` at `$h0st` on `$p0rt`.
```
ssh bandit1@$h0st -p $p0rt
```

### Level 1 ---> 2
The password for the next level is stored in a file called - located in the home directory.

If we try to show contents of the `-` file, it won't work. However if we enclose the filename in quotes like this `"-"` and precede it with a path `~/`:
```
cat ~/"-"

```
It will output the contents of the file. Now go ahead and `ssh` into next level.

### Level 2 ---> 3
The password for the next level is stored in a file called spaces in this filename located in the home directory.

If we enclose the filename in quotes like this `"spaces in the filename"` outputing its contents with a `cat` command will work:
```
cat "spaces in this filename"
```
The content is the password you need for the next level. Use it to ssh into `bandit3`.

### Level 3 ---> 4
The password for the next level is stored in a hidden file in the inhere directory.

To list hidden files in any directory we will need an `ls` command with an `-a` switch:
```
ls -a inhere/
```
As we can see the file we need is `...Hiding-From-You`. Let's open up its contents:
```
cat inhere/...Hiding-From-You
```
Grab the password and `ssh` into `bandit4`

### Level 4 ---> 5
The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

Let's go to the inhere directory and list all its contents:
```
cd inhere && ls -a
```
We can see that the naming convention of these files starts with `-` and ends with a two digit number `##` like `-file##`. Let's open each file and find out human-readable string:
```
cat ~/inhere/"-file07"
```
That's the file with the password. Use it to ssh into `bandit5`.

### Level 5 ---> 6
The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:

> human-readable
> 
> 1033 bytes in size
> 
> not executable

I will list contents of `inhere` directory recursively and filter out only files with `1033` bytes in size:
```
ls -laR inhere | grep 1033
```
Now that we know a file like that is here, and it is not executable, let's check if it's human readable. But first let's find its full path:
```
find ~/inhere/ -type f -name ".file2" -size 1033c
```
It returns a full path of the file we found. Let's see what's inside:
```
cat /home/bandit5/inhere/maybehere07/.file2
```
We got the password. Let's use it to login to `bandit6`

### Level 6 ---> 7
The password for the next level is stored somewhere on the server and has all of the following properties:

> owned by user bandit7
>
> owned by group bandit6
>
> 33 bytes in size

I'll use the following `find` command to try to find this file by all of the above properties:
```
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
```
This command returned the full path of this file. Let's open it and see what's inside:
```
cat /var/lib/dpkg/info/bandit7.password
```
This is the password for level `bandit7`.

### Level 7 ---> 8
The password for the next level is stored in the file data.txt next to the word millionth

I'll be using `grep` to find the word `millionth` in this data and also awk to extract only the password as output:
```
cat data.txt | grep "millionth" | awk '{print $2}'
```
This is the password for the next level.

### Level 8 ---> 9
The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

Let's sort the data and find unique strings in it:
```
cat data.txt | sort | uniq -u
```
The output is the password for next level.

### Level 9 ---> 10
The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

To find this password we will use `strings` command and filter output with `grep`:
```
strings data.txt | grep -E "^==.*"
```
The last entry is our password.

### Level 10 ---> 11
The password for the next level is stored in the file data.txt, which contains base64 encoded data.

For this we will need to use `base64` to decode data in `data.txt`:
```
base64 --decode data.txt
```
The output tells us the password.

### Level 11 ---> 12
The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

Let's use `tr` command for this task:
```
cat data.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
```
This is the password for the next level.

### Level 12 ---> 13
The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)

First we need to create a temp directory and navigate to it:
```
mktemp -d
cd /tmp/tmp.vOEBr5463p
```
Then we need to copy our `data.txt` file located in the home directory to this temp directory:
```
cp ~/data.txt .
```
Let's rename it and call it what it is --- a `hexdump_data`:
```
mv data.txt hexdump_data
```
We can output the beginning of this hexdump with a `head` command:
```
head hexdump_data
```
We use an `xxd` command to revert the hexdump and get the actual data:
```
xxd -r hexdump_data compressed_data
head compressed_data
```
This file is unreadable so we need to understand what to use to decompress it. To do that we need to `head` the `hexdump_file` once again and compare its first bytes with the [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
```
head hexdump_data
```
As we can see the starting `1F 8B` of this file matches the `.gz` file signature, which means it is a `gzip` compressed file. Let's rename the compressed file accordingly and decompress it, with gzip:
```
mv compressed_data compressed_data.gz
gzip -d compressed_data.gz
```
Now let's see the contents of the resulting file:
```
head compressed_data
```
Still unreadable. Let's look at its first bytes and check in the list of signatures once again:
```
xxd compressed_data | head
```
The first bytes `42 5a 68` match the file signature of `bz2` archives, let's try and decompress it with `bzip2`
```
mv compressed_data compressed_data.bz2
bzip2 -d compressed_data.bz2
```
Let's look into the resulting file:
```
head compressed_data
```
Unreadable again. Let's look into its first bytes again.
```
xxd compressed_data | head
```
This looks familiar, it is the same sequence as it was with `gz` files above --- `1f 8b`. Let's decompress it with `gzip` once again:
```
mv compressed_data compressed_data.gz
gzip -d compressed_data.gz
```
Let's look inside the resulting file:
```
cat compressed_data
```
It outputs a long string that starts with `data5.bin` which is presumably the name of the file it holds compressed and also a `0ustar`, which if we check in the list of file signatures, indicates it is a tar archive as it resembles the ISO code of it, let's try to unarchive it, with `tar`:
```
mv compressed_data compressed_data.tar
tar -xf compressed_data.tar
```
If we check what the resulting file `data5.bin` is, we get much of the same:
```
xxd data5.bin | head
```
It seems to be another `tar` archive with a file named `data6.bin` in it. Let's extract it:
```
mv data5.bin data5.bin.tar
tar -xf data5.bin.tar
```
This yields the file named `data6.bin`. Let's check what it is:
```
xxd data6.bin | head
```
Again a familiar sequence `42 5a 68` indicating a `bzip2` compressed file. Let's decompress it and look open it with `xdd`.
```
mv data6.bin data6.bin.bz2
bzip2 -d data6.bin.bz2
xdd data6.bin | head
```
Looks like another `tar` archive with a `data8.bin` file inside it. We know what to do by now:
```
mv data6.bin data6.bin.tar
tar -xf data6.bin.tar
xxd data8.bin | head
```
Based on the beginning byte sequence, nothing we haven't seen --- it's another `gzip` compressed file, that seems to hold `data9.bin` inside it:
```
mv data8.bin data8.bin.gz
gzip -d data8.bin.gz
cat data8.bin
```
This is the password for the next level.

### Level 13 ---> 14
The password for the next level is stored in /etc/bandit\_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on.

If we list the contents of the current working directory:
```
ls
```
We are going to notice a file named `sshkey.private`. Let's download it to our host machine:
```
scp -P $p0rt bandit13@h0st:/home/bandit13/sshkey.private sshkey.private
```
To use this key to login to `bandit14` we first need to make sure only the user has permissions to use it in any way:
```
chmod 700 sshkey.private
```
Next we `ssh` into bandit14:
```
ssh -i sshkey.private bandit14@$h0st -p $p0rt
```
And we're in.

### Level 14 ---> 15
The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

First let's find out what the password for the current level is:
```
cat /etc/bandit_pass/bandit14
```
Now let's use `netcat` to connect to the port `30000` on the localhost (`127.0.0.1`):
```
nc 127.0.0.1 30000
```
Just paste the password for bandit14 in the prompt and it will return the password for the next level.

### Level 15 ---> 16
The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL/TLS encryption.

> Helpful note: Getting “DONE”, “RENEGOTIATING” or “KEYUPDATE”? Read the “CONNECTED COMMANDS” section in the manpage.

For this level we will have to use `openssl s_client` to get it to work:
```
openssl s_client -connect 127.0.0.1:30001
```
Once the prompt opens, paste the password to the current level there. If you don't have the password to the current level, obtain it this way:
```
cat /etc/bandit_pass/bandit15
```

### Level 16 ---> 17
The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

> Helpful note: Getting “DONE”, “RENEGOTIATING” or “KEYUPDATE”? Read the “CONNECTED COMMANDS” section in the manpage. 

First let's find the password for the current level:
```
cat /etc/bandit_pass/bandit16
```
Now let's find out which of the ports in the named range have ssl connections.
```
nmap -sV -p31000-32000 127.0.0.1 | grep ssl
```
Let's choose the one with `ssl/unknown` and make sure to add `-ign_eof` option to avoid `KEYUPDATE` prompt:
```
openssl s_client -ign_eof -connect 127.0.0.1:31790
```
Enter the password in the prompt. You will get an output of private ssh key. Use it to log in as `bandit17`.

### Level 17 ---> 18
There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new

> NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19

Let's just use the `diff` command and compare the two files:
```
diff passwords.old passwords.new
```
The resulting difference in the second (third) output line is the string in `passwords.new` that is the password for `bandit18`

### Level 18 ---> 19
The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

When you try to log into `bandit18` via `ssh` it indeed logs you out immediately. Let's see if we can execute commands on the remote system via `ssh`:
```
ssh bandit18@$h0st -p $p0rt ls
```
It worked. After we submitted the password the command listed the contents of the home directory for `bandit18`. The output shows a sole `readme` file. Let's read it:
```
ssh bandit18@$h0st -p $p0rt cat readme
```
This is the password for `bandit19`

### Level 19 ---> 20
To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit\_pass), after you have used the setuid binary.

Let's see the name of said binary in the home directory:
```
ls
```
The binary is named `bandit20-do`. Let's try to run it:
```
./bandit20-do
```
The output details that we're supposed to follow running the binary with a command we want to run as user `bandit20`. Well, that's easy --- we want to find out their password from a password directory:
```
./bandit20-do cat /etc/bandit_pass/bandit20
```
This is the password for user `bandit20`

### Level 20 ---> 21
There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

> NOTE: Try connecting to your own network daemon to see if it works as you think

We can create a connection in server mode using netcat, which listens to inbound connection on port `1234`:
```
echo $(cat /etc/bandit_pass/bandit20) | nc -lp 1234 &
```
As you can see we are piping the password for `bandit20` (current user) into netcat. Now we can run the setuid binary for port `1234`:
```
./suconnect 1234
```
The passwords matched and the password for the next level has been returned.

### Level 21 ---> 22
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

Let's see what's in each file in the `/etc/cron.d/` directory:
```
cat /etc/cron.d
```
Looks like `cronjob_bandit22` is running the `/usr/bin/cronjob_bandit22.sh` script. let's see what's inside it:
```
cat /usr/bin/cronjob_bandit22.sh
```
Looks like a `/tmp` folder is holding the file with the bandit22 password there. Let's open it.
```
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
This is the password for the next level.

### Level 22 ---> 23
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

> NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

Let's look into `/etc/cron.d`:
```
ls /etc/cron.d
```
Let's open `cronjob_bandit23`:
```
cat /etc/cron.d/cronjob_bandit23
```
Looks like it again points to a script in `/usr/bin` named `cronjob_bandit23.sh`. Let's see what's inside it:
```
cat /usr/bin/cronjob_bandit23.sh
```
Looks like it creates a `/tmp` file with a name generated from current user's username (`bandit22`) and copies the password for it to that file. Let's run the part that generates the folder name, only use `bandit23` and see what happens:
```
echo I am a user bandit23 | md5sum | cut -d ' ' -f 1
```
Now that we have a string, let's try to open a file in a `/tmp` directory that matches the same string:
```
cat /tmp/$(echo I am a user bandit23 | md5sum | cut -d ' ' -f 1)
```
This is the password for the next level.

### Level 23 ---> 24
A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

> NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!

> NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

Let's list all files in `/etc/cron.d`:
```
ls /etc/cron.d
```
There is a file named `cronjob_bandit24`, let's see its contents:
```
cat /etc/cron.d/cronjob_bandit24
```
Looks like it deletes all files in `/var/spool/bandit24/foo`, but executes scripts owned by `bandit23`. Let's create a temp directory where we will create our script to be executed:
```
cd $(mktemp -d)
vim bandit24_pass.sh
```
Let's write the following script:
```
#! /bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/tmp.3XNMCPH3IG/password
```
Now let's give necessary permissions to our script and create `password` file which it modifies and give permissions to it as well and finally move `bandit24_pass.sh` script to `/var/spool/bandit24/foo`:
```
chmod 777 bandit24_pass.sh
chmod 777 /tmp/tmp.3XNMCPH3IG
touch password
chmod 777 password
cp bandit24_pass.sh /var/spool/bandit24/foo/bandit24_pass.sh
```
Now try to open the `password` file:
```
cat password
```
This is the password to the next level.

### Level 24 ---> 25
A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.
You do not need to create new connections each time

Let's copy the password for the current user:
```
cat /etc/bandit_pass/bandit24
```
Now let's try to inject the password and a for loop with four digit pin codes!
```
echo "$(for i in {0000..9999}; do echo gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i; done)" | nc 127.0.0.1 30002 
```
This is the password for the next level.

### Level 25 ---> 26
Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

> NOTE: if you’re a Windows user and typically use Powershell to ssh into bandit: Powershell is known to cause issues with the intended solution to this level. You should use command prompt instead.

Let's find out what the shell is for user `bandit26`:
```
cat /etc/passwd | grep bandit26
```
We got `/usr/bin/showtext`. Let's find out what it is:
```
cat /usr/bin/showtext
```
It opens a file in the home directory called `text.txt` with `more`. Let's list the current directory:
```
ls
```
There seems to be an ssh key to `bandit26`. Let's download it.

### Level 26 ---> 27
Good job getting a shell! Now hurry and grab the password for bandit27!

Let's download the `bandit26.sshkey`:
```
scp -P $p0rt bandit25@$h0st:/home/bandit25/bandit26.sshkey bandit26.sshkey
```
Now let's minimize the terminal window as much as possible and use the key to log into `bandit26`:
```
ssh -i bandit26.sshkey bandit26@$h0st -p $p0rt
```
It opened the `more` interface. Now let's press `v` on the keyboard to enter `vim` environment. 

Now let's press `:` and type:
```
set shell=/bin/bash
```
Once that is done, press `:` again and type:
```
shell
```
Now you're inside the shell, list directories:
```
ls
```
As you can see there is `bandit27-do` binary like in one of the previous levels. Use it to find password to `bandit27`:
```
./bandit27-do cat /etc/bandit_pass/bandit27
```
This is the password for the next level.

### Level 27 ---> 28
There is a git repository at ssh://bandit27-git@localhost/home/bandit27-git/repo via the port 2220. The password for the user bandit27-git is the same as for the user bandit27.

Clone the repository and find the password for the next level.

Let's make a temporary directory for the project and navigate to it:
```
cd $(mktemp -d)
```
Now let's clone the repository to this directory:
```
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
```
Let's list everything in the repo directory:
```
ls -la repo
```
Let's check out the `README` file:
```
cat repo/README
```
This is the password to the next level:

### Level 28 ---> 29
There is a git repository at ssh://bandit28-git@localhost/home/bandit28-git/repo via the port 2220. The password for the user bandit28-git is the same as for the user bandit28.

Clone the repository and find the password for the next level.

Let's make a temporary directory and navigate to it:
```
cd $(mktemp -d)
```
Now let's clone the repository to this directory:
```
git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
```
Let's list the contents of the cloned repo:
```
ls -la repo
```
Let's see what's in the `README.md`:
```
cat repo/README.md
```
It mentions a password, but doesn't show it. Let's check the git logs:
```
cd repo
git log
```
One of the commits has a message `fix info leak`. Let's copy the commit id and see what changes were made:
```
git show 8cbd1e08d1879415541ba19ddee3579e80e3f61a
```
We have the password for the next level.

### Level 29 ---> 30
There is a git repository at ssh://bandit29-git@localhost/home/bandit29-git/repo via the port 2220. The password for the user bandit29-git is the same as for the user bandit29.

Clone the repository and find the password for the next level.

Let's make a temporary directory and navigate to it:
```
cd $(mktemp -d)
```
Now let's clone the repository to this directory:
```
git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
```
Let's list the contents of the cloned repo:
```
ls -la repo
```
Let's look into the `README.md` file:
```
cat repo/README.md
```
It mentions a password but doesn't show it. It also mentions "production", which indicates there could be other branches. Let's list all the branches:
```
cd repo
git branch -a
```
There is a `dev` branch. Let's switch to it:
```
git checkout dev
```
Let's see the files:
```
ls -la
```
There is a `README.md` file for this branch. Let's see it:
```
cat README.md
```
This is the password for the next level.

### Level 30 ---> 31
There is a git repository at ssh://bandit30-git@localhost/home/bandit30-git/repo via the port 2220. The password for the user bandit30-git is the same as for the user bandit30.

Clone the repository and find the password for the next level.

Let's make a temporary directory and navigate to it:
```
cd $(mktemp -d)
```
Now let's clone the repository to this directory:
```
git clone ssh://bandit30-git@localhost:2220/home/bandit30-git/repo
```
Let's list the contents of the cloned repo:
```
ls -la repo
```
Let's look into the `README.md` file:
```
cat repo/README.md
```
It's just an empty file. Let's check the `git tag`:
```
cd repo
git tag
```
Let's see what it is:
```
git show secret
```
This is the password for the next level.

### Level 31 ---> 32
There is a git repository at ssh://bandit31-git@localhost/home/bandit31-git/repo via the port 2220. The password for the user bandit31-git is the same as for the user bandit31.

Clone the repository and find the password for the next level.

Let's make a temporary directory and navigate to it:
```
cd $(mktemp -d)
```
Now let's clone the repository to this directory:
```
git clone ssh://bandit31-git@localhost:2220/home/bandit31-git/repo
```
Let's list the contents of the cloned repo:
```
ls -la repo
```
Let's look into the `README.md` file:
```
cat repo/README.md
```
The `README.md` file states we have to push a file named `key.txt` with content `May I come in?` to the repository. Let's create the file:
```
cd repo
echo "May I come in?" > key.txt
```
Now we have to push this file, however the `.gitignore` file excludes `.txt` files from the repository:
```
cat '.gitignore'
```
Let's push it anyway with `git add`:
```
git add -f key.txt
git commit -a
```
Add a commit message in `nano`, save the file and:
```
git push
```
This is the password for the next level.

### Level 32 ---> 33
After all this git stuff, it’s time for another escape. Good luck!

Let's type `$0` to break out of the uppercase shell:
```
$0
```
Now let's check all files in the directory:
```
ls -la
```
The file `uppershell` is owned by and runs as `bandit33`. Which means we can retrieve password for bandit33:
```
cat /etc/bandit_pass/bandit33
```
This is the password for the next level.

### Level 33 ---> 34
At this moment, level 34 does not exist yet.
