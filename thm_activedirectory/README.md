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
xfreerdp /u:Sophie@THM /p:Pass!@#$1234 /v:10.10.185.134 /cert:ignore +clipboard
```

Change the password and capture the flag!

- The process of granting privileges to a user over some OU or other AD Object is called...
- __Delegation_

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


