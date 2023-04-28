# Domain Audit
The tool is a wrapper around PowerView, Impacket, PowerUpSQL, BloodHound, Ldaprelayscan and Crackmapexec to automate the execution of enumeration and a lot of checks performed during a On-Prem Active Directory Penetrationtest. Thanks to all the authors of the original tools.

## Installation & Setup
- Install python 3.10 (For example from the Windows store)
```
git clone https://github.com/0xJs/domain_audit
cd .\domain_audit\import\
git clone https://github.com/SecureAuthCorp/impacket
cd impacket; python3 -m pip install .
cd ../;
git clone https://github.com/zyn3rgy/LdapRelayScan;
cd LdapRelayScan;
python3 -m pip install -r .\requirements.txt
cd ../../;
```
- Make sure the path viariables in the script to the following tools are correct (if you followed the installation steps it should be)
```
$script:PowerView_Path = "$PSScriptRoot\import\PowerView.ps1"
$script:Powerupsql_Path = "$PSScriptRoot\import\PowerUpSQL.ps1"
$script:Impacket_Path = "$PSScriptRoot\import\impacket"
$script:BloodHound_Path = "$PSScriptRoot\import\Sharphound.ps1"
$script:GpRegisteryPolicy_Path = "$PSScriptRoot\import\GPRegistryPolicy\GPRegistryPolicy.psd1"
$script:CME_Path = "$PSScriptRoot\import\cme"
$script:LdapRelayScan_Path = "$PSScriptRoot\import\LdapRelayScan\LdapRelayScan.py"
```

- Issue with accessing Sysvol access denied?
    - To resolve this issue run `gpedit.msc`, go to `Computer -> Administrative Templates -> Network -> Network Provider -> Hardened UNC Paths`, enable the policy and click "Show" button.
    - Enter `*` into "Value name" and enter `RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0` in value.

## Running domain_audit
- Start PowerShell as Administrator
    - This is required to change the DNS server to DC IP and add domain to hosts file. Otherwise some checks/executions will fail such as Impacket.

### Run all checks
```
PS C:\Users\user\Desktop> . C:\Tools\domain_audit\domain_audit.ps1
PS C:\Users\user\Desktop> Invoke-ADCheckAll -Domain "amsterdam.bank.local" -User "john" -Password "Welcome2022!" -Server 10.0.0.3
```
- Example output at the bottom of the page.

### Run seperate checks
- Some checks need the DNS And domain name in the host file. So best is to set that!

#### Set dns and host file
```
Invoke-ChangeDNS -Server 10.0.0.3 -Domain "amsterdam.bank.local"
```

#### Run a check
```
Invoke-ADEnum -Domain "amsterdam.bank.local" -User "john" -Password "Welcome2022!" -Server 10.0.0.3
Invoke-ADEnumTrust -Domain "amsterdam.bank.local" -User "john" -Password "Welcome2022!" -Server 10.0.0.3
Invoke-ADCheckSQL -Domain "amsterdam.bank.local" -User "john" -Password "Welcome2022!" -Server 10.0.0.3
```

## Output
The tool will create a directory with the domain name and date on current directory or in the supplied location. In this directory there are three directories:
- ```Data```, has .csv files from domain objects, bloodhound data and some lists of objects.
- ```Findings```, has output from checks that could be something interesting or reported as a finding.
- ```Checks```, has output from checks that should be assessed manually to check ifs something to be reported.

## Checks
Invoke-ADCheckAll will execute the following in order:
- Collect basic data of AD objects and place them in `/data/` directory in `.csv` format
- Collect data with bloodhound - Collectionmethods all, acl and sessions in the background.
- Create list of all (enabled) users, admin accounts, computers and groups in `/data/`
- List amount of users, groups, computers, OU's, GPO's, Administrators, domain controllers and domain functional level.
- Check if the amount of admins is more then 5% (High amount of admins in the domain)
- Enumerate domain trusts and trusts within forst
- Check if AzureAD or Azure SSO is installed
- Execute a runas in a new window for the SQL checks
  - Check for SQL instances in the domain
  - Check if current user has access to SQL instances
    - Check if the current user is sysadmin
    - Gather database info on SQL instancees
    - Check as who the SQL instance is running
    - Check for database links as sysadmin
    - Run invoke-sqlaudit and save all data
       - Check for weak passwords
       - Check for Execute xp_dirtree and Execute xp_fileexist
- Check if domain functional level is 2016
- Check password policy configuration
    - Check for cleartextpasswords = 1
    - Check passwordlength
    - Check passwordcomplexity
    - Check account lockout
- Check if kerberos policy configuration is changed from the defaults
- Check if there is a GPO with LAPS in its name
    - Check to which OU's the GPO is applied to
    - Check the LAPS policy
        - Check adminaccountname
        - Check passwordcomplexity
        - Check passwordlength
        - Check passwordagedays
        - Check pwdexpirationprotection enabled
        - Check admpwdenabled  
- Check if there are systems with LAPS installed
    - Check if there are systems where LAPS isn't installed on
- If LAPS GPO found or LAPS computers found - Check if the current user can read LAPS passwords
- Get all users with a description - Manually check for passwords or interesting information
    - Check if the string pw, pass, ww or wachtwoord is in the description.
- Get all groups with a description - Manually check for passwords or interesting information
- Get all computers with a description - Manually check for passwords or interesting information
- Check if there are admins with a Spn
- Check if there are users with a Spn 
    - Kerberoast users with a Spn
- Check for users with constrained delegation
- Check for users with unconstrained delegation
- Check for computers with constrained delegation
- Check for computers with unconstrained delegation except domain controllers
- Check for computers with resource based constrained delegation set
- Check PASSWD_NOT_REQ attribute on users
    - Checks if users has empty password
- Check DONT_REQ_PREAUTH attribute on users
    - AS-REP Roast users
- Check DONT_EXPIRE_PASSWORD attribute on users
- Check if there are users with reversible encryption
- Check if there are users that use DES encryption
- Check if there are domain admins with an old password
- Check if the KRBTGT has a old password
- Check for EOL operating systems in the AD
- Check for EOS Windows 10 versions
- Check for inactive computerobjects with no login or pwdlastset older then 365 days
- Check for inactive users that didn't login the last 365 days
- Check if all privileged users are part of the protected users groups
- Check if all privileged users have the flag "This account is sensitive and cannot be delegated"
- Check if there are members of the following privileged groups: Account Operators, Backup Operators, Print Operators, DNS Admins, Schema Admins
- Check if there are computerobjects part of a high privileged groups
- Check who can add computerobjects to the domain
    - Check if this is the default authenticated users group
    - Check what the ms-ds-machineaccountqouta is, if it is null(good) or not-set(bad) or another value.
- Check ADIDNS 
    - if it contains createchild for the authenticated users group
    - If wildcard record exists
- Check membership of Pre-Windows 2000 Compatible Access group and if authenticated users is still member of it
- Check if printspooler service is running on the DC
- Check if LDAP signing is enabled, if LDAPS is configured and LDAPS binding is enabled
- Check if default Exchange groups exists within the domain
    - Check if there is an Exchange server and if its active
    - Check for memberships in the default Exchange groups
- Check for passwords in the sysvol
- Check for passwords in netlogon (scripts, programs etc)
- Retrieve IP adresses of all computer objects and create /24 ranges for further enumeration
  - Scan the ranges for well known Windows ports + ssh and web. Create lists for each port
  - Checks for SMB on accessible machines
    - Check SMBv1
    - Check signing requirement
    - Check for readable shares
    - Check for writable shares
    - Check if the webservice client is running on accessible machines
  - Check Access
    - Check if the current user is local admin through SMB
    - Check if the current user can access over WINRM
    - Check if the current user can access over RDP (WIP)
    - Check if the current user can access over MSSQL and is sysadmin (WIP)

## TO-DO & Features
- Create query for EOS Server versions?
- Update queries/checks for domain admin/enterprise admins to all privileged groups.
- Update queries to filter disabled users from data.
- Check for old vulnerable Exchange permissions
- Change privileged role function to loop and add more roles
- Remove -Ping function for accessible machines and execute a portscan for specific ports using Invoke-Portscan
- Check for access to discovered machines over SMB, RDP, MSSQL etc!
- Find a way to audit all ACL's (Invoke-ACLScanner doesnt work well from non domain joined perspective, -ResolvGUIDS breaks!)
- Add ADCS checks, but need to set this up in a LAB environment first.
- Add function to skip dns change
- Add dependancy options to each function

## Example output Invoke-ADCheckAll
```
PS C:\Users\user\Desktop> . C:\Tools\domain_audit\domain_audit.ps1
PS C:\Users\user\Desktop> Invoke-ADCheckAll -Domain "amsterdam.bank.local" -User "john" -Password "Welcome2022!" -Server 10.0.0.3

[+] Running as administrator, changing DNS to 10.0.0.3 and adding 10.0.0.3 amsterdam.bank.local to host file
[+] AD Authentication for amsterdam.bank.local\john succeeded!
[+] Output will be written in C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22

---------- DATA EXPLAINED ----------
- All data is written to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\
- In this folder are three subfolders
- files in \findings\ are findings that should be reported
- files in \checks\ needs to be checked
- files in \data\ is raw data

---------- COLORS EXPLAINED ----------
White is informational text
Green means check has passed
Yellow means manually check the data
Dark Red means finding

---------- GATHERING DATA ----------
[+] Gathering data of all Users, Groups, Computerobject, GPO's, OU's, DC's and saving it to csv
[+] Gathering BloodHound data all, session and ACL in seperate PowerShell session in background

---------- BASIC ENUMERATION ----------
[W] Saving a list of all users to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\list_users.txt
[W] Saving a list of all enabled users to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\list_users_enabled.txt
[W] Saving a list of all administrators to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\list_administrators.txt
[W] Saving a list of all groups to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\list_groups.txt
[W] Saving a list of all computerobjects to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\list_computers.txt

---------- DOMAIN INFORMATION ----------
The domain functional level is: Windows 2016
In the domain amsterdam.bank.local there are:
- 27 users and 25 enabled users
- 51 groups
- 4 computers
- 4 OU's
- 2 GPO's
- 3 Administrators
- 1 Domain Controllers

---Checking if amount of admins is more then 5% of all users---
[-] There are 3 administrators, which is 11.11% of all users
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\large_amount_of_administrators.txt

---------- ENUMERATING DOMAIN TRUSTS ----------
[+] The domain amsterdam.bank.local trusts 1 domains which are:
bank.local
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\trusts.txt

[+] The trust for domain bank.local is WITHIN_FOREST, enumerating trusts
[+] The domain bank.local trusts 2 domains which are:
amsterdam.bank.local
secure.local
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\trusts.txt

---Checking if AzureAD connect is in use---
[+] AzureAD connect is not installed

---Checking if Azure SSO is in use---
[+] Azure SSO is not configured

---------- EXECUTING CHECKS ----------
[+] Executing in another window because runas is required
[+] Pleace manually supply the Password Welcome2022!
--- Running SQL checks in new window ---
Enter the password for amsterdam.bank.local\john:
Attempting to start powershell.exe -Exec bypass -NoExit Import-Module C:\Tools\domain_audit\domain_audit.ps1; Set-Variable Findings_Path -Value C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings; Set-Variable Data_Path -Value C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data; Set-Variable Checks_Path -Value C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\checks; Set-Variable OutputDirectoryCreated -Value True; Invoke-ADCheckSQL -Domain amsterdam.bank.local -Server 10.0.0.3 -User john -Password Welcome2022! -SkipPrompt as user "amsterdam.bank.local\john" ...

---Checking password policy---
[+] Passwordpolicy contains ClearTextPassword=0. Domain controller does not save passwords in cleartext
[-] Password length requirement is 7 characters
[-] PasswordComplexity is 0 (Disabled)!
[-] LockOutBadCount is 0, accounts wont be locked!
[-] ResetLockoutCount is not set
[-] LockoutDuration is not set
Writing password policy to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\passwordpolicy.txt

---Checking if there is a GPO with LAPS---
[-] There is no GPO with LAPS in their name

---Checking if LAPS is enabled on any computerobject---
[-] There are no systems where LAPS is enabled
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\laps_notenabled.txt

---Checking description field for passwords---
[-] There are 4 users that have a description, please manually check for passwords!
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\checks\description_users.txt

---Checking groups description field for interesting information---
[-] There are 45 groups that have a description, please manually check for passwords or interesting information!
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\checks\description_groups.txt

---Checking computerobjects description field for interesting information---
[+] There are no computerobjects with a description

---Checking kerberoastable administrators---
[-] There are 1 kerberoastable administrators
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\administrators_serviceprincipalname.txt

---Checking kerberoastable users---
[-] There are 2 kerberoastable users
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_serviceprincipalname.txt
[+] Requested 2 hashes, please crack with hashcat
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_kerberoast_hashes.txt

---Checking if there are users with the DONT_REQ_PREAUTH attribute---
[-] There are 2 users with the attribute DONT_REQ_PREAUTH
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_dontrequirepreath.txt
[+] Requested 2 hashes, please crack with hashcat
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_aspreproast_hashes.txt

---Checking constrained delegation users---
[-] There are 1 users that have constrained delegation enabled
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_constrained_delegation.txt

---Checking unconstrained delegation computerobjects, excluding domain-controllers---
[-] There are 1 users that have unconstrained delegation enabled
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_unconstrained_delegation.txt

---Checking constrained delegation computerobjects---
[+] There are no computerobjects with constrained delegation

---Checking unconstrained delegation computerobjects, excluding domain-controllers---
[-] There are 1 computerobjects that have unconstrained delegation enabled
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\computers_unconstrained_delegation.txt

---Checking resource based constrained delegation computerobjects---
[+] There are no computerobjects with resource based constrained delegation

---Checking if there are users with the PASSWD_NOTREQD attribute---
[-] There are 2 users with the attribute PASSWD_NOTREQD
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_passwdnotreqd.txt

---Checking for users with empty password---
[-] The password for user bank_dev is empty
[-] The password for user steve is empty

---Checking if there are users with the DONT_EXPIRE_PASSWORD attribute---
[-] There are 17 users with the attribute DONT_EXPIRE_PASSWORD
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\users_dontexpirepassword.txt

---Checking if there are users with the reversible encryption---
[+] There are no users with reversible encryption

---Checking if there are users with DES encryption---
[+] There are no users with DES encryption

---Checking if administrator accounts - that aren't disabled - have a password older then 365 days---
[+] There where no enabled administrators with a password older then 365 days

---Checking if KRBTGT account has a password older then 365 days---
[+] The password from the krbtgt is not older then 365 days

---Checking if there are EOL operating systems in the AD---
[+] There are no computerobjects in the AD that are EOL

---Checking if there are end of service Windows 10 operating systems in the AD---
[+] There are no Windows 10 computerobjects computerobjects in the AD that are End Of Service

---Checking if there are computerobjects that have no login or login/pwdlastset older then 365 days---
[+] There are no computerobjects in the AD that are inactive

---Checking if there are users that didn't login for 365 days---
[+] There are no users in the AD that are inactive (didn't login or changed their password in the last 365 days)

---Checking if members of privileged groups are part of the protected users group---
[-] There are 3 privileged users not part of the protected users group
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\administrators_notin_protectedusersgroup.txt

---Checking if members of privileged groups have the flag 'this account is sensitive and cannot be delegated'---
[-] There are 3 privileged users without the flag 'this account is sensitive and cannot be delegated' that aren't in the Protected Users group
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\administrators_delegation_flag.txt

---Checking if there are members in high privileged groups---
[+] There are no users in the Account Operators group
[+] There are no users in the Backup Operators group
[+] There are no users in the Print Operators group
[+] There are no users in the DNS Admins group
[+] There are no users in the Schema Admins group

---Checking if there are computerobjects part ofhigh privileged groups---
[+] There are no computerobjects part of a high privileged groups

---Checking who can add computerobjects to the domain---
[-] The authenticated users group(S-1-5-11) can add 10 computerobjects to the domain
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\authenticated_users_can_join_domain.txt
[W] Writing amount of computerobjects that can be joined to the domain by the object to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\checks\can_join_domain_amount.txt

---Checking if there are passwords in the SYSVOL share---
This might take a while
[+] Checking SYSVOL of DC02
[-] There might be 1 passwords in the SYSVOL of DC02. Please manually check
Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\checks\sysvol_passwords.txt

---Checking if there are passwords in the NETLOGON share---
This might take a while
[+] Checking NETLOGON of DC02
[-] There might be 1 passwords(string pass) in the NETLOGON of DC02. Please manually check
Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\checks\netlogon_passwords.txt

---Checking printspooler service on each DC---
[-] Printspooler enabled on DC02
Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\printspooler_domaincontrollers.txt

---Running LdapRelayScan---
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\domaincontrollers_ldaprelayscan.txt

---Checking for LDAP signing---
[+] One or more domain controller(s) does not require LDAP signing
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\domaincontrollers_no_ldap_signing.txt

---Checking for LDAPS binding---
[+] One or more domain controller(s) does not require LDAPS binding
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\domaincontrollers_no_ldaps_binding.txt

---Checking if exchange is used within the domain---
[+] No Exchange groups exist

---Checking which machines are reachable from current machine through ping---
[+] There are 3 computers which are reachable
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\computers_accessible.txt

---Running crackmapexec against each reachable host enumerating SMB data and shares---
[+] Crackmapexec will hang and needs a enter to continue
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\crackmapexec_reachablecomputers.txt

---Checking for hosts which have SMBV1 enabled---
[+] There are no reachable computers which have SMBV1 enabled (SMBv1:True)

---Checking for hosts without signing---
[+] There are 2 reachable computers which does not require signing (Signing:False)
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\computers_nosigning.txt

---Checking for shares with READ access---
[+] There are 4 shares the current user can READ
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\shares_read_access.txt

---Checking for shares with WRITE access---
[+] There are 1 shares the current user can WRITE to
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\shares_write_access.txt

---Running crackmapexec against each reachable host enumerating webclient service---
[+] Crackmapexec will hang and needs a enter to continue
[W] Writing all data to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\data\crackmapexec_webdav.txt

[+] There are 1 systems with the webclient service running
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\computers_webdav.txt

---------- EXECUTING SQL CHECKS ----------
---Checking MSSQL instances---
[+] Found 1 MSSQL instances
[+] Checking connection to each MSSQL instance
[-] The current user can access 1 MSSQL instances
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\SQLserver_user_has_access.txt

---Checking if the user is sysadmin on the accessible instances---
[+] The current user is not sysdmin to any SQL instances

---Checking database links for sysadmin security context---
[-] There are 1 links which run under the security context of a sysadmin user
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\SQLserver_sysadmin_on_links.txt

---Running Invoke-SQLAudit on the accessible instances---
This might take a while
VERBOSE: WEB01.amsterdam.bank.local : No named instance found.
VERBOSE: WEB01.amsterdam.bank.local : Connection Success.
VERBOSE: WEB01.amsterdam.bank.local : Checking for autoexec stored procedures...
[-] Invoke-SQLAudit found 7 issues
[W] Writing to C:\Users\user\Desktop\amsterdam.bank.local-2022-08-22\findings\SQLserver_sqlaudit.txt
```

![image](https://user-images.githubusercontent.com/43987245/179800219-f087ba71-7d87-4a03-8f02-f5833b6a0289.png)
