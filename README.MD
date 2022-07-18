# Domain Audit
The tool is a wrapper around PowerView, Impacket, PowerUpSQL and BloodHound to execute a lot of checks I normally perform during a AD pentest/assesment. **The tool is still being developed and tested.** Thanks to all the authors of the tools listed above!

## Installation
- Make sure that Python and [Impacket](https://github.com/SecureAuthCorp/impacket) are installed for kerberoasting/as-rep roasting.
- Make sure the path viariables to the following tools are correct, especially impacket.
```
$powerview_path = "$PSScriptRoot\import\PowerView.ps1" 
$impacket_path = "$PSScriptRoot\import\impacket"
$bloodhound_path = "$PSScriptRoot\import\Sharphound.ps1"
$sqlchecks_path = "$PSScriptRoot\sql_checks.ps1"
$gpregisterpolicy_path = "$PSScriptRoot\import\GPRegistryPolicy\GPRegistryPolicy.psd1"
```

## Running the tool
- Start PowerShell as Administrator
    - This is required to change the DNS server to DC IP and add domain to hosts file. Otherwise some checks/executions will fail such as Impacket.
```
Invoke-ADCheckAll -User <USER> -Password <PASSWORD> -Domain <DOMAIN> -Server <DC IP>
```

## Output
The tool will create a directory with the domain name and date on the desktop. In this directory there are three directories:
- ```Data```, has .csv files from domain objects, bloodhound data and some lists of objects.
- ```Findings```, has output from checks that could be something interesting or reported as a finding.
- ```Checks```, has output from checks that should be assessed manually to check ifs something to be reported.

## Checks
Invoke-ADCheckAll will execute the following in order:
- Collect basic data of AD objects and place them in `/data/` directory in `.csv` format
- Collect data with bloodhound - Collectionmethods all, acl and sessions in the background.
- Create list of all (enabled) users, admin accounts, computers and groups in `/data/`
- List amount of users, groups, computers, OU's, GPO's, Administrators
- Check if the amount of admins is more then 5% (High amount of admins in the domain)
- Enumerate domain trusts and trusts within forst
- Check if AzureAD or Azure SSO is installed
- Execute a runas in a new window for the SQL checks
  - Check for SQL instances in the domain
  - Check if current user has access to SQL instances
    - Check if the current user is sysadmin
    - Run invoke-sqlaudit
    - Check for database links as sysadmin
- Check password policy configuration
    - Check for cleartextpasswords = 1
    - Check passwordlength
    - Check passwordcomplexity
    - Check account lockout
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
- Get all groups with a description - Manually check for passwords or interesting information
- Get all computers with a description - Manually check for passwords or interesting information
- Check if there are admins with a Spn
- Check if there are users with a Spn 
    - Kerberoast users with a Spn
- Check for users with constrained delegation
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
- Check for accessible machines

## TO-DO
- A way to enumerate all shares, PowerView is doing weird. Crackmapexec is better but output is not in powershell and my crackmapexec is broken atm.
- Add ADCS checks?
- Add GPO checks
- Check for signing and binding LDAP port
- Expand Invoke-ADCheckDescriptions to check for the word pass and for duch ww and wachtwoord etc.
- Add Unconstrained delegation for user?
- Add checks for kerberos password policy?
- Add function to skip dns change
- Check if printspooler is enabled on DC's
- Check if webdav is active on hosts
- Add SQL query to retrieve databases of accessible SQL servers
- Check what happens when domain join amount is not 10.
- Check for admin count on users or groups which are no longer admin
- Find a way to audit all ACL's.
- Split invoke-sqlaudit into seperate checks
- Function to generate a password spray list
- Add functionality to start password spray?
