# Author Jony Schats - 0xjs

#Parameters
Param(
   [Parameter(Mandatory=$true)]
   [string]$Domain,
   
   [Parameter(Mandatory=$true)]
   [string]$Server,
   
   [Parameter(Mandatory=$true)]
   [string]$User,
   
   [Parameter(Mandatory=$true)]
   [string]$Password
) #end param

if(-not($Domain)) { Throw “You must supply a value for -Domain” }
if(-not($Server)) { Throw “You must supply a value for -Server” }
if(-not($User)) { Throw “You must supply a value for -User” }
if(-not($Password)) { Throw “You must supply a value for -Password” }

# PLEASE EDIT THESE VARIABLES BEFORE YOU RUN!
$powerview_path = "$PSScriptRoot\import\PowerView.ps1" 
$impacket_path = "$PSScriptRoot\import\impacket"
$bloodhound_path = "$PSScriptRoot\import\Sharphound.ps1"
$sqlchecks_path = "$PSScriptRoot\sql_checks.ps1"
$gpregisterpolicy_path = "$PSScriptRoot\import\GPRegistryPolicy\GPRegistryPolicy.psd1"

#Check if running as administrator and if yes then change dns and hostfile!
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)){
	# Set DNS for adapter
	Write-Host "[+] Changing DNS for each adapter to IP DC"
	$Array = Get-DnsClientServerAddress
	foreach($element in $Array)
		{
			Set-DnsClientServerAddress -InterfaceIndex $($element).InterfaceIndex -ServerAddresses $Server -ErrorAction silentlycontinue | Out-Null
		} 
	
	#Change host file
	$hostfile_path = "C:\Windows\System32\drivers\etc\hosts"
	$content_hostfile = Get-Content $hostfile_path
	$hostline = "$Server $Domain"
	if ($content_hostfile -match "$hostline"){
			Write-host "[+] $Domain is already in \etc\hosts"
		}
		else {
			Write-Host "[+] Writing Domainname and IP DC to $hostfile_path"
			Add-Content -Path $hostfile_path -Value "`r`n$hostline"
		}
	}     
	else { 
		Write-Host -ForegroundColor Red "[-] Not running as administrator, please manually set hostfile for the domainname and DNS to the DC"
		$confirmation = Read-Host "Did you set the entry in hostfile and changed DN? y/n"
		if ($confirmation -eq 'n') {
		exit
		}
	}
Write-Host " "

# Create secure credential string
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential($User, $SecurePassword) 

#Import Powerview and Bloodhound
Import-Module -Force -Name $powerview_path -WarningAction silentlycontinue
Import-Module -Force -Name $bloodhound_path -WarningAction silentlycontinue
Import-Module -Force -Name $gpregisterpolicy_path -WarningAction silentlycontinue

#Create a folder with the current date to save data
$date = (get-date).ToString('yyyy-MM-dd')
$directory_path = "$env:USERPROFILE\desktop\$domain-$date"
$findings_path = "$directory_path\findings" 
$data_path = "$directory_path\data" 
$checks_path = "$directory_path\checks"
New-Item -ItemType Directory -Path "$directory_path" -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path "$findings_path" -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path "$data_path" -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path "$checks_path" -ErrorAction SilentlyContinue | Out-Null

#Write explanation output
Write-Host "---------- DATA EXPLAINED ----------"
Write-Host "- All data is written to $directory_path\"
Write-Host "- In this folder are three subfolders"
Write-Host "- files in \findings\ are findings that should be reported"
Write-Host "- files in \checks\ needs to be checked"
Write-Host "- files in \data\ is raw data"
Write-Host " "

Write-Host "---------- COLORS EXPLAINED ----------"
Write-Host "White is informational text"
Write-Host -ForegroundColor DarkGreen "Green means check has passed"
Write-Host -ForegroundColor Yellow "Yellow means manually check the data"
Write-Host -ForegroundColor DarkRed "Dark Red means finding"
Write-Host " "

#Gather data
$data_users = "$data_path\data_users.csv"
$data_groups = "$data_path\data_groups.csv"
$data_computers = "$data_path\data_computers.csv"
$data_gpo = "$data_path\data_gpo.csv"
$data_ou = "$data_path\data_ou.csv"
$data_domaincontrollers = "$data_path\data_dcs.csv"

Write-Host "---------- GATHERING DATA ----------"
Write-Host "[+] Gathering data of all Users"
Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Select-Object samaccountname, description, mail, serviceprincipalname, msds-allowedtodelegateto, useraccountcontrol, lastlogon, pwdlastset | Export-Csv $data_users
Write-Host "[+] Gathering data of all Groups"
Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds | Export-Csv $data_groups
Write-Host "[+] Gathering data of all Computerobjects"
Get-DomainComputer -Domain $Domain -Server $Server -Credential $Creds | Export-Csv $data_computers
Write-Host "[+] Gathering data of all GPO's"
Get-DomainGPO -Domain $Domain -Server $Server -Credential $Creds | Export-Csv $data_gpo
Write-Host "[+] Gathering data of all OU's"
Get-DomainOU -Domain $Domain -Server $Server -Credential $Creds | Export-Csv $data_ou
Write-Host "[+] Gathering data of all domain controllers"
Get-DomainController -Domain $Domain -Server $Server -Credential $Creds | Export-Csv $data_domaincontrollers
Write-Host "[+] Gathering all data with Bloodhound"
Invoke-BloodHound -CollectionMethod all -Domain $Domain -DomainController $Server -LdapUsername $User -LdapPassword $Password -OutputDirectory $findings_path 
Write-Host "[+] Gathering Session data with Bloodhound"
Invoke-BloodHound -CollectionMethod session -Domain $Domain -DomainController $Server -LdapUsername $User -LdapPassword $Password -OutputDirectory $findings_path 
Write-Host "[+] Gathering acl data with Bloodhound"
Invoke-BloodHound -CollectionMethod acl -Domain $Domain -DomainController $Server -LdapUsername $User -LdapPassword $Password -OutputDirectory $findings_path 
Write-Host -ForegroundColor Yellow "[+] Please inject the data in bloodhoud. Data saved in $findings_path"
Write-Host " "

#Get the amount of users, groups, computers etc
$usercount = Import-Csv $data_users | Measure-Object | Select-Object -expand Count
$groupcount = Import-Csv $data_groups | Measure-Object | Select-Object -expand Count
$computercount = Import-Csv $data_computers | Measure-Object | Select-Object -expand Count
$oucount = Import-Csv $data_ou | Measure-Object | Select-Object -expand Count
$gpocount = Import-Csv $data_gpo | Measure-Object | Select-Object -expand Count

Write-Host "---------- DOMAIN INFORMATION ----------"
Write-Host "In the domain $Domain there are:" 
Write-Host "- $usercount users"
Write-Host "- $groupcount groups"
Write-Host "- $computercount computers"
Write-Host "- $oucount OU's"
Write-Host "- $gpocount GPO's"
Write-Host " "

# User enumeration
Write-Host "---------- BASIC ENUMERATION ----------"
Write-Host "[+] Saving a list of all users to $data_path\list_users.txt"
Import-Csv $data_users | Select-Object -ExpandProperty samaccountname | Sort-Object -Property samaccountname | Out-File $data_path\list_users.txt
Write-Host "[+] Saving a list of all enabled users to $data_path\list_users_enabled.txt"
Import-Csv $data_users | Where-Object -Property useraccountcontrol -NotMatch "ACCOUNTDISABLE" | Select-Object -ExpandProperty samaccountname | Sort-Object -Property samaccountname | Out-File $data_path\list_users_enabled.txt

$file = "$data_path\list_admins.txt"
Write-Host "[+] Saving a list of all Administrators to $file"
$data = Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Domain Admins" -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Select-Object samaccountname | Format-Table -Autosize 
$data += Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Enterprise Admins" -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Select-Object samaccountname | Format-Table -Autosize 
$data += Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Administrators"  -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Select-Object samaccountname | Format-Table -Autosize 
$data | Out-File $file
$data = Get-Content $file
$data = $data | Sort-Object -Unique 
$data = $data -replace 'samaccountname', '' -replace '--------------', '' #remove strings
$data = $data.Trim() | ? {$_.trim() -ne "" } #Remove spaces and white lines
$data = $data | Sort-Object -Unique
$data | Out-File $file

Write-Host "[+] Saving a list of all groups to $data_path\list_groups.txt"
Import-Csv $data_groups | Select-Object samaccountname | Sort-Object -Property samaccountname | Out-File $data_path\list_groups.txt

Write-Host "[+] Saving a list of all computerobjects to $data_path\list_computers.txt"
Import-Csv $data_computers | Select-Object samaccountname | Sort-Object -Property samaccountname | Out-File $data_path\list_computers.txt
Write-Host " "

# All the checks
Write-Host "---------- EXECUTING CHECKS ----------"

Write-Host "---Executing SQL checks in another window because runas is required---"
Write-Host -ForegroundColor Yellow "[+] Pleace manually supply the Password $Password"
runas /noprofile /netonly /user:$Domain\$User "powershell.exe -Exec bypass -NoExit $sqlchecks_path -Domain $Domain -Server $Server -User $User -Password $Password"

#Check if AzureAD connect is in use
Write-Host "---Checking if AzureAD connect is in use---"
$data = Import-Csv $data_users | Where-Object {$_.samaccountname -match "MSOL_" -or $_.samaccountname -match "AAD_"} | select samaccountname, description | ft -wrap
$file = "$data_path\azuread_installedon.txt"
if ($data -eq $null){ 	
		Write-Host "[+] AzureAD connect is not installed"
    }
    else {
		Write-Host -ForegroundColor Yellow "[+] AzureAD connect is installed"
		Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

Write-Host "---Checking if Azure SSO is in use---"
$data = Import-Csv $data_computers | Where-Object {$_.samaccountname -match "AZUREADSSOACC"} | select samaccountname
if ($data -eq $null){ 	
		Write-Host "[+] Azure SSO is not configured"
    }
    else {
		Write-Host -ForegroundColor Yellow "[+] Azure SSO is configured"
    }
Write-Host " "

Write-Host "---Checking password policy---"
$data = Get-DomainPolicyData -Domain $Domain -Server $Server -Credential $Creds
$file = "$findings_path\passwordpolicy.txt"

# CHECK IF ClearTextPassword=0
if ($data.systemaccess.ClearTextPassword -as [int] -eq 0){ 
		Write-Host -ForegroundColor DarkGreen "[+] Passwordpolicy contains ClearTextPassword=0. Domain controller does not save passwords in cleartext"
    }
    ElseIf ($data.systemaccess.ClearTextPassword -as [int] -eq 1) {
        Write-Host -ForegroundColor Red "[-] Passwordpolicy contains ClearTextPassword=1. Domain Controller saves passwords in cleartext"
		$file = "$findings_path\passwordpolicy_cleartext.txt"
		Write-Host "writing to $file"
		$data.systemaccess | Out-File "$findings_path\passwordpolicy_ClearTextPassword.txt"
    }
	Else {
		Write-Host -ForegroundColor Yellow "[+] Could not determine cleartextpassword value, please manually check passwordpolicy"
	}

#Check minimun password length
if ($data.systemaccess.MinimumPasswordLength -as [int] -ge "15"){
		Write-Host -ForegroundColor DarkGreen "[+] Password length requirement is higher or equal to 15"
    }
    Else {
        Write-Host -ForegroundColor Red "[-] Password length requirement is lower then 15"
    }

#Check Password complexity
if ($data.systemaccess.MinimumPasswordLength -as [int] -eq "1"){
		Write-Host -ForegroundColor DarkGreen "[+] PasswordComplexity is equal to 1 (Enabled)"
    }
    Else {
        Write-Host -ForegroundColor Red "[-] PasswordComplexity is 0 (Disabled)!"
    }

#Checks for account lockout
if ($data.systemaccess.LockoutBadCount -as [int] -gt "6"){
		Write-Host -ForegroundColor Red "[-] LockOutBadCount is higher or equal to 6"
    }
    ElseIf ($data.systemaccess.LockoutBadCount -as [int] -eq 0) {
		Write-Host -ForegroundColor Red "[-] LockOutBadCount is 0, accounts wont be locked!"
	}
	Else {
        Write-Host -ForegroundColor DarkGreen "[+] LockOutBadCount is lower then 5"
    }

if ($data.systemaccess.ResetLockoutCount -as [int] -ge "30"){
		Write-Host -ForegroundColor DarkGreen "[+] ResetLockoutCount is higher or equal to 30"
    }
	Else {
        Write-Host -ForegroundColor Red "[-] ResetLockoutCount is lower then 30"
    }

if ($data.systemaccess.LockoutDuration -as [int] -ge "30"){
		Write-Host -ForegroundColor DarkGreen "[+] LockoutDuration is higher or equal to 30"
    }
	Else {
        Write-Host -ForegroundColor Red "[-] LockoutDuration is lower then 30"
    }
Write-Host "Writing password policy to $file"
$data.systemaccess | Out-File $file
Write-Host " "

# Checking LAPS existence + configuration
# Check if there is a GPO with laps in its name
Write-Host "---Checking if there is a GPO with LAPS---"
$data = Get-DomainGPO -Domain $Domain -Server $Server -Credential $Creds -Identity *LAPS* 
$file = "$data_path\laps_gpo.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor Red "[+] There is no GPO with LAPS in their name"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor DarkGreen "[+] There are $count GPO's with LAPS in their name"
        Write-Host "Writing to $file"
		$data | Out-File $file
		Write-Host " "
		$lapsgpo = 1
		
		# Check to which OU's the GPO's are applied to
		Write-Host "---Checking to which OU's the GPO's are applied to---"
        ForEach ($distinguishedname in $data.distinguishedname){
            $data2 = Get-DomainOU -Domain $Domain -Server $Server -Credential $Creds -GPLink $distinguishedname  | select name, distinguishedname
			if ($data2 -eq $null){ 
					Write-Host -ForegroundColor Red "[-] The GPO isn't linked to any OU"
					Write-Host -ForegroundColor Yellow "[-] Please manually check out"
			    }
			    else {
			        $count = $data2 | Measure-Object | Select-Object -expand Count
					Write-Host -ForegroundColor DarkGreen "[+] The GPO is linked to $count OU's"
					Write-Host -ForegroundColor Yellow "[-] Please manually check which OU's etc."
					$file = "$findings_path\laps_gpo_ou.txt"
			        Write-Host "Writing to $file"
					$data2 | Out-File -Append $file
			    }
        }
        Write-Host " "
		
		# Check the LAPS policy
		Write-Host "---Checking the LAPS policy for each GPO---"
		
		# Mount drive
		$hostname = (Get-Domain -Domain $Domain -Credential $Creds).name
		New-PSDrive -Name LAPS -PSProvider FileSystem -Root \\$hostname\SYSVOL -Credential $Creds | out-null
		
        ForEach ($entry in $data){
			$GPO = $entry.displayname
			$gpcfilesyspath = $entry.gpcfilesyspath
            $data2 = Parse-PolFile "$gpcfilesyspath\Machine\Registry.pol" | select ValueName, ValueData
			if ($data2 -eq $null){ 
					Write-Host -ForegroundColor Red "[-] The policy could not be found!"
			    }
			    else {
					Write-Host -ForegroundColor Yellow "[-] Found laps password policy for GPO"
					$file = "$findings_path\laps_policy.txt"
			        Write-Host "Writing to $file"
					echo "$GPO" >> $file
					$data2 | Out-File -Append $file
					echo "- Checking $GPO -"
					# Check AdminAccountName
					if (($data2 | Where-Object -Property ValueName -Match AdminAccountName | Select-Object ValueData).ValueData -eq $null){
						Write-Host -ForegroundColor Yellow "[-] The LAPS local admin user is the default administrator account"
					}
					Else {
						Write-Host -ForegroundColor DarkGreen "[+] The LAPS local admin user is not the default administrator account"
					}
					
					# Check PasswordComplexity
					if (($data2 | Where-Object -Property ValueName -Match PasswordComplexity | Select-Object ValueData).ValueData -eq "4"){
						Write-Host -ForegroundColor DarkGreen "[+] The password complexity is 4"
					}
					Else {
						Write-Host -ForegroundColor Red "[-] The password complexity is less then 4"
					}
					
					# Check PasswordLength
					if (($data2 | Where-Object -Property ValueName -Match PasswordLength | Select-Object ValueData).ValueData -eq "14"){
						Write-Host -ForegroundColor Yellow "[+] The password length is the default 14"
					}
					Elseif (($data2 | Where-Object -Property ValueName -Match PasswordLength | Select-Object ValueData).ValueData -lt "14") {
						Write-Host -ForegroundColor Red "[-] The password length is less then 14"
					}
					Elseif (($data2 | Where-Object -Property ValueName -Match PasswordLength | Select-Object ValueData).ValueData -gt "14") {
						Write-Host -ForegroundColor DarkGreen "[+] The password length is longer then 14"
					}
					
					# Check PasswordAgeDays
					if (($data2 | Where-Object -Property ValueName -Match PasswordAgeDays | Select-Object ValueData).ValueData -eq "30"){
						Write-Host -ForegroundColor Yellow "[+] The password age days is the default 30"
					}
					Elseif (($data2 | Where-Object -Property ValueName -Match PasswordAgeDays | Select-Object ValueData).ValueData -lt "30") {
						Write-Host -ForegroundColor DarkGreen "[+] The password age days is less then 30"
					}
					Elseif (($data2 | Where-Object -Property ValueName -Match PasswordAgeDays | Select-Object ValueData).ValueData -gt "30") {
						Write-Host -ForegroundColor Red "[-] The password age days is longer then 30"
					}
					
					# Check PwdExpirationProtectionEnabled
					if (($data2 | Where-Object -Property ValueName -Match PwdExpirationProtectionEnabled | Select-Object ValueData).ValueData -eq "1"){
						Write-Host -ForegroundColor DarkGreen "[+] The PwdExpirationProtectionEnabled is enabled"
					}
					Else {
						Write-Host -ForegroundColor Red "[-] The PwdExpirationProtectionEnabled is disabled or not configured (which means disabled)"
					}
					
					# Check AdmPwdEnabled
					if (($data2 | Where-Object -Property ValueName -Match AdmPwdEnabled | Select-Object ValueData).ValueData -eq "1"){
						Write-Host -ForegroundColor DarkGreen "[+] The LAPS policy is enabled"
					}
					Else {
						Write-Host -ForegroundColor Red "[-] The LAPS policy is disabled"
					}
					
			    }
        }
		Write-Host " "
	}

# Check if there are systems where LAPS is enabled on
Write-Host "---Checking if LAPS is enabled on any computerobject---"
$data = Get-DomainComputer -Domain $Domain -Server $Server -Credential $Creds | Where-Object -Property ms-Mcs-AdmPwdExpirationTime | Select-Object samaccountname
$file = "$data_path\laps_computers_enabled.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor Red "[-] There are no systems where LAPS is enabled"
		$file = "$findings_path\laps_notenabled.txt"
		Write-Host "Writing to $file"
		echo "LAPS NOT ENABLED ON ANY COMPUTER" >> $file
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor DarkGreen "[+] There are $count systems where LAPS is enabled"
        	Write-Host "Writing to $file"
		$data | Out-File $file
		$lapsgpo = 1
		Write-Host " "
		
		# Check if there are systems where LAPS isn't enabled on
		Write-Host "---Checking Windows computerobjects where LAPS isn't enabled---"
		$data = Get-DomainComputer -Domain $Domain -Server $Server -Credential $Creds | Where-Object {$_."ms-Mcs-AdmPwdExpirationTime" -Like $null -and $_.Operatingsystem -match "Windows" } | Select-Object samaccountname, lastlogon, whenchanged | Sort-Object whenchanged -Descending
		$file = "$data_path\laps_computers_disabled.txt"
		if ($data -eq $null){ 
			Write-Host -ForegroundColor DarkGreen "[+] There are no Windows systems where LAPS isn't enabled"
		}
		else {
			$count = $data | Measure-Object | Select-Object -expand Count
			Write-Host -ForegroundColor Red "[-] There are $count Windows systems where LAPS isn't enabled"
			Write-Host "Writing to $file"
			$data | Out-File $file
		}
		Write-Host " "
    }
Write-Host " "

# If there is LAPS found in GPO or Computers with LAPS
if ($lapsgpo -eq 1){ 
		# Check if current user can read LAPS passwords
		Write-Host "---Checking if current user can read LAPS passwords---"
        $data = Get-DomainComputer -Domain $Domain -Server $Server -Credential $Creds | Where-Object -Property ms-mcs-admpwd | Select-Object samaccountname, ms-mcs-admpwd
		if ($data -eq $null){ 
				Write-Host -ForegroundColor DarkGreen "[-] The current user couldn't read any LAPS passwords!"
			}
			else {
				Write-Host -ForegroundColor Red "[-] The current user could read LAPS passwords"
				$file = "$findings_path\laps_passwords.txt"
				Write-Host "Writing to $file"
				$data | Out-File $file
			}
    }
Write-Host " "

# Check if the amount of admins is more then 5% of all users
Write-Host "---Checking if amount of admins is more then 5% of all users---"
$data = Get-Content $data_path\list_admins.txt | sort-object -Unique
$admincount = $data | Measure-object | Select-Object -expand Count
$file = "$findings_path\alot_of_administrators.txt"
$percentage_admins = ($admincount / $usercount ) * 100
$thresholdpercentage = 5
if ($percentage_admins -lt $thresholdpercentage){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are only $admincount administrators, which is $percentage_admins %"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $admincount administrators, which is $percentage_admins %"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Usernames with description, possible passwords
Write-Host "---Checking description field for passwords---"
$data = Import-Csv $data_users | Where-Object -Property description | Select-Object samaccountname, description | Sort-Object description -Descending
$file = "$checks_path\description_users.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There where no Domain users with a description"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Yellow "[-] There are $count Domains users that have a description, please manually check for passwords!"
        Write-Host "Writing to $file"
        $data | Out-File $file
    }
Write-Host " "
	
# Groups with description, possible interesting information
Write-Host "---Checking groups description field for interesting information---"
$data = Import-Csv $data_groups | Where-Object -Property description | Select-Object samaccountname, description  | Sort-Object description -Descending 
$file = "$checks_path\description_groups.txt"
if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no groups with a description"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Yellow "[-] There are $count groups that have a description, please manually check for passwords!"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Computers with description, possible interesting information
Write-Host "---Checking computerobjects description field for interesting information---"
$data = Import-Csv $data_computers | Where-Object description | Select-Object samaccountname, description | Sort-Object description -Descending 
$file = "$checks_path\description_computers.txt"
if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no computerobjects with a description"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Yellow "[-] There are $count computerobjects that have a description, please manually check for passwords!"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check users with SPN set (kerberoasting)
Write-Host "---Checking kerberoastable users---"
$data = Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds -SPN | Where-Object -Property samaccountname -NotMatch krbtgt | Select-Object samaccountname, serviceprincipalname | Sort-Object -Property samaccountname
$file = "$findings_path\users_serviceprincipalname.txt"
$file_hashes = "$findings_path\users_kerberoast_hashes.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no kerberoastable users"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count kerberoastable users"
        Write-Host "Writing to $file"
		$data | Out-File $file
		Write-Host "[+] Requesting sevice tickets"
		$impacket_creds = $Domain + '/' + $User + ':' + $Password
		python $impacket_path\examples\GetUserSPNs.py -request -dc-ip $Server $impacket_creds -save -outputfile $file_hashes | Out-Null
		$hashes_count = cat $file_hashes | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Yellow "[+] Requested $hashes_count hashes, please crack with hashcat"
		Write-Host "Writing to $file_hashes"
    }
Write-Host " "

# Check if Administrator accounts has SPN set (kerberoasting)
Write-Host "---Checking kerberoastable administrators---"
$file = "$findings_path\administrators_serviceprincipalname.txt"
$data = Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Domain Admins" -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds -SPN | Select-Object samaccountname, serviceprincipalname | Format-Table -Autosize 
$data += Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Enterprise Admins" -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds -SPN | Select-Object samaccountname, serviceprincipalname | Format-Table -Autosize 

if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no kerberoastable administrators"
    }
    else {
		$data | Out-File $file
		$data = Get-Content $file
		$data = $data | Sort-Object -Unique 
		$data = $data -replace 'samaccountname', '' -replace '--------------', '' #remove strings
		$data = $data.Trim() | ? {$_.trim() -ne "" } #Remove spaces and white lines
		$count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count kerberoastable administrators"
        Write-Host "Writing to $file"
		$data | Out-File $file
		Write-Host -ForegroundColor Red "[+] Service tickets already requested at previous check, please crack with hashcat"
    }
Write-Host " "

# Check for constrained delegation users
Write-Host "---Checking constrained delegation users---"
$data = Get-DomainUser -TrustedToAuth -Domain $Domain -Server $Server -Credential $Creds | Select-Object samaccountname, msds-allowedtodelegateto | Sort-Object -Property samaccountname
$file = "$findings_path\users_constrained_delegation.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users with constrained delegation"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
       Write-Host -ForegroundColor Red "[-] There are $count users that have constrained delegation enabled"
       Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check for constrained delegation computerobjects
Write-Host "---Checking constrained delegation computerobjects---"	
$data = Get-DomainComputer -TrustedToAuth -Domain $Domain -Server $Server -Credential $Creds | Select-Object samaccountname, msds-allowedtodelegateto | Sort-Object -Property samaccountname
$file = "$findings_path\computers_constrained_delegation.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no computerobjects with constrained delegation"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count computerobjects that have constrained delegation enabled"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check for unconstrained delegation
Write-Host "---Checking unconstrained delegation computerobjects, excluding domain-controllers---"	
$data = Get-DomainComputer -Unconstrained -Domain $Domain -Server $Server -Credential $Creds | Where-Object -Property useraccountcontrol -NotMatch "SERVER_TRUST_ACCOUNT" | Select-Object samaccountname | Sort-Object -Property samaccountname
$file = "$findings_path\computers_unconstrained_delegation.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no computerobjects with unconstrained delegation"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count computerobjects that have unconstrained delegation enabled"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check PASSWD_NOTREQD users
Write-Host "---Checking if there are users with the PASSWD_NOTREQD attribute---"	
$data = Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {$_.useraccountcontrol -Match "PASSWD_NOTREQD" -and $_.useraccountcontrol -notmatch "ACCOUNTDISABLE"} | Select-Object samaccountname | Sort-Object -Property samaccountname
$file = "$findings_path\users_passwdnotreqd.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users with the attribute PASSWD_NOTREQD"
    }
else {
	$count = $data | Measure-Object | Select-Object -expand Count
	Write-Host -ForegroundColor Red "[-] There are $count users with the attribute PASSWD_NOTREQD"
	Write-Host "Writing to $file"
	$data | Out-File $file	
	Write-Host " "
	
	Write-Host "---Checking for users with empty password---"	
	ForEach ($user in $data.samaccountname){
		$samaccountname = $user
		$Credentials = New-Object System.Management.Automation.PSCredential("$samaccountname",(New-Object System.Security.SecureString))
		$data2 = Get-Domain -Domain $Domain -Credential $Credentials
		if ($data2 -eq $null){ 
			Write-Host -ForegroundColor DarkGreen "[+] The password for user $samaccountname isn't empty"
		}
		else {
			Write-Host -ForegroundColor Red "[-] The password for user $samaccountname is empty"
		}
	}
}
Write-Host " "
	
# Check DONT_EXPIRE_PASSWORD users
Write-Host "---Checking if there are users with the DONT_EXPIRE_PASSWORD attribute---"	
$data = Import-Csv $data_users | Where-Object -Property useraccountcontrol -Match "DONT_EXPIRE_PASSWORD" | Select-Object samaccountname | Sort-Object -Property samaccountname
$file = "$findings_path\users_dontexpirepassword.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users with the attribute DONT_EXPIRE_PASSWORD"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count users with the attribute DONT_EXPIRE_PASSWORD"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "
	
# Check DONT_REQ_PREAUTH users
Write-Host "---Checking if there are users with the DONT_REQ_PREAUTH attribute---"	
$data = Import-Csv $data_users | Where-Object -Property useraccountcontrol -Match "DONT_REQ_PREAUTH" | Select-Object samaccountname | Sort-Object -Property samaccountname
$file = "$findings_path\users_dontrequirepreath.txt"
$file_hashes = "$findings_path\users_aspreproast_hashes.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users with the attribute DONT_REQ_PREAUTH"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count users with the attribute DONT_REQ_PREAUTH"
        Write-Host "Writing to $file"
		$data | Out-File $file
		python $impacket_path\examples\GetNPUsers.py -request -dc-ip $Server $impacket_creds -outputfile $file_hashes | Out-Null
		$hashes_count = cat $file_hashes | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Yellow "[+] Requested $hashes_count hashes, please crack with hashcat"
		Write-Host "Writing to $file_hashes"
    }
Write-Host " "

# Check if there are users with reversible encryption
Write-Host "---Checking if there are users with the reversible encryption---"	
$data = Import-Csv $data_users | Where-Object -Property useraccountcontrol -Match "ENCRYPTED_TEXT_PWD_ALLOWED" | Select-Object samaccountname | Sort-Object -Property samaccountname
$file = "$findings_path\users_reversibleencryption.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users with reversible encryption"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count users with reversible encryption"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check if there are users with DES encryption
Write-Host "---Checking if there are users with DES encryption---"	
$data = Import-Csv $data_users | Where-Object -Property useraccountcontrol -Match "USE_DES_KEY_ONLY" | Select-Object samaccountname | Sort-Object -Property samaccountname
$file = "$findings_path\users_reversibleencryption.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users with DES encryption"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count users with DES encryption"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "
	
# Check for Domain admins with old password
Write-Host "---Checking if administrator accounts - that aren't disabled - have a password older then 365 days---"
$file = "$findings_path\administrators_oldpassword.txt"
$data = Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Domain Admins" -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {$_.pwdlastset -lt (Get-Date).AddDays(-365) -and $_.useraccountcontrol -notmatch "ACCOUNTDISABLE"} | Select-Object samaccountname, pwdlastset | Format-Table -Autosize | Out-File $file
$data += Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds "Enterprise Admins" -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {$_.pwdlastset -lt (Get-Date).AddDays(-365) -and $_.useraccountcontrol -notmatch "ACCOUNTDISABLE"} | Select-Object samaccountname, pwdlastset | Format-Table -Autosize | Out-File -Append $file

if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There where no enabled administrators with a password older then 365 days"
    }
    else {
        $data | Out-File $file
		$data = Get-Content $file
		$data = $data | Sort-Object -Unique 
		$data = $data -replace 'samaccountname', '' -replace '--------------', '' #remove strings
		$data = $data.Trim() | ? {$_.trim() -ne "" } #Remove spaces and white lines
		$count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count enabled administrators with a password older then 365 days!"
        Write-Host "Writing to $file"
        $data | Out-File $file
    }
Write-Host " "

# Check for KRBTGT with old password
Write-Host "---Checking if KRBTGT account has a password older then 365 days---"
$data = Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds krbtgt | Where-Object {$_.pwdlastset -lt (Get-Date).AddDays(-365)} | Select-Object samaccountname, pwdlastset 
$file = "$findings_path\krbtgt_oldpassword.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] The password from the krbtgt is not older then 365 days"
    }
    else {
		 Write-Host -ForegroundColor Red "[-] The password from the krbtgt is older then 365 days"
        Write-Host "Writing to $file"
        $data | Out-File $file
    }
Write-Host " "

# Checking for EOL operating systems in the AD
Write-Host "---Checking if there are EOL operating systems in the AD---"
$data = Get-DomainComputer  -Credential $Creds -Server $Server -Domain $Domain | Where-Object {$_.operatingsystem -match 'Windows 7' -or $_.operatingsystem -match 'Windows Server 2008' -or $_.operatingsystem -match 'Windows Server 2003' -or $_.operatingsystem -match 'XP'} | Select-Object samaccountname, operatingsystem, lastlogon | Sort-Object -Property lastlogon -Descending 
$file = "$findings_path\computers_os_EOL.txt"
if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no computerobjects in the AD that are EOL"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count computerobjects in the AD that are EOL"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Checking for EOL operating systems in the AD
Write-Host "---Checking if there are end of service Windows 10 operating systems in the AD---"
$data = Get-DomainComputer  -Credential $Creds -Server $Server -Domain $Domain | Where-Object {$_.operatingsystem -match 'Windows 10'} | Where-Object {$_.operatingsystemversion -match 19041 -or $_.operatingsystemversion -match 18362 -or $_.operatingsystemversion -match 17134 -or $_.operatingsystemversion -match 16299 -or $_.operatingsystemversion -match 15063 -or $_.operatingsystemversion -match 10586 -or $_.operatingsystemversion -match 14393 -or $_.operatingsystemversion -match 10240} | Select-Object samaccountname, operatingsystem, operatingsystemversion, lastlogon | Sort-Object -Property lastlogon -Descending 
$file = "$findings_path\computers_W10_EOL.txt"
if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no W10 computerobjects in the AD that are end of service"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count W10 computerobjects in the AD that are end of service"
        Write-Host "Writing to $file"
		$data | Out-File $file
		Write-Host "[+] Replacing Powerview versions with more readable versions"
		Write-Host "End of servic versions at https://docs.microsoft.com/en-us/windows/release-health/release-information"
		(Get-Content $file) | Foreach-Object {
		$_ 	-replace '19041', '2004' `
			-replace '18362', '1903' `
			-replace '17134', '1803' `
			-replace '16299', '1709' `
			-replace '15063', '1703' `
			-replace '10586', '1511' `
			-replace '14393', '1607' `
			-replace '10240', '1507' 
		} | Set-Content $file
    }
Write-Host " "

# Checking for inactive computerobjects that have no login or login/pwdlastset older then 365 days
#-or $_.lastlogon -Like $null
Write-Host "---Checking if there are computerobjects that have no login or login/pwdlastset older then 365 days---"
$data = Get-DomainComputer  -Credential $Creds -Server $Server -Domain $Domain | Where-Object {$_.lastlogon -lt (Get-Date).AddDays(-365) -and $_.pwdlastset -lt (Get-Date).AddDays(-365)} | select-object samaccountname, pwdlastset, lastlogon  | Sort-Object -Property lastlogon -Descending 
$file = "$findings_path\computers_inactive.txt"
if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no computerobjects in the AD that are inactive"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count computerobjects in the AD that have no login or login & pwdlastset older then 365 days"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Checking for inactive users that didn't login for the last 365 days	
Write-Host "---Checking if there are users that didn't login for 365 days---"
#-and $_.lastlogon -notlike $null 
$data = Get-DomainUser  -Credential $Creds -Server $Server -Domain $Domain | Where-Object {$_.lastlogon -lt (Get-Date).AddDays(-365) -and $_.useraccountcontrol -notmatch "ACCOUNTDISABLE" -and $_.pwdlastset -lt (Get-Date).AddDays(-365)}| select-object samaccountname, pwdlastset, lastlogon  | Sort-Object -Property lastlogon -Descending 
$file = "$findings_path\users_inactive.txt"
if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no users in the AD that are inactive"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Red "[-] There are $count users in the AD that have didn't login in the last 365 days"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check if all privileged users are part of the protected users group
Write-Host "---Checking if members of privileged groups are part of the protected users group---"
$data = Get-DomainGroup -AdminCount -Domain $Domain -Server $Server -Credential $Creds | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {!($_.memberof -match "Protected Users")} | Select-Object samaccountname | Sort-object samaccountname -Unique
$file = "$findings_path\administrators_notin_protectedusersgroup.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no administrators that aren't in the protected users group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count privileged users not part of the protected users group"
        Write-Host "Writing to $file"
		$data | Out-File $file
	}
Write-Host " "

# Check if all privileged users have the flag "this account is sensitive and cannot be delegated"
Write-Host "---Checking if members of privileged groups have the flag 'this account is sensitive and cannot be delegated'---"
$data = Get-DomainGroup -AdminCount -Domain $Domain -Server $Server -Credential $Creds | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds -Allowdelegation | Where-Object {!($_.memberof -match "Protected Users")} | Select-Object samaccountname | Sort-object samaccountname -Unique
$file = "$findings_path\administrators_delegation_flag.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no high privileged users without the flag 'this account is sensitive and cannot be delegated' that aren't in the Protected Users group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count high privileged users without the flag 'this account is sensitive and cannot be delegated' that aren't in the Protected Users group"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check if there are members part of some privileged groups
Write-Host "---Checking if there are members in high privileged groups---"
$data = Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds "Account Operators" | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {!($_.memberof -match "Domain Admins" -or $_.memberof -match "Enterprise Admins")} | Select-Object samaccountname
$file = "$checks_path\users_highprivilegegroups.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users in the Account Operators group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count users in the Account Operators group that aren't Domain- or Enterprise Administrators"
        Write-Host "Writing to $file"
		"Account Operators" | Out-File $file -Append
		$data | Out-File $file -Append
	}

$data = Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds "Backup Operators" | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {!($_.memberof -match "Domain Admins" -or $_.memberof -match "Enterprise Admins")} | Select-Object samaccountname
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users in the Backup Operators group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count users in the Backup Operators group that aren't Domain- or Enterprise Administrators"
        Write-Host "Writing to $file"
		"Backup Operators" | Out-File $file -Append
		$data | Out-File $file -Append
	}

$data = Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds "Print Operators" | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {!($_.memberof -match "Domain Admins" -or $_.memberof -match "Enterprise Admins")} | Select-Object samaccountname
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users in the Print Operators group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count users in the Print Operators group that aren't Domain- or Enterprise Administrators"
        Write-Host "Writing to $file"
		"Print Operators" | Out-File $file -Append
		$data | Out-File $file -Append
	}
	
$data = Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds "DNS Admins" | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {!($_.memberof -match "Domain Admins" -or $_.memberof -match "Enterprise Admins")} | Select-Object samaccountname
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users in the DNS Admins group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count users in the DNS Admins group that aren't Domain- or Enterprise Administrators"
        Write-Host "Writing to $file"
		"Print Operators" | Out-File $file -Append
		$data | Out-File $file -Append
	}

$data = Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds "Schema Admins" | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse | Get-DomainUser -Domain $Domain -Server $Server -Credential $Creds | Where-Object {!($_.memberof -match "Domain Admins" -or $_.memberof -match "Enterprise Admins")} | Select-Object samaccountname
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no users in the Schema Admins group"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count users in the Schema Admins group that aren't Domain- or Enterprise Administrators"
        Write-Host "Writing to $file"
		"Backup Operators" | Out-File $file -Append
		$data | Out-File $file -Append
	}
Write-Host " "

# Check if there is a computer part of a high priveleged group
Write-Host "---Checking if there is a computerobject part of a high privileged group---"
$data = Get-DomainGroup -Domain $Domain -Server $Server -Credential $Creds -AdminCount | Get-DomainGroupMember -Domain $Domain -Server $Server -Credential $Creds -Recurse -ErrorAction Silentlycontinue -WarningAction Silentlycontinue | Where-Object -Property MemberObjectClass -Match computer | Select-Object MemberName
$file = "$findings_path\computers_part_of_highprivilegedgroups.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no computerobjects part of a high privileged groups"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count computerobjects part of a high privileged groups"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "
	
# Check who can add computerobjects to the domain
Write-Host "---Checking who can add computerobjects to the domain---"
$data = (Get-DomainPolicy -Policy DC -Domain $Domain -Server $Server -Credential $Creds).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject -Domain $Domain -Server $Server -Credential $Creds | Select-Object name
$file = "$findings_path\authenticated_users_can_join_domain.txt"
if ($data.name -eq "S-1-5-11"){ 
		$data2 = Get-DomainObject -Credential $creds -Domain $Domain -Server $Server | Where-Object ms-ds-machineaccountquota
		$count = $data2."ms-ds-machineaccountquota"
		Write-Host -ForegroundColor Red "[-] The authenticated users group(S-1-5-11) can add $count computerobjects to the domain"
        Write-Host "Writing to $file"
		$data | Out-File $file
		$file = "$checks_path\can_join_domain_amount.txt"
		Write-Host "Writing amount of computerobjects that can be joined to $file"
		$data2 | Out-File $file
    }
    else {
		$file = "$checks_path\can_join_domain.txt"
		Write-Host -ForegroundColor DarkGreen "[+] The authenticated users group can't add computerobjects to the domain"
		Write-Host -ForegroundColor Yellow "[-] Please manually check which users or groups can add computerobjects to the domain"
		Write-Host "Writing to $file"
		$data | Out-File $file
		$data = Get-DomainObject -Credential $creds -Domain $Domain -Server $Server | Where-Object ms-ds-machineaccountquota | select-object ms-ds-machineaccountquota
		$file = "$checks_path\can_join_domain_amount.txt"
		Write-Host "Writing amount of computerobjects that can be joined to $file"
		$data | Out-File $file
    }
Write-Host " "

# Check if there are users with admincount=1 which have a session
Write-Host "---Gathering all session information for users with admincount=1---"
Invoke-UserHunter -Domain $Domain -Server $Server -Credential $Creds -Threads 50 -ServerTimeLimit 60  -ErrorAction silentlycontinue -AdminCount | Export-Csv $data_path\admin_sessions.csv
$data = import-csv $data_path\admin_sessions.csv
$file = "$findings_path\admins_sessions.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] There are no sessions found for users with admincount=1, please check bloodhound data manually"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count sessions found for users with admincount=1"
        Write-Host "Writing to $file"
		$data | select-object UserName, ComputerName | Out-File $file
		Write-Host "[+] Please manually check for sessions that aren't to domain controllers!"
    }
Write-Host " "
	
# Check if the current user is localadmin to a machine
Write-Host "---Checking if the current user is local admin to any machines---"
$data = Find-LocalAdminAccess -DomainController $Domain -Credential $Creds -ServerTimeLimit 60 -Threads 50 -ErrorAction silentlycontinue -WarningAction silentlycontinue
$file = "$findings_path\user_localadmin.txt"
if ($data -eq $null){ 
		Write-Host -ForegroundColor DarkGreen "[+] The current user is not local admin to any machine"
    }
    else {
        $count = $data | Measure-Object | Select-Object -expand Count
		Write-Host -ForegroundColor Red "[-] There are $count machines the current user is local admin too!"
        Write-Host "Writing to $file"
		$data | Out-File $file
    }
Write-Host " "

# Look through sysvol on each domain for the string password in all *xml files
Write-Host "---Checking if there are passwords in the SYSVOL share---"
Write-Host "This might take a while"
$file = "$checks_path\sysvol_passwords.txt"
$data = Get-DomainController -Domain $Domain -Server $Server -Credential $Creds
ForEach ($dc in $data){
	$name = $dc.name
	$hostname = $dc.dnshostname
	Write-Host "[+] Checking SYSVOL of $name"
	New-PSDrive -Name $dc.name -PSProvider FileSystem -Root \\$hostname\SYSVOL -Credential $Creds | out-null
	$data = Get-ChildItem -Recurse -Path \\$hostname\SYSVOL\$Domain\Policies\*.xml -ErrorAction silentlycontinue | Select-String -Pattern "password"
	if ($data -eq $null){ 
        Write-Host -ForegroundColor DarkGreen "[+] There are no passwords in the sysvol of $name"
    }
    else {
		$count = $data | Measure-Object | Select-Object -expand Count
        Write-Host -ForegroundColor Yellow "[-] There might be $count passwords in the SYSVOL of $name. Please manually check"
        Write-Host "Writing to $file"
		$data | Add-Content $file
    }
}
Write-Host " "

# Create a list of all shares the current user has access to
Write-Host "---Checking if our user has access to any shares---"
Write-Host "This might take a while"
$file = "$checks_path\shares_all.txt"
$data = Find-DomainShare -Server $Server -Credential $Creds -CheckShareAccess -Threads 40 -ServerTimeLimit 60 -ErrorAction silentlycontinue

if ($data -eq $null){ 
	Write-Host -ForegroundColor DarkGreen "[+] There are no shares"
}
else {
	ForEach ($share in $data) {
		$hostname = $share.computername
		$sharename = $share.Name
		echo \\$hostname\$sharename | Add-Content $file
	}
	$count = $data | Measure-Object | Select-Object -expand Count
	Write-Host -ForegroundColor Yellow "[-] There are $count shares. There might interesting files in the shares. Please manually check"
	Write-Host "Writing all shares to $file"
	$file_interestingshares = "$checks_path\shares_noprint-ipc.txt"
	cat $file | Select-String -Pattern "IPC\$" -NotMatch | Select-String -Pattern "print\$" -NotMatch | Add-Content $file_interestingshares
	Write-Host "Writing all shares except IPC and print to $file_interestingshares"
}
Write-Host " "

# Look for interesting files on all shares
Write-Host "---Going through all the shares to find interesting files---"
$terms = "'*admin*', '*account*', '*backup*', '*back-up*', '*beheer*', '*confidential*', '*cred*', '*geheim*', '*HackDefense*', '*login*', '*key3.db*', '*pass*', '*rdp*', '*secret*', '*vnc*', '*wachtwoord*', '*.BAK*', '*.bat*', '*.sh*', '*.ps1*', '*.db*', '*.hive*', '*.GHO*', '*.ini*', '*id_rsa*',  '*.ovpn*', '*.kdb*', '*.kdbx*', '*unattend*.xml', '*bootstrap*.ini*', '*CustomSettings*.ini*', '*.cmd', '*.vbs', '*vnc*', '*.ini', '*NTDS.*dit*'"
Write-Host "Keywords are: $terms"
Write-Host "Last check and this will take a while....."
$file = "$checks_path\shares_interestingfiles.csv"
Find-InterestingDomainShareFile -Server $Server -Credential $Creds -Threads 40 -ServerTimeLimit 60 -Terms '*admin*', '*account*', '*backup*', '*back-up*', '*beheer*', '*confidential*', '*cred*', '*geheim*', '*HackDefense*', '*login*', '*key3.db*', '*pass*', '*rdp*', '*secret*', '*vnc*', '*wachtwoord*', '*.BAK*', '*.bat*', '*.sh*', '*.ps1*', '*.db*', '*.hive*', '*.GHO*', '*.ini*', '*id_rsa*',  '*.ovpn*', '*.kdb*', '*.kdbx*', '*unattend*.xml', '*bootstrap*.ini*', '*CustomSettings*.ini*', '*.cmd', '*.vbs', '*vnc*', '*.ini', '*NTDS.*dit*' -ErrorAction silentlycontinue | Export-Csv $file
Write-Host "Writing to $file"
Write-Host -ForegroundColor Yellow "[-] There might interesting files. Please manually check the .csv"
Write-Host "Tip of the day: Import-CSV $file | where-object -Property Path -Match 'Searchterm'"
Write-Host " "
