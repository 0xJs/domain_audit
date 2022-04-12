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
$powerupsql_path = "$PSScriptRoot\import\PowerUpSQL.ps1" 

#Import Powerview
Import-Module -Force -Name $powerview_path
Import-Module -Force -Name $powerupsql_path

# Create secure credential string
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential($User, $SecurePassword) 

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

# Checking if there are MSSQL instances in the domain. Checking for SPN's
Write-Host "---Checking MSSQL instances---"
$data = Get-DomainComputer -Server $Server -Credential $Creds -Domain $Domain | Where-Object serviceprincipalname -Match MSSQL | Select-Object -ExpandProperty serviceprincipalname | Select-String MSSQL
$data = $data -replace 'MSSQLSvc/', ''
$count = $data | Measure-Object | Select-Object -expand Count
if ($count -ge 1){ 
	Write-Host "[+] Found $count MSSQL instances"

	# Checking connection to MSSQL instances
	Write-Host "[+] Checking connection to each MSSQL instance"
	$results = ForEach ($sqlserver in $data){
		Get-SQLConnectionTest -Instance $sqlserver
	}
	$count = $results | Where-Object -Property status -Like Accessible | Measure-Object | Select-Object -expand Count
	
	if ($count -ge 1){
		# If able to connect to a MSSQL server.
		$file = "$findings_path\SQLserver_user_access.txt"
	
		Write-Host -ForegroundColor Red "[-] The current user can access $count MSSQL instances"
		Write-Host "Writing to $file"
		$results | Out-File $file
		Write-Host " "
	
		# Checking if the user is sysadmin on the instance
		Write-Host "---Checking if the user is sysadmin on the accessible instances---"	
		$accessible_sql = $results | Where-Object -Property status -Like Accessible | Get-SQLServerInfo
		$data = $accessible_sql | Where-Object -Property IsSysadmin -Match Yes
		$file = "$findings_path\SQLserver_user_issysadmin.txt"
		if ($data.IsSysadmin -match "Yes"){ 
				$count = $data | Measure-Object | Select-Object -expand Count
				Write-Host -ForegroundColor Red "[-] The current user is sysadmin to $count MSSQL instances"
				Write-Host "Writing to $file"
				$data | Out-File $file
			}
			else {
				Write-Host -ForegroundColor DarkGreen "[+] The current user is not sysdmin to any SQL instances"
			}
		Write-Host " "
			
		# Audit SQL instances
		Write-Host "---Running Invoke-SQLAudit on the accessible instances---"	
		$data = $results | Where-Object -Property status -Like Accessible | Invoke-SQLAudit -ErrorAction silentlycontinue
		$file = "$findings_path\SQLserver_sqlaudit.txt"
		if ($data -eq $null){ 
				Write-Host -ForegroundColor DarkGreen "[+] Invoke-SQLAudit didn't found anything"
			}
			else {
				$count = $data | Measure-Object | Select-Object -expand Count
				Write-Host -ForegroundColor Red "[-] Invoke-SQLAudit found $count issues"
				Write-Host "Writing to $file"
				$data | Out-File $file
			}
		Write-Host " "
	
		# Check SQL Server database links
		Write-Host "---Checking database links for sysadmin security context---"	
		$data = $results | Where-Object -Property status -Like Accessible | Get-SQLServerLinkCrawl | Where-Object -Property  sysadmin -Match 1
		$file = "$findings_path\SQLserver_sysadminlinks.txt"
		if ($data -eq $null){ 
				Write-Host -ForegroundColor DarkGreen "[+] There are no links which run under the security context of a sysadmin user"
			}
			else {
				$count = $data | Measure-Object | Select-Object -expand Count
				Write-Host -ForegroundColor Red "[-] There are $count links which run under the security context of a sysadmin user"
				Write-Host "Writing to $file"
				$data | Out-File $file
			}
		Write-Host " "
	
	}
	else {
	Write-Host -ForegroundColor Green "[+] The current user can't access any MSSQL instances"	
	}
}
else {
	Write-Host -ForegroundColor DarkGreen "[+] There are no SQL instances"
}
