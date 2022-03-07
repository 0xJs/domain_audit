###########################################################
#
#  Group Policy - Registry Policy module
#
#  Copyright (c) Microsoft Corporation, 2016
#
###########################################################

data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
    InvalidHeader = File '{0}' has an invalid header.
    InvalidVersion = File '{0}' has an invalid version. It should be 1.
    InvalidFormatBracket = File '{0}' has an invalid format. A [ or ] was expected at location {1}.
    InvalidFormatSemicolon = File '{0}' has an invalid format. A ; was expected at location {1}.
    OnlyCreatingKey = Some values are null. Only the registry key is created.
    Progress = Progress: {0,8:p}
    InvalidPath = Path {0} doesn't point to an existing registry key/property.
    InternalError = Internal error while creating a registry entry for {0}
'@
}

Import-LocalizedData  LocalizedData -filename GPRegistryPolicy.Strings.psd1
Import-Module "$PSScriptRoot\GPRegistryPolicyParser.psm1" -DisableNameChecking

$script:SystemAndAdminAccounts = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators'
)

$script:WellKnownSids = @(
    'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES'
)

$script:DefaultEntries = @(
    "Software\Policies"
)

<# 
.SYNOPSIS
Applies a registry policy.

.DESCRIPTION
Applies a registry policy. The division to which the contents must be applied has to be defined
as one of the three available values: LocalMachine, CurrentUser, and Users.

.PARAMETER RegistryPolicy
Specifies the registry policy that has to be applied: Key, Value, Type, Size and Data

.PARAMETER Division
The destination registry division to which the policy has to be applied.

.PARAMETER KeyPrefix
A prefix that will be prepended to the given key.

.PARAMETER SID
The SID that defines which key in Users division is going to be used.
#>
function Apply-GPRegistryPolicy
{
    [OutputType([array])]
    param (
		[Parameter(Mandatory = $true)]
        [GPRegistryPolicy]
        $RegistryPolicy,

        [ValidateSet("LocalMachine", "CurrentUser", "Users")]
        [string]
        $Division = "LocalMachine",

        [string]
        [ValidateNotNullOrEmpty()]
        $KeyPrefix,

        [string]
        [ValidateNotNullOrEmpty()]
        $SID
    )

    switch ($Division) 
    { 
        'LocalMachine' { $Hive = [Microsoft.Win32.Registry]::LocalMachine } 
        'CurrentUser'  { $Hive = [Microsoft.Win32.Registry]::CurrentUser } 
        'Users'        { $Hive = [Microsoft.Win32.Registry]::Users } 
    }

    $targetKeyName = $RegistryPolicy.KeyName

    # if we have a prefix, prepend that to the key name
    if ($PSBoundParameters.ContainsKey('KeyPrefix'))
    {
        $targetKeyName = $KeyPrefix + '\' + $targetKeyName
    }

    # if we have a SID in Users division, prepend that to the key name
    if (($Division -ieq "Users") -and ($PSBoundParameters.ContainsKey('SID')))
    {
        $targetKeyName = $SID + '\' + $targetKeyName
    }

    try
    {
        # Create a new subkey or open an existing subkey for write access
        $key = $Hive.CreateSubKey($targetKeyName)

        # If value, type, size, or data are missing or zero, only the registry key is created.
        $keyOnly = ([System.String]::IsNullOrEmpty($RegistryPolicy.ValueName)) -or
                   ([System.String]::IsNullOrEmpty($RegistryPolicy.ValueType)) -or
                   ([System.String]::IsNullOrEmpty($RegistryPolicy.ValueLength)) -or
                   ([System.String]::IsNullOrEmpty($RegistryPolicy.ValueData))


        if ( $KeyOnly )
        {
            return
        }

        if ( $RegistryPolicy.ValueName -ieq "**DeleteValues" )
        {
            $ValueNames = ($RegistryPolicy.ValueData).Split(';')
            # TODO: Assert on type being REG_SZ
            Assert ($RegistryPolicy.ValueType -eq [RegType]::REG_SZ) "Failed"
            foreach($valueName in $ValueNames)
            {
                if (-not ([System.String]::IsNullOrEmpty($valueName)))
                {
                    try
                    {
                        $key.DeleteValue($valueName)
                    }
                    catch
                    {
                        # Do nothing
                    }
                }
            }
        }
        elseif ( ($RegistryPolicy.ValueName).StartsWith("**Del.") )
        {
            $ValueName = ($RegistryPolicy.ValueName).Substring( ($RegistryPolicy.ValueName).IndexOf('.')+1 )
            # TODO: Assert on type being REG_SZ
            # TODO: Assert on data being ' '
            $key.DeleteValue($valueName)
        }
        elseif ( $RegistryPolicy.ValueName -ieq "**DelVals." )
        {
            $ValueNames = $Key.GetValueNames()
            # TODO: Assert on type being REG_SZ
            # TODO: Assert on data being ' '
            foreach($valueName in $ValueNames)
            {
                $key.DeleteValue($valueName)
            }
        }
        elseif ( $RegistryPolicy.ValueName -ieq "**DeleteKeys" )
        {
            $SubKeys = ($RegistryPolicy.ValueData).Split(';')
            # TODO: Assert on type being REG_SZ
            foreach($subkey in $SubKeys)
            {
                if (-not ([System.String]::IsNullOrEmpty($subkey)))
                {
                    try
                    {
                        $key.DeleteSubKeyTree($subkey)
                    }
                    catch
                    {
                        # Do nothing
                    }
                }
            }
        }
        elseif ( $RegistryPolicy.ValueName -ieq "**SecureKey" )
        {
            $AccessLevel = [System.Int32] $RegistryPolicy.ValueData
            # TODO: Assert on type being REG_DWORD
            $AccessControl = $key.GetAccessControl()
            $AccessRules = $AccessControl.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])

            foreach ($Access in $AccessRules)
            {
                if ($script:SystemAndAdminAccounts.Contains($Access.IdentityReference.ToString()))
                {
                    [System.Security.AccessControl.RegistryAccessRule] $NewAccessRule = [System.Security.AccessControl.RegistryAccessRule]::new(
                        $Access.IdentityReference,
                        [System.Security.AccessControl.RegistryRights]::FullControl,
                        $Access.InheritanceFlags,
                        $Access.PropagationFlags,
                        $Access.AccessControlType
                    )
                }
                elseif ($script:WellKnownSids.Contains($access.IdentityReference.ToString()))
                {
                    $strSID = $access.IdentityReference.ToString()
                    $groupName = $strSID.Substring($strSID.IndexOf('\')+1)
                    [System.Security.AccessControl.RegistryAccessRule] $NewAccessRule = [System.Security.AccessControl.RegistryAccessRule]::new(
                        $groupName,
                        [System.Security.AccessControl.RegistryRights]::ReadKey,
                        $access.InheritanceFlags,
                        $access.PropagationFlags,
                        $access.AccessControlType
                    )
                }
                else
                {
                    [System.Security.AccessControl.RegistryAccessRule] $NewAccessRule = [System.Security.AccessControl.RegistryAccessRule]::new(
                        $access.IdentityReference,
                        [System.Security.AccessControl.RegistryRights]::ReadKey,
                        $access.InheritanceFlags,
                        $access.PropagationFlags,
                        $access.AccessControlType
                    )
                }

                $AccessControl.RemoveAccessRule($Access)
                $AccessControl.SetAccessRule($NewAccessRule)
            }
        }   
        elseif ( ($RegistryPolicy.ValueName).StartsWith("**soft.") )
        {
            $CurrentValueNames = $Key.GetValueNames()
            $ValueName = ($RegistryPolicy.ValueName).Substring( ($RegistryPolicy.ValueName).IndexOf('.')+1 )
            if ( -not ($CurrentValueNames.Contains($ValueName)) )
            {
                $type = Get-RegType -Type $RegistryPolicy.ValueType
                $key.SetValue($RegistryPolicy.ValueName, $RegistryPolicy.ValueData, $type)
            }
        }
        else
        {
            # This is not a special value. So just update the value.
            if ($RegistryPolicy.ValueType -eq [RegType]::REG_MULTI_SZ)
            {
                [string[]] $data = ($RegistryPolicy.ValueData).Split("`0",[System.StringSplitOptions]::RemoveEmptyEntries)
            }
            elseif ($RegistryPolicy.ValueType -eq [RegType]::REG_MULTI_SZ)
            {
                [byte[]] $data = [System.Text.Encoding]::Unicode.GetBytes($RegistryPolicy.ValueData)
            }
            elseif ($RegistryPolicy.ValueType -eq [RegType]::REG_BINARY)
            {
                [byte[]] $data = $RegistryPolicy.ValueData
            }
            else
            {
                $data = $RegistryPolicy.ValueData
            }
        
            $key.SetValue($RegistryPolicy.ValueName, $data, $RegistryPolicy.ValueType)
        }
    }
    finally
    {
        if ($key)
        {
            if ($PSVersionTable.PSEdition -ieq 'Core')
            {
                $key.Flush()
                $key.Dispose()
            }
            else
            {
                $key.Close()
            }
        }
    }
}

<# 
.SYNOPSIS
Reads a .pol file containing group policy registry entries and applies its contents to the machine.

.DESCRIPTION
Reads a .pol file containing group policy registry entries and applies its contents to the machine.
The division to which the contents must be applied to has to be defined using one of the three available
options for **LocalMachine**, **CurrentUser**, or **Username**.

.PARAMETER Path
Specifies the path to the .pol file to be imported.

.PARAMETER LocalMachine
A switch that sets the Local Machine as the destination registry division.

.PARAMETER CurrentUser
A switch that sets the Current User as the destination registry division.

.PARAMETER Username
A string that selects the target user in the Users registry division.

.PARAMETER KeyPrefix
A prefix that will be prepended to the given key.

.EXAMPLE
C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine

.EXAMPLE
C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -CurrentUser

.EXAMPLE
C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -Username testdomain\testuser

.EXAMPLE
C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -Username localtestuser

.EXAMPLE
C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine -KeyPrefix 'Software\TestKeys'

.OUTPUT
None.
#>
function Import-GPRegistryPolicy
{
    [CmdletBinding(DefaultParameterSetName='LocalMachine')]
    param (
		[Parameter(Mandatory = $true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

		[Parameter(ParameterSetName = 'LocalMachine')]
        [switch]
        $LocalMachine = $true,

		[Parameter(ParameterSetName = 'CurrentUser')]
        [switch]
        $CurrentUser = $false,

		[Parameter(ParameterSetName = 'Users')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username = "$($env:USERDOMAIN)\$($env:USERNAME)",

        [string]
        [ValidateNotNullOrEmpty()]
        $KeyPrefix
    )

    $Parameters = @{}

    switch ($PsCmdlet.ParameterSetName) 
    { 
        'LocalMachine' 
        { 
            $Parameters.Add('Division', 'LocalMachine')
        } 

        'CurrentUser'
        {
            $Parameters.Add('Division', 'CurrentUser')
        } 
        
        'Users'  {
            $Parameters.Add('Division', 'Users')

            # Translate the username into SID
            $objUser = New-Object System.Security.Principal.NTAccount($Username)
            $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
            $Parameters.Add('SID', $strSID.Value)
        } 
    }

    if ($PSBoundParameters.ContainsKey('KeyPrefix'))
    {
        $Parameters.Add('KeyPrefix', $KeyPrefix)
    }

    $RegistryPolicies = Parse-PolFile -Path $Path

    foreach ($rp in $RegistryPolicies)
    {
        if ($rp -ne $null)
        {
            Apply-GPRegistryPolicy -RegistryPolicy $rp @Parameters
        }
    }
}

<# 
.SYNOPSIS
Reads registry entries and write them in a .pol file.

.DESCRIPTION
Reads registry entries and write them in a .pol file. By default, the root key from which the registry
entries are read is 'Software\Policies'. However, if Entries are assinged in input, then this function
will export those instead. The division from which the contents must be read has to be defined using one
of the three available options for **LocalMachine**, **CurrentUser**, or **Username**.

.PARAMETER Path
Specifies the path to the destination .pol file.

.PARAMETER LocalMachine
A switch that sets the Local Machine as the source registry division.

.PARAMETER CurrentUser
A switch that sets the Current User as the source registry division.

.PARAMETER Username
A string that selects the target user in the Users registry division.

.PARAMTER Entries
Specifies the list of registry keys to be exported. The default value is set to 'Software\Policies'.

.PARAMETER Username
A string that selects the target user in the Users registry division.

.EXAMPLE
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine

.EXAMPLE
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -CurrentUser

.EXAMPLE
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -Username testdomain\testuser

.EXAMPLE
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -Username localtestuser

.EXAMPLE
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine -Entries @('Software\Policies\Microsoft\Windows', 'Software\Policies\Microsoft\WindowsFirewall')

.INPUTS
None. You cannot pipe objects to Import-GPRegistryPolicy.

.OUTPUT
None.
#>
function Export-GPRegistryPolicy
{
    [CmdletBinding(DefaultParameterSetName='LocalMachine')]
    param (
		[Parameter(Mandatory = $true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,
        
		[Parameter(Position=1)]
        [string[]]
        $Entries = $script:DefaultEntries,

		[Parameter(Mandatory = $true, ParameterSetName = 'LocalMachine')]
        [switch]
        $LocalMachine = $true,

		[Parameter(Mandatory = $true, ParameterSetName = 'CurrentUser')]
        [switch]
        $CurrentUser = $false,

		[Parameter(ParameterSetName = 'Users')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username = "$($env:USERDOMAIN)\$($env:USERNAME)"
    )

    switch ($PsCmdlet.ParameterSetName) 
    { 
        'LocalMachine' 
        { 
            $Division = 'LocalMachine'
        } 

        'CurrentUser'
        {
            $Division = 'CurrentUser'
        } 
        
        'Users'  {
            $Division = 'Users'

            # Translate the username into SID
            $objUser = New-Object System.Security.Principal.NTAccount($Username)
            $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
            $SID = $strSID.Value

            # Modify the entries and prepend the SID of the selected user to all of them.
            $Entries = $Entries | % { $SID+'\'+$_ }
        } 
    }

    $RegistryPolicies = Read-RegistryPolicies -Entries $Entries -Division $Division
    
    Create-GPRegistryPolicyFile -Path $Path

    Append-RegistryPolicies -RegistryPolicies $RegistryPolicies -Path $Path
}



<# 
.SYNOPSIS
Reads a .pol file containing group policy registry entries and tests its contents against current registry.

.DESCRIPTION
Reads a .pol file containing group policy registry entries and tests its contents against current registry.
The division to which the contents must be applied has to be defined using one of the three available options 
for **LocalMachine**, **CurrentUser**, or **Username**.

.PARAMETER Path
Specifies the path to the .pol file to be tested.

.PARAMETER LocalMachine
A switch that sets the Local Machine as the destination registry division.

.PARAMETER CurrentUser
A switch that sets the Current User as the destination registry division.

.PARAMETER Username
A string that selects the target user in the Users registry division.

.PARAMTER Entries
Specifies the list of registry keys to be exported. The default value is set to 'Software\Policies'.

.EXAMPLE
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine

.EXAMPLE
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -CurrentUser

.EXAMPLE
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -Username testdomain\testuser

.EXAMPLE
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -Username localtestuser

.EXAMPLE
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine -Entries @('Software\Policies\Microsoft\Windows', 'Software\Policies\Microsoft\WindowsFirewall')

.INPUTS
None. You cannot pipe objects to Test-GPRegistryPolicy.

.OUTPUT
None.
#>
function Test-GPRegistryPolicy
{
    [CmdletBinding(DefaultParameterSetName='LocalMachine')]
    param (
		[Parameter(Mandatory = $true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,
        
		[Parameter(Position=1)]
        [string[]]
        $Entries = $script:DefaultEntries,

		[Parameter(ParameterSetName = 'LocalMachine')]
        [switch]
        $LocalMachine = $true,

		[Parameter(ParameterSetName = 'CurrentUser')]
        [switch]
        $CurrentUser = $false,

		[Parameter(ParameterSetName = 'Users')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username = "$($env:USERDOMAIN)\$($env:USERNAME)"
    )

    $Parameters = @{}

    switch ($PsCmdlet.ParameterSetName) 
    { 
        'LocalMachine'  { 
            $Parameters.Add('LocalMachine', $true)
            $Hive = [Microsoft.Win32.Registry]::LocalMachine
        }
        'CurrentUser'  { 
            $Parameters.Add('CurrentUser', $true)
            $Hive = [Microsoft.Win32.Registry]::CurrentUser
        } 
        'Users'  { 
            $Parameters.Add('Username', $Username)
            $Hive = [Microsoft.Win32.Registry]::Users
        } 
    }

    $tempID = New-Guid
    $tempFile = Join-Path -Path $env:TEMP -ChildPath "$tempID.pol"
    $tempFileActual = Join-Path -Path $env:TEMP -ChildPath "$tempID.actual.pol"
    $tempFileExpected = Join-Path -Path $env:TEMP -ChildPath "$tempID.expected.pol"
    $tempRegKey = "Software\$tempID"
    
    # Export the target registry entries into a temp file
    Export-GPRegistryPolicy -Path $tempFile -Entries $Entries @Parameters -ErrorAction SilentlyContinue

    # Import the target registry entries into a temp location on registry
    Import-GPRegistryPolicy -Path $tempFile -KeyPrefix $tempRegKey @Parameters

    # Export the the temp registry key into a file to get actual settings
    Export-GPRegistryPolicy -Path $tempFileActual -Entries @($tempRegKey) @Parameters -ErrorAction SilentlyContinue

    # Import and apply the target .pol file into the temp location on registry
    Import-GPRegistryPolicy -Path $Path -KeyPrefix $tempRegKey @Parameters

    # Export the the temp registry key into a file to get expected settings
    Export-GPRegistryPolicy -Path $tempFileExpected -Entries @($tempRegKey) @Parameters
    
    $ActualRP = Parse-PolFile -Path $tempFileActual
    $ExpectedRP = Parse-PolFile -Path $tempFileExpected
    
    $ActualRPInJSON = ConvertTo-Json -InputObject $ActualRP
    $ExpectedRPInJSON = ConvertTo-Json -InputObject $ExpectedRP
    

    if (($ActualRPInJSON -ne $null) -and ($ExpectedRPInJSON -ne $null))
    {
        $DiffResults = Compare-Object `
            -ReferenceObject ($ActualRPInJSON) `
            -DifferenceObject ($ExpectedRPInJSON)
    }
    else
    {
        $DiffResults = 'FAILED' # Anything but a null value for $DiffResults indicates a failure.
    }

    # Clean up
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tempFileActual -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tempFileExpected -Force -ErrorAction SilentlyContinue
    $Hive.DeleteSubKeyTree($tempRegKey)

    return ([string]::IsNullOrEmpty($DiffResults))    
}

Function Get-AllKeys
{
    [OutputType([Array])]
    param (
        [Parameter(Mandatory)]
        [System.Object[]]
        $RegistryPolicies
    )

    $Result = @()

    foreach( $RP in $RegistryPolicies)
    {
        if (-not $Result.Contains($RP.keyName))
        {
            $Result += ,$RP.keyName
        }
    }

    return $Result
}

Function Assert
{
    param (
        [Parameter(Mandatory)]
        $Condition,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ErrorMessage
    )

    if (!$Condition) 
    {
        throw $ErrorMessage;
    }
}

#Export-ModuleMember -Function 'Import-GPRegistryPolicy','Export-GPRegistryPolicy','Test-GPRegistryPolicy'
#Export-ModuleMember -Function 'Parse-PolFile','Read-RegistryPolicies','Create-RegistrySettingsEntry','Create-GPRegistryPolicyFile','Append-RegistryPolicies'
Export-ModuleMember -Function 'Import-GPRegistryPolicy','Export-GPRegistryPolicy','Test-GPRegistryPolicy','Parse-PolFile','Read-RegistryPolicies','Create-RegistrySettingsEntry','Create-GPRegistryPolicyFile','Append-RegistryPolicies'
