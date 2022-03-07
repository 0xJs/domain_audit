# Registry Policy Cmdlets

These cmdlets will allow you to export and import .POL files, which contain the registry keys enacted by Group Policy. The primary intent of these cmdlets is to enable enforcing security policy settings on Nano Server, but this method will also work on Windows Server 2016.


These security-related settings include three different kinds of Group Policy artifacts:
* .POL files containing registry settings. These are handled by the cmdlets listed below.
* .INF files containing security template settings. This is handled by the "securityCmdlets"(*) module that ships in Server Technical Preview 5
* .CSV files containing advanced auditing settings. This is handled by the "securityCmdlets"(*) module that ships in Server Technical Preview 5
 (*) "securityCmdlets" is a temporary name for TP5. These modules will be renamed in a later release of Windows Server, which will be a breaking change. Please be aware any scripts that use this module will have to change for future releases of Windows Server 2016. 

.POL files can be generated from GPO Backups, or they can be generated with `Export-GpRegistryPolicy`. POL files will have either Local Machine or Local User registry keys, which must be specified to the Import- and Export- cmdlets. For Nano Server, all relevant settings will be Local Machine only. 

## Walkthrough for setting security policies on Nano Server

If you want to use the Security Baselines for Windows Server, you can download baselines in GPO format here: http://blogs.technet.com/b/secguide/archive/2016/01/22/security-baseline-for-windows-10-v1511-quot-threshold-2-quot-final.aspx

After extracting the attached .zip, there will be several GPOs in the "GPOs" folder.  From the GPO you wish to import, go to:
DomainSysvol\GPO\Machine
Copy the folder to the server you wish to manage.

If there are .POL files in the root of this folder, you can remotely invoke the following to import that .POL file onto the server
```powershell
Import-Module GpRegistryPolicy
#replace this string with the path to the .pol file
$GpoPol = "c:\GPO\domainSysvol\GPO\Machine\registry.pol"
Import-GPRegistryPolicy -Path $GpoPol -LocalMachine
```

If there are audit or security CSE files in this folder, they will be in:
DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\*.csv
DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\*.inf
respectively.

You can remotely invoke the following to import both audit and security settings to the server:
```powershell
Import-Module SecurityCmdlets
#replace this string with the path to the .INF file
$SecInf = "c:\GPO\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
$AuditCsv = "c:\GPO\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv"

Restore-SecurityPolicy -Path $secInf
Restore-AuditPolicy -Path $auditCsv
```

---

## Import-GPRegistryPolicy
Reads a .pol file containing group policy registry entries and applies its contents to the machine.
The division to which the contents must be applied to has to be defined using one of the three available
options for **LocalMachine**, **CurrentUser**, or **Username**.

### Syntax
```
Import-GPRegistryPolicy [-Path] <string> [-LocalMachine] [-KeyPrefix <string>]  [<CommonParameters>]

Import-GPRegistryPolicy [-Path] <string> [-CurrentUser] [-KeyPrefix <string>]  [<CommonParameters>]

Import-GPRegistryPolicy [-Path] <string> [-Username <string>] [-KeyPrefix <string>]  [<CommonParameters>]
```

| Parameter Name | Description                                                                            | 
| ---            | ---                                                                                    |
| Path           | Specifies the path to the .pol file to be imported.                                    |
| LocalMachine   | A switch that sets the Local Machine as the destination registry division.             |
| CurrentUser    | A switch that sets the Current User as the destination registry division.              |
| Username       | A string that selects the target user in the Users registry division.                  |
| KeyPrefix      | A prefix that will be prepended to the given key.                                      |

### Example
```
C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine

C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -CurrentUser

C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -Username testdomain\testuser

C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -Username localtestuser

C:\PS> Import-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine -KeyPrefix 'Software\TestKeys'
```

---

## Export-GPRegistryPolicy
Reads registry entries and write them in a .pol file. By default, the root key from which the registry
entries are read is 'Software\Policies'. However, if Entries are assinged in input, then this function
will export those instead. The division from which the contents must be read has to be defined using one
of the three available options for **LocalMachine**, **CurrentUser**, or **Username**.

### Syntax
```
Export-GPRegistryPolicy [-Path] <string> [[-Entries] <string[]>] -LocalMachine  [<CommonParameters>]

Export-GPRegistryPolicy [-Path] <string> [[-Entries] <string[]>] -CurrentUser  [<CommonParameters>]

Export-GPRegistryPolicy [-Path] <string> [[-Entries] <string[]>] [-Username <string>]  [<CommonParameters>]
```

| Parameter Name | Description                                                                                          | 
| ---            | ---                                                                                                  |
| Path           | Specifies the path to the .pol file to be imported.                                                  |
| LocalMachine   | A switch that sets the Local Machine as the destination registry division.                           |
| CurrentUser    | A switch that sets the Current User as the destination registry division.                            |
| Username       | A string that selects the target user in the Users registry division.                  |
| Entries        | Specifies the list of registry keys to be exported. The default value is set to 'Software\Policies'. |

### Example
```
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine
   
C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -CurrentUser

C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -Username testdomain\testuser

C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -Username localtestuser

C:\PS> Export-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine -Entries @('Software\Policies\Microsoft\Windows', 'Software\Policies\Microsoft\WindowsFirewall')
```

---

## Test-GPRegistryPolicy
Reads a .pol file containing group policy registry entries and tests its contents against current registry.
The division to which the contents must be applied has to be defined using one of the three available options 
for **LocalMachine**, **CurrentUser**, or **Username**.

### Syntax
```
Test-GPRegistryPolicy [-Path] <string> [[-Entries] <string[]>] [-LocalMachine]  [<CommonParameters>]

Test-GPRegistryPolicy [-Path] <string> [[-Entries] <string[]>] [-CurrentUser]  [<CommonParameters>]

Test-GPRegistryPolicy [-Path] <string> [[-Entries] <string[]>] [-Username <string>]  [<CommonParameters>]
```

| Parameter Name | Description                                                                                          | 
| ---            | ---                                                                                                  |
| Path           | Specifies the path to the .pol file to be imported.                                                  |
| LocalMachine   | A switch that sets the Local Machine as the destination registry division.                           |
| CurrentUser    | A switch that sets the Current User as the destination registry division.                            |
| Username       | A string that selects the target user in the Users registry division.                  |
| Entries        | Specifies the list of registry keys to be exported. The default value is set to 'Software\Policies'. |

### Example
```
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine
   
C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -CurrentUser

C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -Username testdomain\testuser

C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -Username localtestuser

C:\PS> Test-GPRegistryPolicy -Path "C:\Registry.pol" -LocalMachine -Entries @('Software\Policies\Microsoft\Windows', 'Software\Policies\Microsoft\WindowsFirewall')
```

---

# Registry Policy Parser Cmdlets

These cmdlets will allow you to work with .POL files, which contain the registry keys enacted by Group Policy. The primary intent of these cmdlets is to enable enforcing security policy settings on Nano Server, but this method will also work on Windows Server 2016. These cmdlets are used internally by *GPRegistryPolicy* Module.

---

## Parse-PolFile
Reads a .pol file containing group policy registry entries and returns an array of objects each containing a registry setting.

### Syntax
```
Parse-PolFile [-Path <string>]  [<CommonParameters>]
```

| Parameter Name | Description                                                                            | 
| ---            | ---                                                                                    |
| Path           | Specifies the path to the .pol file to be imported.                                    |

### Example
```
C:\PS> $RegistrySettings = Parse-PolFile -Path "C:\Registry.pol"
```

---

## Read-RegistryPolicies
Reads given registry entries and returns an array of registry settings.

### Syntax
```
Read-RegistryPolicies [-Division <string>] [-Entries <string[]>]  [<CommonParameters>]
```

| Parameter Name | Description                                                                                          | 
| ---            | ---                                                                                                  |
| Division       | Specifies the target registry division (LocalMachine, CurrentUser or Users)                          |
| Entries        | Specifies the list of registry keys to be exported. The default value is set to 'Software\Policies'. |

### Example
```
C:\PS> $RegistrySettings = Read-RegistryPolicies -Entries @('Software\Policies\Microsoft\Windows', 'Software\Policies\Microsoft\WindowsFirewall')

C:\PS> $RegistrySettings = Read-RegistryPolicies -Divistion 'CurrentUser'

C:\PS> $RegistrySettings = Read-RegistryPolicies -Divistion 'LocalMachine' -Entries @('Software\Policies\Microsoft\Windows', 'Software\Policies\Microsoft\WindowsFirewall')
```

---

## Create-RegistrySettingsEntry
Creates a .pol file entry byte array from a GPRegistryPolicy instance. This entry can be written
in a .pol file later.

### Syntax
```
$RegistrySettings = Create-RegistrySettingsEntry [-RegistryPolicy <GPRegistryPolicy[]>
```

| Parameter Name | Description                                                                                          | 
| ---            | ---                                                                                                  |
| RegistryPolicy | An instance of internal type 'GPRegistryPolicy'                                                      |

### Example
```
C:\PS> $Entry = Create-RegistrySettingsEntry -RegistryPolicy $GPRegistryPolicyInstance
```

---

## Append-RegistryPolicies
Appends an array of registry policy entries to a file. The file must alreay have a valid header.

### Syntax
```
Append-RegistryPolicies [-RegistryPolicies <GPRegistryPolicy[]>] [-Path <string>]
```

| Parameter Name   | Description                                                                                          | 
| ---              | ---                                                                                                  |
| RegistryPolicies | An array of instance of internal type 'GPRegistryPolicy'                                             |
| Path             | Specifies the path to the .pol file to be imported.                                                  |

### Example
```
C:\PS> Append-RegistryPolicies -RegistryPolicies $RegistryPoliciesInput -Path "C:\Registry.pol"
```

---

# Registry Policy DSC Resource

This resource will allow you to synchronize registry settings with a .POL file which contains the registry keys enacted by Group Policy. The primary intent of this resourceis to enable enforcing security policy settings on Nano Server, but this method will also work on Windows Server 2016.

| Parameter Name | Description                                                                               | 
| ---            | ---                                                                                       |
| Path           | Specifies the path to the .pol file containing the registry keys enacted by Group Policy. |
