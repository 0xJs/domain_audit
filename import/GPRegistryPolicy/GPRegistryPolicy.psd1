@{

# Script module or binary module file associated with this manifest.
RootModule = 'GPRegistryPolicy.psm1'

#DscResourcesToExport = ''

# Version number of this module.
ModuleVersion = '0.3'

# ID used to uniquely identify this module
GUID = 'dad09e6f-22bf-4f90-94ba-4d1505c6b8ea'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = '(c) 2016 Microsoft. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Module with cmdlets to work with GP Registry Policy .pol files'

# Required Modules - Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Nested Modules - Modules that must be imported into the global environment prior to importing this module
NestedModules = @('GPRegistryPolicyResource.psd1')

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Name of the DSC resources to export in this module
DscResourcesToExport = @('RegistryPolicy')

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('GroupPolicy', 'DSC', 'DesiredStateConfiguration')

		# A URL to the license for this module.
		LicenseUri = 'https://github.com/PowerShell/GPRegistryPolicy/blob/master/LICENSE'

		# A URL to the main website for this project.
		ProjectUri = 'https://github.com/PowerShell/GPRegistryPolicy'

        # A URL to an icon representing this module.
        # IconUri = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

FunctionsToExport = @('Import-GPRegistryPolicy','Export-GPRegistryPolicy','Test-GPRegistryPolicy','Parse-PolFile','Read-RegistryPolicies','Create-RegistrySettingsEntry','Create-GPRegistryPolicyFile','Append-RegistryPolicies')
}
