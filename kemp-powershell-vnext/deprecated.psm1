#
# $Id: fcarpin $ Fabrizio Carpin
#

$warning = "WARNING: This function is deprecated. Please use"

# ==================================================
# region TEMPLATES
# ==================================================
Function ExportVSTemplate
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$Port,

		[ValidateSet("tcp", "udp")]
		[string]$Protocol,

		[Int32]$VSIndex,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path,
		[switch]$Force,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Export-VSTemplate"
}
Export-ModuleMember -function ExportVSTemplate

Function UploadTemplate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Install-Template"
}
Export-ModuleMember -function UploadTemplate

Function DeleteTemplate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-Template"
}
Export-ModuleMember -function DeleteTemplate

Function ListTemplates
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-Template"
}
Export-ModuleMember -function ListTemplates
# ==================================================
# endregion TEMPLATES
# ==================================================


# ==================================================
# region LOGGING
# ==================================================
Function Get-EmailOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LogEmailConfiguration"
}
Export-ModuleMember -function Get-EmailOption

Function Set-EmailOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$EmailEnable,

		[string]$EmailServer,

		[ValidateRange(3, 65530)]
		[int]$EmailPort,

		[string]$EmailUser,

		[string]$EmailPassword,

		[string]$EmailDomain,

		[ValidateSet(0, 1, 2, 3)]
		[Int16]$EmailSSLMode,

		[string]$EmailEmergency,

		[string]$EmailCritical,

		[string]$EmailError,

		[string]$EmailWarn,

		[string]$EmailNotice,

		[string]$EmailInfo,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LogEmailConfiguration"
}
Export-ModuleMember -function Set-EmailOption

Function Get-SyslogOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LogSyslogConfiguration"
}
Export-ModuleMember -function Get-SyslogOption

Function Set-SyslogOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$SyslogCritical,
		[string]$SyslogEmergency,
		[string]$SyslogError,
		[string]$SyslogInfo,
		[string]$SyslogNotice,
		[string]$SyslogWarn,

		[UInt16]$SyslogPort,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LogSyslogConfiguration"
}
Export-ModuleMember -function Set-SyslogOption

Function Get-Statistics
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[switch]$VirtualService,
		[switch]$RealServer,
		[switch]$Totals,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LogStatistics"
}
Export-ModuleMember -function Get-Statistics
# ==================================================
# endregion LOGGING
# ==================================================


# ==================================================
# region SSO
# ==================================================
Function UploadRSAConfigurationFile
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Install-SSORSAConfigurationFile"
}
Export-ModuleMember -function UploadRSAConfigurationFile

Function UploadRSANodeSecretAndPassword
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Password,

		[Parameter(Mandatory=$true)]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Install-SSORSANodeSecretAndPassword"
}
Export-ModuleMember -function UploadRSANodeSecretAndPassword

Function FlushSsoCache
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Clear-SSOCache"
}
Export-ModuleMember -function FlushSsoCache
# ==================================================
# endregion SSO
# ==================================================


# ==================================================
# region NETWORKING
# ==================================================
Function ListIfconfig
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmNetworkInterface"
}
Export-ModuleMember -function ListIfconfig

Function Get-NetworkOptions
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-NetworkConfiguration"
}
Export-ModuleMember -function Get-NetworkOptions

Function Set-NetworkOptions
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$SNAT,

		[bool]$AllowUpload,

		[ValidateRange(0, 86400)]
		[Int64]$ConnTimeout,

		[bool]$KeepAlive,

		[bool]$MultiGW,

		[bool]$NonLocalRS,

		[bool]$OnlyDefaultRoutes,

		[bool]$ResetClose,

		[bool]$SubnetOrigin,

		[bool]$SubnetOriginating,

		[bool]$TCPTimeStamp,

		[bool]$RouteFilter,

		[ValidateRange(512, 4096)]
		[Int32]$DHKeySize,

		[string]$Http_Proxy,

    [ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-NetworkConfiguration"
}
Export-ModuleMember -function Set-NetworkOptions

Function Get-DNSConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-NetworkDNSConfiguration"
}
Export-ModuleMember -function Get-DNSConfiguration

Function Set-DNSConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Hostname,

		[string]$HA1Hostname,

		[string]$HA2Hostname,

		[string]$NameServer,

		[string]$Searchlist,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-NetworkDNSConfiguration"
}
Export-ModuleMember -function Set-DNSConfiguration

Function Update-LmDNSCache
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Update-NetworkDNSCache"
}
Export-ModuleMember -function Update-LmDNSCache

Function Get-SNMPOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-NetworkSNMPConfiguration"
}
Export-ModuleMember -function Get-SNMPOption

Function Set-SNMPOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$SNMPEnable,
		[bool]$SNMPv3enable,
		[string]$SNMPv3user,
		[string]$SNMPv3userpasswd,

		[ValidateSet("SHA", "MD5")]
		[string]$snmpAuthProt,

		[ValidateSet("AES", "DES")]
		[string]$snmpPrivProt,

		[string]$SNMPClient,
		[string]$SNMPCommunity,
		[string]$SNMPContact,
		[string]$SNMPLocation,
		[bool]$SNMPTrapEnable,
		[bool]$SNMPHaTrap,
		[string]$SNMPv1Sink,
		[string]$SNMPv2Sink,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-NetworkSNMPConfiguration"
}
Export-ModuleMember -function Set-SNMPOption

Function Get-Interface
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Int16]$InterfaceID = -1,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-NetworkInterface"
}
Export-ModuleMember -function Get-Interface

Function Set-Interface
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Int16]$InterfaceID = 0,

		[string]$IPAddress,

		[Int32]$MTU,

		[bool]$HACheck,

		[bool]$GWIface,

		[bool]$clupdate,

		[bool]$GeoTraffic,

		[ValidateSet("802.3ad", "Active-backup")]
		[string]$BondMode,

		[string]$Partner,

		[string]$Shared,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-NetworkInterface"
}
Export-ModuleMember -function Set-Interface

Function Add-InterfaceAddress
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Int16]$InterfaceID,
		[string]$Address,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-NetworkInterfaceAdditionalAddress"
}
Export-ModuleMember -function Add-InterfaceAddress

Function Remove-InterfaceAddress
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[Int16]$InterfaceID,
		[string]$Address,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-NetworkInterfaceAdditionalAddress"
}
Export-ModuleMember -function Remove-InterfaceAddress

Function Get-Route
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-NetworkRoute"
}
Export-ModuleMember -function Get-Route

Function New-Route
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Destination,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Alias("Mask", "SubnetMask")]
		[Int16]$CIDR,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Gateway,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-NetworkRoute"
}
Export-ModuleMember -function New-Route

Function Remove-Route
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Destination,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-NetworkRoute"
}
Export-ModuleMember -function Remove-Route

Function Register-BondedInterface
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Register-NetworkBondedInterface"
}
Export-ModuleMember -function Register-BondedInterface

Function Unregister-BondedInterface
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Unregister-NetworkBondedInterface"
}
Export-ModuleMember -function Unregister-BondedInterface

Function Add-BondedInterface
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[Parameter(Mandatory=$true)]
		[Int16]$BondID,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-NetworkBondedInterface"
}
Export-ModuleMember -function Add-BondedInterface

Function Remove-BondedInterface
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[Parameter(Mandatory=$true)]
		[Int16]$BondID,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-NetworkBondedInterface"
}
Export-ModuleMember -function Remove-BondedInterface

Function Add-VLan
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[Parameter(Mandatory=$true)]
		[ValidateRange(1, 4095)]
		[Int16]$VLanId,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-NetworkVLAN"
}
Export-ModuleMember -function Add-VLan

Function Remove-VLan
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-NetworkVLAN"
}
Export-ModuleMember -function Remove-VLan

Function Add-VxLan
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[Parameter(Mandatory=$true)]
		[ValidateRange(1, 16777214)]
		[Int32]$VNI,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Addr,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-NetworkVxLAN"
}
Export-ModuleMember -function Add-VxLan

Function Remove-VxLan
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int16]$InterfaceID,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-NetworkVxLAN"
}
Export-ModuleMember -function Remove-VxLan
# ==================================================
# endregion NETWORKING
# ==================================================


# ==================================================
# region ADC
# ==================================================
Function New-VirtualService
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$VirtualService,

		[Parameter(Mandatory=$true)]
		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[Parameter(Mandatory=$true)]
		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[ValidateRange(0, 6)]
		[Int16]$AddVia,

		[string]$Template,

		[bool]$Cache = $false,

		[string]$CertFile,

		[ValidateSet("tcp", "icmp", "https", "http", "smtp", "nntp", "ftp", "telnet", "pop3", "imap", "rdp", "ldap", "none")]
		[string]$CheckType = "tcp",

		[string]$CheckHost,

		[string]$CheckPattern,

		[string]$CheckUrl,

		[string]$CheckHeaders,

		[string]$LdapEndpoint,

		[string]$MatchLen,

		[ValidateRange(0, 1)]
		[int]$CheckUse1_1 = -1,

		[Int32]$CheckPort,

		[bool]$EnhancedHealthChecks,

		[Int32]$RsMinimum,

		[ValidateRange(0, 2)]
		[Int16]$ClientCert = 0,

		[bool]$Compress = $false,

		[string]$Cookie,

		[ValidateRange(0, 100)]
		[Int16]$CachePercent = 0,

		[string]$DefaultGW,

		[bool]$Enable = $true,

		[string]$ErrorCode = 0,

		[string]$ErrorUrl,

		[ValidateRange(3, 65530)]
		[Int32]$PortFollow,

		[bool]$ForceL7 = $true,

		[ValidateRange(0, 86400)]
		[Int32]$Idletime,

		[String[]]$LocalBindAddresses,

		[ValidateSet("gen", "http", "tls", "ts")]
		[string]$VSType,

		[string]$Nickname,

		[ValidateSet("ssl", "cookie", "active-cookie", "cookie-src", "active-cook-src", "cookie-hash",
		             "url", "query-hash", "host", "header", "super", "super-src", "src", "rdp", "rdp-src",
		             "rdp-sb", "udpsip", "none")]
		[string]$Persist,

		[ValidateRange(0, 604800)]
		[Int32]$PersistTimeout,

		[string]$QueryTag,

		[string]$CipherSet,

		[bool]$SSLReencrypt,

		[bool]$SSLReverse,

		[ValidateSet("", "http", "https")]
		[string]$SSLRewrite,

		[string]$ReverseSNIHostname,

		[ValidateSet("rr", "wrr", "lc", "wlc", "fixed", "adaptive", "sh")]
		[string]$Schedule,

		[ValidateRange(0, 5)]
		[Int16]$ServerInit,

		[bool]$SSLAcceleration,

		[string]$StandByAddr,

		[string]$StandByPort,

		[Int32]$TransactionLimit,

		[bool]$Transparent,

		[bool]$SubnetOriginating,

		[bool]$UseforSnat,

		[ValidateSet("0", "1", "2", "4", "8")]
		[string]$QoS,

		[int32]$CheckUseGet,

		[ValidateRange(0, 7)]
		[Int16]$Verify,

		[string]$ExtraHdrKey,

		[string]$ExtraHdrValue,

		[string]$AllowedHosts,

		[string]$AllowedDirectories,

		[string]$AllowedGroups,

		[string]$GroupSIDs,

		[bool]$IncludeNestedGroups,

		[bool]$DisplayPubPriv,

		[bool]$DisablePasswordForm,

		[string]$Domain,

		[string]$AltDomains,

		[string]$Logoff,

		[ValidateRange(0, 7)]
		[Int16]$ESPLogs,

		[string]$SMTPAllowedDomains,

		[bool]$ESPEnabled,

		[string]$UserPwdChangeUrl,

		[string]$UserPwdChangeMsg,

		[ValidateRange(0, 5)]
		[Int16]$InputAuthMode,

		[ValidateRange(0, 2)]
		[Int16]$OutputAuthMode,

		[ValidateRange(0, 1)]
		[Int16]$StartTLSMode,

		[string]$ExtraPorts,

		[string]$AltAddress,

		[bool]$MultiConnect,

		[string]$SingleSignOnDir,

		[string]$OCSPVerify,

		[Int32]$FollowVSID,

		[bool]$TlsType = $false,

		[string]$CheckPostData,

		[string]$CheckCodes,

		[string]$PreProcPrecedence,

		[Int16]$PreProcPrecedencePos,

		[string]$RequestPrecedence,

		[Int16]$RequestPrecedencePos,

		[string]$ResponsePrecedence,

		[Int16]$ResponsePrecedencePos,

		[string]$RsRulePrecedence,

		[Int16]$RsRulePrecedencePos,

		[bool]$NeedHostName,

		[string]$CopyHdrFrom = "",

		[string]$CopyHdrTo = "",

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcVirtualService"
}
Export-ModuleMember -function New-VirtualService

Function Get-VirtualService
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[String]$VSProtocol,

		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcVirtualService"
}
Export-ModuleMember -function Get-VirtualService

Function Set-VirtualService
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[Int16]$AddVia,

		[bool]$Cache,

		[string]$CertFile,

		[ValidateSet("tcp", "icmp", "https", "http", "smtp", "nntp", "ftp", "telnet", "pop3", "imap", "rdp", "ldap", "none")]
		[string]$CheckType,

		[string]$CheckHost,

		[string]$CheckPattern,

		[string]$CheckUrl,

		[string]$CheckHeaders,

		[string]$LdapEndpoint,

		[string]$MatchLen,

		[ValidateRange(0, 1)]
		[int]$CheckUse1_1 = -1,

		[Int32]$CheckPort,

		[bool]$EnhancedHealthChecks,

		[Int32]$RsMinimum,

		[ValidateRange(0, 2)]
		[Int16]$ClientCert,

		[bool]$Compress,

		[string]$Cookie,

		[ValidateRange(0, 100)]
		[Int16]$CachePercent,

		[string]$DefaultGW,

		[bool]$Enable,

		[string]$ErrorCode,

		[string]$ErrorUrl,

		[ValidateRange(3, 65530)]
		[Int32]$PortFollow,

		[bool]$ForceL7,

		[ValidateRange(0, 86400)]
		[Int32]$Idletime,

		[String[]]$LocalBindAddresses,

		[ValidateSet("gen", "http", "tls", "ts")]
		[string]$VSType,

		[string]$Nickname,

		[ValidateSet("none", "ssl", "cookie", "active-cookie", "cookie-src", "active-cook-src", "cookie-hash", "url",
		             "query-hash", "host", "header", "super", "super-src", "src", "rdp", "rdp-src", "rdp-sb", "udpsip")]
		[string]$Persist,

		[ValidateRange(0, 604800)]
		[Int32]$PersistTimeout,

		[string]$QueryTag,

		[string]$CipherSet,

		[bool]$SSLReencrypt,

		[bool]$SSLReverse,

		[ValidateSet("", "http", "https")]
		[string]$SSLRewrite,

		[string]$ReverseSNIHostname,

		[ValidateSet("rr", "wrr", "lc", "wlc", "fixed", "adaptive", "sh")]
		[string]$Schedule,

		[ValidateRange(0, 5)]
		[Int16]$ServerInit,

		[bool]$SSLAcceleration,

		[string]$StandByAddr,

		[string]$StandByPort,

		[Int32]$TransactionLimit,

		[bool]$Transparent,

		[bool]$SubnetOriginating,

		[bool]$UseforSnat,

		[ValidateSet("0", "1", "2", "4", "8")]
		[string]$QoS,

		[int32]$CheckUseGet,

		[ValidateRange(0, 7)]
		[Int16]$Verify,

		[string]$ExtraHdrKey,

		[string]$ExtraHdrValue,

		[string]$AllowedHosts,

		[string]$AllowedDirectories,

		[string]$AllowedGroups,

		[string]$GroupSIDs,

		[bool]$IncludeNestedGroups,

		[bool]$DisplayPubPriv,

		[bool]$DisablePasswordForm,

		[string]$Domain,

		[string]$AltDomains,

		[string]$Logoff,

		[ValidateRange(0, 7)]
		[Int16]$ESPLogs,

		[string]$SMTPAllowedDomains,

		[bool]$ESPEnabled,

		[string]$UserPwdChangeUrl,

		[string]$UserPwdChangeMsg,

		[ValidateRange(0, 5)]
		[Int16]$InputAuthMode,

		[ValidateRange(0, 1)]
		[Int16]$OutputAuthMode,

		[ValidateRange(0, 1)]
		[Int16]$StartTLSMode,

		[string]$ExtraPorts,

		[string]$AltAddress,

		[bool]$MultiConnect,

		[string]$SingleSignOnDir,

		[string]$OCSPVerify,

		[Int32]$FollowVSID,

		[bool]$TlsType = $false,

		[string]$CheckPostData,

		[string]$CheckCodes,

		[string]$PreProcPrecedence,

		[Int16]$PreProcPrecedencePos,

		[string]$RequestPrecedence,

		[Int16]$RequestPrecedencePos,

		[string]$ResponsePrecedence,

		[Int16]$ResponsePrecedencePos,

		[string]$RsRulePrecedence,

		[Int16]$RsRulePrecedencePos,

		[bool]$NeedHostName,

		[string]$CopyHdrFrom,

		[string]$CopyHdrTo,

		[string]$ServerFbaPath,

		[string]$ServerFbaPost,

		[bool]$Intercept,

		[bool]$AllowHTTP2,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptOpts,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptRules,

		[ValidateRange(0, 100000)]
		[int32]$AlertThreshold,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-AdcVirtualService"
}
Export-ModuleMember -function Set-VirtualService

Function Remove-VirtualService
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[Parameter(ParameterSetName="IPAddress",ValueFromPipelineByPropertyName=$true)]
		[Parameter(ParameterSetName="Credential")]
		[Parameter(ParameterSetName="Certificate")]
		[string]$VirtualService,

		[Parameter(ParameterSetName="IPAddress",ValueFromPipelineByPropertyName=$true)]
		[Parameter(ParameterSetName="Credential")]
		[Parameter(ParameterSetName="Certificate")]
		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[Parameter(ParameterSetName="IPAddress",ValueFromPipelineByPropertyName=$true)]
		[Parameter(ParameterSetName="Credential")]
		[Parameter(ParameterSetName="Certificate")]
		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Parameter(ParameterSetName="Index",ValueFromPipelineByPropertyName=$true)]
		[Parameter(ParameterSetName="Credential")]
		[Parameter(ParameterSetName="Certificate")]
		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-AdcVirtualService"
}
Export-ModuleMember -function Remove-VirtualService

Function New-RealServer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RealServer,

		[Parameter(Mandatory=$true)]
		[ValidateRange(3, 65530)]
		[Int32]$RealServerPort,

		[ValidateRange(1, 65530)]
		[Int32]$Weight,

		[ValidateSet("nat", "route")]
		[string]$Forward = "nat",

		[bool]$Enable = $true,

		[bool]$Non_Local = $false,

		[ValidateRange(0, 100000)]
		[Int64]$Limit = 0,

		[bool]$Critical,

		[ValidateRange(0, 65535)]
		[Int32]$Follow,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcRealServe"
}
Export-ModuleMember -function New-RealServer

Function Remove-RealServer
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$RealServer,

		[ValidateRange(3, 65530)]
		[Int32]$RealServerPort,

		[Int32]$RSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-AdcRealServer"
}
Export-ModuleMember -function Remove-RealServer

Function Set-RealServer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$RealServer,

		[ValidateRange(3, 65530)]
		[Int32]$RealServerPort,

		[Int32]$RSIndex = -1,

		[ValidateRange(3, 65530)]
		[Int32]$NewPort,

		[ValidateRange(1, 65530)]
		[Int32]$Weight,

		[ValidateSet("nat", "route")]
		[string]$Forward = "nat",

		[bool]$Enable = $true,

		[ValidateRange(0, 100000)]
		[Int64]$Limit = 0,

		[bool]$Critical,

		[ValidateRange(0, 65535)]
		[Int32]$Follow,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-AdcRealServer"
}
Export-ModuleMember -function Set-RealServer

Function Get-RealServer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[String]$VSProtocol,

		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$RealServer,

		[ValidateRange(3, 65530)]
		[Int32]$RSPort,

		[Int32]$RSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcRealServer"
}
Export-ModuleMember -function Get-RealServer

Function Enable-RealServer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RSIpAddress,

		[ValidateRange(3, 65530)]
		[Int32]$RSPort,

		[ValidateNotNullOrEmpty()]
		[string]$RSFqdn,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Enable-AdcRealServer"
}
Export-ModuleMember -function Enable-RealServer

Function Disable-RealServer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RSIpaddress,

		[ValidateRange(3, 65530)]
		[Int32]$RSPort,

		[ValidateNotNullOrEmpty()]
		[string]$RSFqdn,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Disable-AdcRealServer"
}
Export-ModuleMember -function Disable-RealServer

Function Remove-AdcVirtualServerRule
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[Parameter(Mandatory=$true)]
		[ValidateSet("pre", "response", "request")]
		[string]$RuleType,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-AdcVirtualServiceRule"
}
Export-ModuleMember -function Remove-AdcVirtualServerRule

Function Remove-VirtualServerRule
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[Parameter(Mandatory=$true)]
		[ValidateSet("pre", "response", "request")]
		[string]$RuleType,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-AdcVirtualServiceRule"
}
Export-ModuleMember -function Remove-VirtualServerRule

Function New-RealServerRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$RealServer,

		[ValidateRange(3, 65530)]
		[Int32]$RSPort,

		[Int32]$RSIndex = -1,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcRealServerRule"
}
Export-ModuleMember -function New-RealServerRule

Function Remove-RealServerRule
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[ValidateNotNullOrEmpty()]
		[string]$RealServer,

		[ValidateRange(3, 65530)]
		[Int32]$RSPort,

		[Int32]$RSIndex = -1,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RuleName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-AdcRealServerRule"
}
Export-ModuleMember -function Remove-RealServerRule

Function New-Rule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$RuleName,

		[ValidateSet("regex", "prefix", "postfix")]
		[string]$MatchType = "regex",

		[bool]$IncHost = $false,

		[bool]$NoCase = $false,

		[bool]$Negate = $false,

		[bool]$IncQuery = $false,

		[string]$Header,

		[string]$Pattern,

		[string]$Replacement,

		[ValidateRange(0, 5)]
		[Int32]$Type,		# TODO: to change Type to RuleType. Pay attention to the mapping
		                #       to add values range
		                #       EVEN BETTER: set the RuleType to string as in Get-AdcContentRule with the
		                #       same values and maps the string type to the corrispondent integer value.

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcContentRule"
}
Export-ModuleMember -function New-Rule

Function Remove-Rule
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string]$RuleName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-AdcContentRule"
}
Export-ModuleMember -function Remove-Rule

Function Set-Rule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$RuleName,

		[ValidateSet("regex", "prefix", "postfix")]
		[string]$MatchType = "regex",

		[bool]$IncHost,

		[bool]$NoCase,

		[bool]$Negate,

		[bool]$IncQuery,

		[string]$Header,

		[string]$Pattern,

		[string]$Replacement,

		[ValidateRange(0, 5)]
		[Int32]$Type,		# TODO: to change Type to RuleType. Pay attention to the mapping
		                #       to add values range
		                #       EVEN BETTER: set the RuleType to string as in Get-AdcContentRule with the
		                #       same values and maps the string type to the corrispondent integer value.

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-AdcContentRule"
}
Export-ModuleMember -function Set-Rule

Function Get-Rule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$RuleName,

		[ValidateSet("MatchContentRule", "AddHeaderRule", "DeleteHeaderRule", "ReplaceHeaderRule", "ModifyUrlRule", "ReplaceBodyRule")]
		[string]$RuleType,

		[switch]$All,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcContentRule"
}
Export-ModuleMember -function Get-Rule

Function Get-L7Configuration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcL7Configuration"
}
Export-ModuleMember -function Get-L7Configuration

Function Set-L7Configuration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$ScalingOver64KConnections,

		[ValidateSet("No", "Yes", "Yes - Accept Changes")]
		[string]$AlwaysCheckPersist,

		[bool]$AddPortToActiveCookie,

		[bool]$RFCConform,

		[bool]$CloseOnError,

		[bool]$AddViaHeaderInCacheResponses,

		[bool]$RSAreLocal,

		[bool]$DropOnRSFail,

		[bool]$DropAtDrainEnd,

		[ValidateRange(30, 300)]
		[Int16]$L7AuthTimeoutSecs,

		[ValidateRange(60, 300)]
		[Int16]$L7ClientTokenTimeoutSecs,

		[int]$L7ConnectionDrainTimeoutSecs,

		[ValidateSet("X-ClientSide", "X-Forwarded-For", "None")]
		[string]$AdditionalL7Header,

		[ValidateSet("RFC-2616 Compliant", "Require 100-Continue", "RFC-7231 Compliant")]
		[string]$OneHundredContinueHandling,

		[bool]$AllowEmptyPosts,

		[bool]$AllowEmptyHttpHeaders,

		[bool]$ForceCompleteRSMatch,

		[ValidateRange(0, 600)]
		[Int16]$SlowStart,

		[bool]$ShareSubVSPersistance,

		#[bool]$Transparent,	# FIXME: still available?

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-AdcL7Configuration"
}
Export-ModuleMember -function Set-L7Configuration

Function Get-LogSplitInterval
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	param(
		[validatenotnullorempty()]
		[string]$LoadBalancer = $loadbalanceraddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcL7LogInsightSplitConfiguration"
}
Export-ModuleMember -function Get-LogSplitInterval

Function Set-LogSplitInterval
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param( 
		[Parameter(Mandatory=$true)]
		[string]$logsplitinterval,	

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcL7LogInsightSplitConfiguration"
}
Export-ModuleMember -function Set-LogSplitInterval

Function Get-ServiceHealth
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcServiceHealth"
}
Export-ModuleMember -function Get-ServiceHealth

Function Set-ServiceHealth
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateRange(9, 120)]
		[Int16]$CheckInterval,

		[ValidateRange(4, 60)]
		[Int16]$ConnectTimeout,

		[ValidateRange(2, 15)]
		[Int16]$RetryCount,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-AdcServiceHealth"
}
Export-ModuleMember -function Set-ServiceHealth

Function Add-NoCompressExtension
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcHttpCompressionException"
}
Export-ModuleMember -function Add-NoCompressExtension

Function Remove-NoCompressExtension
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-AdcServiceHealth"
}
Export-ModuleMember -function Remove-NoCompressExtension

Function Add-NoCacheExtension
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcHttpCacheException"
}
Export-ModuleMember -function Add-NoCacheExtension

Function Remove-NoCacheExtension
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[ValidatePattern({^\.})]
		[String[]]$Extension,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-AdcHttpCacheException"
}
Export-ModuleMember -function Remove-NoCacheExtension

Function Get-AdaptiveCheck
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcAdaptiveHealthCheck"
}
Export-ModuleMember -function Get-AdaptiveCheck

Function Set-AdaptiveCheck
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$AdaptiveURL,
		[Int32]$AdaptivePort,
		[ValidateRange(10, 60)]
		[Int32]$AdaptiveInterval,
		[Int16]$MinPercent,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-AdcAdaptiveHealthCheck"
}
Export-ModuleMember -function Set-AdaptiveCheck

Function VSAddWafRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VS,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VSPort,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Parameter(Mandatory=$true)]
		[string]$Rule,

		[ValidateNotNullOrEmpty()]
		[string]$Enablerules,

		[ValidateNotNullOrEmpty()]
		[string]$Disablerules,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-AdcVsWafRule"
}
Export-ModuleMember -function VSAddWafRule

Function VSRemoveWafRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VS,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VSPort,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Rule,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-AdcVsWafRule"
}
Export-ModuleMember -function VSRemoveWafRule

Function VSListWafRuleIds
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VS,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$VSPort,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Rule,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-AdcVsWafRule"
}
Export-ModuleMember -function VSListWafRuleIds
# ==================================================
# endregion ADC
# ==================================================


# ==================================================
# region SECURITY
# ==================================================
Function Set-AdminAccess
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateRange(0, 99)]
		[Int32]$WuiNetworkInterfaceId = -1,

		[Parameter(Mandatory=$true)]
		[ValidateRange(3, 65530)]
		[int32]$WuiPort = -1,

		[string]$WuiDefaultGateway,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-SecAdminAccess"
}
Export-ModuleMember -function Set-AdminAccess

Function Get-WUIAuth
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-SecWuiAuthentication"
}
Export-ModuleMember -function Get-WUIAuth

Function Set-WUIAuth
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$RADIUSServer,

		[ValidateRange(3, 65530)]
		[Int64]$RADIUSPort,

		[string]$RADIUSSecret,

		[string]$RADIUSBackupServer,

		[ValidateRange(3, 65530)]
		[Int64]$RADIUSBackupPort,

		[string]$RADIUSBackupSecret,

		[int]$RADIUSRevalidateInterval,

		[string]$WuiLdapEp,

		[bool]$SessionLocalAuth,

		[ValidateSet(7, 22, 23, 262, 263, 278, 279, 772, 773, 774, 775, 788, 789, 790, 791)]
		[Int16]$SessionAuthMode,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-SecWuiAuthentication"
}
Export-ModuleMember -function Set-WUIAuth

Function Get-WUISetting
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-SecAdminWuiConfiguration"
}
Export-ModuleMember -function Get-WUISetting

Function Set-WUISetting
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateRange(0, 14)]
		[int]$WUITLSProtocols,

		[ValidateSet("Default", "Default_NoRc4", "BestPractices", "Intermediate_compatibility", "Backward_compatibility", "WUI", "FIPS", "Legacy")]
		[string]$WUICipherset,

		[bool]$sessioncontrol,

		[bool]$sessionbasicauth,

		[ValidateRange(1, 999)]
		[Int16]$sessionmaxfailattempts,

		[ValidateRange(60, 86400)]
		[Int32]$sessionidletime,

		[ValidateRange(0, 9)]
		[Int16]$sessionconcurrent,

		[string]$wuipreauth,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-SecAdminWuiConfiguration"
}
Export-ModuleMember -function Set-WUISetting

Function UserSetSystemPassword
{	
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$CurrentPassword,

		[Parameter(Mandatory=$true)]
		[String]$NewPassword,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	Write-Output "$warning Set-SecSystemUserPassword"
}
Export-ModuleMember -function UserSetSystemPassword

Function UserSetPermissions
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,

		[Parameter(Mandatory=$true)]
		[String]$Permissions,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-SecUserPermission"
}
Export-ModuleMember -function UserSetPermissions

Function UserChangeLocalPassword
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,

		[Parameter(Mandatory=$true)]
		[String]$Password,

		[Parameter(Mandatory=$true)]
		[ValidateRange(0, 1)]
		[int]$Radius,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-SecUserPassword"
}
Export-ModuleMember -function UserChangeLocalPassword
# ==================================================
# endregion SECURITY
# ==================================================


# ==================================================
# region SYSTEM
# ==================================================
Function Initialize-LoadBalancer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Address,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = 443,

		[Parameter(ParameterSetName="Credential")]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(ParameterSetName="Certificate")]
		[ValidateNotNullOrEmpty()]
		[String]$CertificateStoreLocation = $null,

		[Parameter(ParameterSetName="Certificate")]
		[ValidateNotNullOrEmpty()]
		[String]$SubjectCN = $null
	)
	Write-Output "$warning Initialize-LmConnectionParameters"
}
Export-ModuleMember -function Initialize-LoadBalancer

Function Test-ServerConnection
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName,

		[ValidateRange(3, 65530)]
		[Int32]$Port
	)
	Write-Output "$warning Test-LmServerConnection"
}
Export-ModuleMember -function Test-ServerConnection
# ==================================================
# endregion SYSTEM
# ==================================================


# ==================================================
# region GET-SET
# ==================================================
Function Get-AllParameters
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmAllParameters"
}
Export-ModuleMember -function Get-AllParameters, Get-AllParameters

Function Get-Parameter
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Param,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmParameter"
}
Export-ModuleMember -function Get-Parameter

Function Set-Parameter
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Param,

		[Parameter(Mandatory=$true)]
		[AllowEmptyString()]
		[String]$Value = "",

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN

	)
	Write-Output "$warning Set-LmParameter"
}
Export-ModuleMember -function Set-Parameter

# ==================================================
# endregion GET-SET
# ==================================================


# ==================================================
# region TLS
# ==================================================
Function New-Certificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[string]$Password,

		[switch]$Replace,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-TlsCertificate"
}
Export-ModuleMember -function New-Certificate

Function ListCert
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$CertName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-TlsCertificate"
}
Export-ModuleMember -function ListCert

Function Remove-Certificate
{
	[cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-TlsCertificate"
}
Export-ModuleMember -function Remove-Certificate

Function Backup-Certificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateLength(6, 64)]
		[string]$Password,

		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Backup-TlsCertificate"
}
Export-ModuleMember -function Backup-Certificate

Function Restore-Certificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateLength(6, 64)]
		[string]$Password,

		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateSet("Full", "VS", "Third")]
		[string]$Type,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Restore-TlsCertificate"
}
Export-ModuleMember -function Restore-Certificate

Function New-IntermediateCertificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Name,

		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-TlsIntermediateCertificate"
}
Export-ModuleMember -function New-IntermediateCertificate

Function Remove-IntermediateCertificate
{
	[cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact="High",DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Remove-TlsIntermediateCertificate"
}
Export-ModuleMember -function Remove-IntermediateCertificate

Function GetCipherset
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-TlsCipherSet"
}
Export-ModuleMember -function GetCipherset

Function ModifyCipherset
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Value,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-TlsCipherSet"
}
Export-ModuleMember -function ModifyCipherset

Function DelCipherset
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-TlsCipherSet"
}
Export-ModuleMember -function DelCipherset

Function HSMShow
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-TlsHSM"
}
Export-ModuleMember -function HSMShow

Function HSMConfigure
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[String]$Sethsm,
		[String]$Safeaddr,
		[String]$Clpass,
		[bool]$Enable,
		[String]$Cavhsmaddr,
		[String]$Cavhsmpasswd,
		[String]$Cavhsmuser,
		[bool]$Cavhsmenable,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-TlsHSM"
}
Export-ModuleMember -function HSMConfigure

Function HSMGenerateClientCert
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Clcertname,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning New-TlsHSMClientCert"
}
Export-ModuleMember -function HSMGenerateClientCert

Function HSMUploadCACert
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-TlsHSMCACert"
}
Export-ModuleMember -function HSMUploadCACert
# ==================================================
# endregion TLS
# ==================================================


# ==================================================
# region WAF
# ==================================================
Function ListWafRules
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-WafRules"
}
Export-ModuleMember -function ListWafRules

Function AddWafCustomData
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-WafCustomRuleData"
}
Export-ModuleMember -function AddWafCustomData

Function DownloadWafCustomData
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RuleDataName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Export-WafCustomRuleData"
}
Export-ModuleMember -function DownloadWafCustomData

Function DelWafCustomData
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Filename,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Uninstall-WafCustomRuleData"
}
Export-ModuleMember -function DelWafCustomData

Function AddWafCustomRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-WafCustomRuleSet"
}
Export-ModuleMember -function AddWafCustomRule

Function DelWafCustomRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Filename,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Uninstall-WafCustomRuleSet"
}
Export-ModuleMember -function DelWafCustomRule

Function DownloadWafCustomRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RuleSetName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Export-WafCustomRuleSet"
}
Export-ModuleMember -function DownloadWafCustomRule

Function EnableWafRemoteLogging
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$RemoteURI,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Username,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Passwd,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Enable-WafRemoteLogging"
}
Export-ModuleMember -function EnableWafRemoteLogging
	
Function DisableWafRemoteLogging
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Disable-WafRemoteLogging"
}
Export-ModuleMember -function DisableWafRemoteLogging

Function ListWafAuditFiles
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-WafAuditFiles"
}
Export-ModuleMember -function ListWafAuditFiles

Function DownloadWafAuditLog
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$AuditFile,

		[string]$Filter,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Export-WafAuditLog"
}
Export-ModuleMember -function DownloadWafAuditLog

Function GetWafChangeLog
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Export-WafChangeLog"
}
Export-ModuleMember -function GetWafChangeLog

Function ManInstallWafRules
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Install-WafRulesDatabase"
}
Export-ModuleMember -function ManInstallWafRules

Function DownloadWafRules
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Update-WafRulesDatabase"
}
Export-ModuleMember -function DownloadWafRules

Function GetWafSettings
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-WafRulesAutoUpdateConfiguration"
}
Export-ModuleMember -function GetWafSettings
# ==================================================
# endregion WAF
# ==================================================


# ==================================================
# region GEO
# ==================================================
Function AddFQDN
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-GeoFQDN"
}
Export-ModuleMember -function AddFQDN

Function Add-GeoFQDN
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-GeoFQDN"
}
Export-ModuleMember -function Add-GeoFQDN

Function DeleteFQDN
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoFQDN"
}
Export-ModuleMember -function DeleteFQDN

Function ListFQDNs
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoFQDN"
}
Export-ModuleMember -function ListFQDNs

Function ModifyFQDN
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[ValidateSet("RoundRobin", "WeightedRoundRobin", "FixedWeighting", "RealServerLoad", "Proximity", "LocationBased", "AllAvailable")]
		[String]$SelectionCriteria,

		[ValidateRange(0, 1440)]
		[Int32]$SiteFailureDelay = -1,

		[ValidateSet("auto", "manual")]
		[String]$SiteRecoveryMode,

		[ValidateSet("PublicSitesOnly", "PreferPublicSites", "PreferPrivateSites", "AllSites")]
		[string]$PublicRequest,

		[ValidateSet("PrivateSitesOnly", "PreferPrivateSites", "PreferPublicSites", "AllSites")]
		[string]$PrivateRequest,

		[String]$Failover,

		[bool]$LocalSettings,

		[ValidateRange(1, 86400)]
		[Int32]$localttl,

		[ValidateRange(0, 86400)]
		[Int32]$localsticky,

		[bool]$UnanimousChecks,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoFQDN"
}
Export-ModuleMember -function ModifyFQDN

Function AddCluster
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ClusterIp,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ClusterName,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-GeoCluster"
}
Export-ModuleMember -function AddCluster

Function DeleteCluster
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ClusterIp,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoCluster"
}
Export-ModuleMember -function DeleteCluster

Function Get-GeoCluster
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$ClusterIp,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoCluster"
}
Export-ModuleMember -function ListClusters

Function ShowCluster
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$ClusterIp,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoCluster"
}
Export-ModuleMember -function ShowCluster

Function ModifyCluster
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ClusterIp,

		[String]$ClusterName,

		[ValidateSet("default", "remoteLM", "localLM")]
		[String]$Type,

		[ValidateSet("none", "tcp", "icmp")]
		[String]$Checker,

		[Int32]$CheckerPort,

		[String]$Enable,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoCluster"
}
Export-ModuleMember -function ModifyCluster

Function ClusterChangeLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ClusterIp,

		[Parameter(Mandatory=$true)]
		[Int32]$LatSecs,

		[Parameter(Mandatory=$true)]
		[Int32]$LongSecs,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoClusterCoordinates"
}
Export-ModuleMember -function ClusterChangeLocation

Function AddMap
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[string]$Cluster,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-GeoFQDNSiteAddress"
}
Export-ModuleMember -function AddMap

Function DeleteMap
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoFQDNSiteAddress"
}
Export-ModuleMember -function DeleteMap

Function ModifyMap
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[ValidateSet("None", "Icmp Ping", "Tcp Connect", "Cluster Checks")]
		[String]$Checker,

		[Int32]$Weight,

		[String]$Enable,

		[String]$Cluster,

		[String]$Mapaddress,

		[String]$Mapport,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoFQDNSiteAddress"
}
Export-ModuleMember -function ModifyMap

Function ChangeCheckerAddr
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$CheckerIP,

		[Parameter(Mandatory=$true,Position=3)]
		[ValidateNotNullOrEmpty()]
		[String]$CheckerPort,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoFQDNSiteCheckerAddress"
}
Export-ModuleMember -function ChangeCheckerAddr

Function AddCountry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,	# was IP

		[ValidateNotNullOrEmpty()]
		[String]$CountryCode,

		[ValidateNotNullOrEmpty()]
		[String]$IsContinent,

		[ValidateNotNullOrEmpty()]
		[String]$CustomLocation,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoFQDNSiteCountry"
}
Export-ModuleMember -function AddCountry

Function RemoveCountry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[ValidateNotNullOrEmpty()]
		[String]$CountryCode,

		[ValidateNotNullOrEmpty()]
		[String]$IsContinent,

		[ValidateNotNullOrEmpty()]
		[String]$CustomLocation,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoFQDNSiteCountry"
}
Export-ModuleMember -function RemoveCountry

Function ChangeMapLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[Parameter(Mandatory=$true)]
		[Int32]$Lat,

		[Parameter(Mandatory=$true)]
		[Int32]$Long,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoFQDNSiteCoordinates"
}
Export-ModuleMember -function ChangeMapLocation

Function AddCustomLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Location,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-GeoCustomLocation"
}
Export-ModuleMember -function AddCustomLocation

Function DeleteCustomLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Location,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoCustomLocation"
}
Export-ModuleMember -function DeleteCustomLocation

Function ListCustomLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoCustomLocation"
}
Export-ModuleMember -function ListCustomLocation

Function EditCustomLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$clOldName,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$clNewName,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoCustomLocation"
}
Export-ModuleMember -function EditCustomLocation

Function AddIP
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-GeoIpRange"
}
Export-ModuleMember -function AddIP

Function DeleteIP
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoIpRange"
}
Export-ModuleMember -function DeleteIP

Function ShowIP
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoIpRange"
}
Export-ModuleMember -function ShowIP

Function ListIPs
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoIpRange"
}
Export-ModuleMember -function ListIPs

Function ModifyIPLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[Parameter(Mandatory=$true)]
		[Int32]$Lat,

		[Parameter(Mandatory=$true)]
		[Int32]$Long,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoIPRangeCoordinates"
}
Export-ModuleMember -function ModifyIPLocation

Function DeleteIPLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoIPRangeCoordinates"
}
Export-ModuleMember -function DeleteIPLocation

Function AddIPCountry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[Parameter(Mandatory=$true)]
		[String]$CountryCode,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoIPRangeCountry"
}
Export-ModuleMember -function AddIPCountry

Function RemoveIPCountryCustom
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoIPRangeCountry"
}
Export-ModuleMember -function RemoveIPCountryCustom 

Function Remove-GeoIPRangeCustomLocation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoIPRangeCountry"
}
Export-ModuleMember -function Remove-GeoIPRangeCustomLocation

Function RemoveIPCountry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-GeoIPRangeCountry"
}
Export-ModuleMember -function RemoveIPCountry 

Function AddIPCountryCustom
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IP,

		[Parameter(Mandatory=$true)]
		[String]$CustomLoc,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoIPRangeCustomLocation"
}
Export-ModuleMember -function AddIPCountryCustom

Function ListMiscParameters
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-GeoMiscParameter"
}
Export-ModuleMember -function ListMiscParameters

Function ModifyMiscParameters
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[String]$SourceOfAuthority,
		[String]$NameSrv,
		[String]$SOAEmail,
		[String]$TTL,
		[String]$Persist,
		[String]$CheckInterval,
		[String]$ConnTimeout,
		[String]$RetryAttempts,
		[String]$Zone,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-GeoMiscParameter"
}
Export-ModuleMember -function ModifyMiscParameters

Function LocationDataUpdate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Update-GeoDatabase"
}
Export-ModuleMember -function LocationDataUpdate

Function EnableGEO
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Update-GeoDatabase"
}
Export-ModuleMember -function EnableGEO

Function DisableGEO
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,
		
		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Disable-LmGeoPack"
}
Export-ModuleMember -function DisableGEO

Function IsGEOEnabled
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Disable-LmGeoPack"
}
Export-ModuleMember -function IsGEOEnabled
# ==================================================
# endregion GEO
# ==================================================


# ==================================================
# region BACKUP
# ==================================================
Function Backup-LoadBalancer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,
		[switch]$Force,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Backup-LmConfiguration"
}
Export-ModuleMember -function Backup-LoadBalancer

Function Restore-LoadBalancer
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateSet("Base", "Base + VS", "Base + Geo", "VS", "VS + Geo", "Geo", "SSO/LDAP", "All")]
		[string]$Type,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Restore-LmConfiguration"
}
Export-ModuleMember -function Restore-LoadBalancer

Function Get-BackupOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmBackupConfiguration"
}
Export-ModuleMember -function Get-BackupOption

Function Set-BackupOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateSet("yes", "no")]
		[string]$BackupEnable,

		[ValidateRange(0, 23)]
		[Int16]$BackupHour,

		[ValidateRange(0, 59)]
		[Int16]$BackupMinute,

		[ValidateRange(0, 7)]
		[Int16]$BackupDay,

		[ValidateSet("Ftp", "SCP")]
		[string]$BackupMethod,

		[string]$BackupUser,

		[string]$BackupPassword,

		[string]$BackupHost,

		[string]$BackupPath,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmBackupConfiguration"
}
Export-ModuleMember -function Set-BackupOption
# ==================================================
# endregion BACKUP
# ==================================================


# ==================================================
# region VPN
# ==================================================
Function CreateVpnConnection
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-LmVpnConnection"
}
Export-ModuleMember -function CreateVpnConnection

Function DeleteVpnConnection
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-LmVpnConnection"
}
Export-ModuleMember -function DeleteVpnConnection

Function ListVpns
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmVpnConnection"
}
Export-ModuleMember -function ListVpns

Function SetVpnAddrs
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalIp,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalSubnets,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteIp,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteSubnets,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnAddrs"
}
Export-ModuleMember -function SetVpnAddrs

Function SetVpnLocalIp
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalIp,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnLocalIp"
}
Export-ModuleMember -function SetVpnLocalIp

Function SetVpnLocalSubnets
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalSubnets,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnLocalIp"
}
Export-ModuleMember -function SetVpnLocalSubnets

Function SetVpnRemoteIp
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteIp,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnRemoteIp"
}
Export-ModuleMember -function SetVpnRemoteIp

Function SetVpnRemoteSubnets
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteSubnets,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnRemoteSubnet"
}
Export-ModuleMember -function SetVpnRemoteSubnets

Function SetVpnSecret
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LocalId,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RemoteId,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Key,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnSecret"
}
Export-ModuleMember -function SetVpnSecret

Function StartVpnConnection
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Start-LmVpnConnection"
}
Export-ModuleMember -function StartVpnConnection

Function StopVpnConnection
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Stop-LmVpnConnection"
}
Export-ModuleMember -function StopVpnConnection

Function StartIkeDaemon
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Start-LmVpnIkeDaemon"
}
Export-ModuleMember -function StartIkeDaemon

Function StopIkeDaemon
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Stop-LmVpnIkeDaemon"
}
Export-ModuleMember -function StopIkeDaemon

Function StatusIkeDaemon
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmVpnIkeDaemonStatus"
}
Export-ModuleMember -function StatusIkeDaemon

Function SetVpnPfsEnable
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnPfsEnable"
}
Export-ModuleMember -function SetVpnPfsEnable

Function SetVpnPfsDisable
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()] 
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmVpnPfsDisable"
}
Export-ModuleMember -function SetVpnPfsDisable
# ==================================================
# endregion VPN
# ==================================================


# ==================================================
# region ADDON
# ==================================================
Function UploadAddon
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Install-LmAddon"
}
Export-ModuleMember -function UploadAddon

Function DeleteAddon
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-LmAddon"
}
Export-ModuleMember -function DeleteAddon

Function ListAddons
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmAddOn"
}
Export-ModuleMember -function ListAddons
# ==================================================
# endregion ADDON
# ==================================================


# ==================================================
# region PATCH
# ==================================================
Function Install-Patch
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Install-LmPatch"
}
Export-ModuleMember -function Install-Patch

Function Restore-Patch
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Uninstall-LmPatch"
}
Export-ModuleMember -function Restore-Patch

Function Restart-LoadBalancer
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Shutdown,
		[switch]$Force,
		[int]$SleepTime,
		[int]$Cycles
	)
	Write-Output "$warning Restart-Lm"
}
Export-ModuleMember -function Restart-LoadBalancer
# ==================================================
# endregion PATCH
# ==================================================


# ==================================================
# region DATE-TIME
# ==================================================
Function Get-DateTimeOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmDateTimeConfiguration"
}
Export-ModuleMember -function Get-DateTimeOption

Function Set-DateTimeOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$NTPHost,

		[string]$TimeZone,

		[ValidateRange(1, 100)]
		[int]$NTPKeyId,

		[string]$NTPKeySecret,

		[ValidateSet("SHA-1", "MD5")]
		[string]$NTPKeyType,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmDateTimeConfiguration"
}
Export-ModuleMember -function Set-DateTimeOption
# ==================================================
# endregion DATE-TIME
# ==================================================


# ==================================================
# region SDN
# ==================================================
Function AddSDNController
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$IPV4,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$Port,

		[Int32]$Clid,

		[Boolean]$Https,

		[String]$User,

		[String]$Password,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-SdnController"
}
Export-ModuleMember -function AddSDNController

Function DeleteSDNController
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Int32]$Clid,

		[Int32]$Cid,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-SdnController"
}
Export-ModuleMember -function DeleteSDNController

Function ModifySDNController
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$Cid,

		[Int32]$Clid,

		[String]$IPV4,

		[Int32]$Port,

		[Boolean]$Https,

		[String]$User,

		[String]$Password,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-SdnController"
}
Export-ModuleMember -function ModifySDNController

Function GetSDNController
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-SdnController"
}
Export-ModuleMember -function GetSDNController
# ==================================================
# endregion SDN
# ==================================================


# ==================================================
# region AFE
# ==================================================
Function Get-AFEConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmAFEConfiguration"
}
Export-ModuleMember -function Get-AFEConfiguration

Function Set-AFEConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateRange(1, 409)]
		[Int]$CacheSize,

		[bool]$HostCache,

		[ValidateSet("Low - Only logging, no rejection", "Default - Only Critical problems are rejected", "High - Serious and Critical problems are rejected", "Paranoid - All problems detected are rejected")]
		[string]$DetectionLevel,

		[ValidateRange(0, 100000)]
		[Int64]$LimitInput,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmAFEConfiguration"
}
Export-ModuleMember -function Set-AFEConfiguration

Function Update-IDSRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateScript({Test-Path -Path $_})]
		[ValidateNotNullOrEmpty()]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Update-AFEIDSRules"
}
Export-ModuleMember -function Update-IDSRule
# ==================================================
# endregion AFE
# ==================================================


# ==================================================
# region CONNLIMIT
# ==================================================
Function AfeClientLimitList
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmIPConnectionLimit"
}
Export-ModuleMember -function AfeClientLimitList

Function AfeClientLimitAdd
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$L7addr,

		[Parameter(Mandatory=$true)]
		[int32]$L7limit,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-LmIPConnectionLimit"
}
Export-ModuleMember -function AfeClientLimitAdd

Function AfeClientLimitDelete
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$L7addr,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-LmIPConnectionLimit"
}
Export-ModuleMember -function AfeClientLimitDelete
# ==================================================
# endregion CONNLIMIT
# ==================================================


# ==================================================
# region CLUSTER
# ==================================================
Function Get-HAOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmHAConfiguration"
}
Export-ModuleMember -function Get-HAOption

Function Set-HAOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateSet(3, 6, 9, 12, 15)]
		[Int16]$hatimeout,

		[ValidateRange(0, 180)]
		[Int16]$hawait,

		[ValidateRange(1, 255)]
		[Int16]$havhid,

		[ValidateSet("No Preferred Host", "Prefer First HA", "Prefer Second HA")]
		[string]$haprefered,

		[Int16]$haif,

		[bool]$hal4update,

		[bool]$hal7update,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmHAConfiguration"
}
Export-ModuleMember -function Set-HAOption

Function Set-AzureHAMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("master", "slave", "single")]
		[string]$HAMode,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmAzureHAMode"
}
Export-ModuleMember -function Set-AzureHAMode

Function Get-AzureHAOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmAzureHAConfiguration"
}
Export-ModuleMember -function Get-AzureHAOption

Function Set-AzureHAOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$Partner,

		[ValidateNotNullOrEmpty()]
		[string]$Hcp,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, 1)]
		[int]$haprefered,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmAzureHAConfiguration"
}
Export-ModuleMember -function Set-AzureHAOption

Function Set-AwsHAMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("master", "slave", "single")]
		[string]$HAMode,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmAwsHAMode"
}
Export-ModuleMember -function Set-AwsHAMode

Function Get-AwsHAOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmAwsHAConfiguration"
}
Export-ModuleMember -function Get-AwsHAOption

Function Set-AwsHAOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$Partner,

		[ValidateNotNullOrEmpty()]
		[string]$HealthCheckPort,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, 1)]
		[int]$haprefered,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmAwsHAConfiguration"
}
Export-ModuleMember -function Set-AwsHAOption
# ==================================================
# endregion CLUSTER
# ==================================================


# ==================================================
# region DIAGNOSTIC
# ==================================================
Function Get-DebugOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-LmDebugConfiguration"
}
Export-ModuleMember -function Get-DebugOption

Function Set-DebugOption
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$transparent,

		[bool]$irqbalance,

		[bool]$linearesplogs,

		[string]$netconsole,

		[Int16]$netconsoleinterface,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Set-LmDebugConfiguration"
}
Export-ModuleMember -function Set-DebugOption

Function DoTcpDump
{
	[cmdletbinding(SupportsShouldProcess=$true, DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1, 200000)]
		[int]$MaxPackets,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(1, 600)]
		[int]$MaxTime,

		[ValidateNotNullOrEmpty()]
		[string]$Interface,

		[ValidateNotNullOrEmpty()]
		[string]$Port,

		[ValidateNotNullOrEmpty()]
		[string]$Address,

		[ValidateNotNullOrEmpty()]
		[string]$TcpOptions,

		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN,

		[switch]$Force
	)
	Write-Output "$warning Trace-TcpTraffic"
}
Export-ModuleMember -function DoTcpDump
# ==================================================
# endregion DIAGNOSTIC
# ==================================================


# ==================================================
# region N+M
# ==================================================
Function NMClusterStatus
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Get-ClusterStatus"
}
Export-ModuleMember -function NMClusterStatus

Function NMClusterCreate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SharedAddress,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-Cluster"
}
Export-ModuleMember -function NMClusterCreate

Function NMAddNode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning New-ClusterNode"
}
Export-ModuleMember -function NMAddNode

Function NMJoinCluster
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Join-Cluster"
}
Export-ModuleMember -function NMJoinCluster

Function NMEnableNode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$NodeId,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Enable-ClusterNode"
}
Export-ModuleMember -function NMEnableNode

Function NMDisableNode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$NodeId,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Disable-ClusterNode"
}
Export-ModuleMember -function NMDisableNode

Function NMDeleteNode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$NodeId,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[Parameter(ParameterSetName="Credential")]
			[ValidateNotNullOrEmpty()]
			[System.Management.Automation.Credential()]$Credential = $script:cred,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[Parameter(ParameterSetName="Certificate")]
			[ValidateNotNullOrEmpty()]
			[String]$SubjectCN = $script:SubjectCN
	)
	Write-Output "$warning Remove-ClusterNode"
}
Export-ModuleMember -function NMDeleteNode
# ==================================================
# endregion N+M
# ==================================================

# SIG # Begin signature block
# MIIcDQYJKoZIhvcNAQcCoIIb/jCCG/oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDproCmbHORq7dN
# rCvi71htoutFNbUcZ1oxnmMNGCABJaCCCuMwggVWMIIEPqADAgECAhAZGjLLdZyX
# uM+sEY3VEn9JMA0GCSqGSIb3DQEBCwUAMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdv
# cmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhv
# cml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGlj
# IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0xNDAzMDQw
# MDAwMDBaFw0yNDAzMDMyMzU5NTlaMIGRMQswCQYDVQQGEwJVUzEdMBsGA1UEChMU
# U3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5l
# dHdvcmsxQjBABgNVBAMTOVN5bWFudGVjIENsYXNzIDMgRXh0ZW5kZWQgVmFsaWRh
# dGlvbiBDb2RlIFNpZ25pbmcgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBANAYAu7too0IWGMPJtfdInuI9uTH7DsmGHjTx6QgU42DfKU/fqXI
# K0ffDfWm2cMdJZNgz3zc6gMsvnh/XEhtpwLZSfih6+uaYXyfwCbW3BXYuBB8ILpe
# 9Cj2qOqnXHzGnJCQNDy2Iqz+ugw6HtZehLZb8KOBcHiKjUZSe/zbSfMpExF0T40W
# s8LjoC3HAwSdzMNy4Q4M+wKO8SYXe26u+Lczi6ZhS0Xf8iVEx/ewmCM23Ch5Cuib
# coio2Oiue38KZEWl8FeSmncGRR7rn+hm83p9koFfAC0euPZWE1piDbdHoY9y74Ne
# guCUmOGspa2GN+Cn07qxPnrrRajxwUR94gMCAwEAAaOCAW0wggFpMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL3Muc3ltY2IuY29t
# L3BjYTMtZzUuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQE
# AwIBBjAuBggrBgEFBQcBAQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNk
# LmNvbTBfBgNVHSAEWDBWMFQGBFUdIAAwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9k
# LnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNv
# bS9ycGEwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJLTEtNjI5
# MB0GA1UdDgQWBBQWZt5KNONQpxGGA7FsqcaszVlumzAfBgNVHSMEGDAWgBR/02Wn
# wt3su/AwCfNDOfoCrzMxMzANBgkqhkiG9w0BAQsFAAOCAQEAP1sZ8/oT1XU4Klru
# n1qgTKkdxcyU7t4V/vUQbqQbpWSDVBhYxAsooYXDTnTl/4l8/tXtPLpxn1YCJo8W
# Koj+sKMnIs5L4jiOAKY6hl+d5T6o3mRJQXRBIf0HyIQX2h1lMILLJk851gQnpIGx
# S0nDI4t+AjIYJ7erC/MYcrak7mcGbzimWI3g8X5dpGDGqOVQX+DouuKPmVi2taCo
# dvGi8RyIQXJ+UpebCjaZjVD3Aes85/AiauU1jGM2ihqx2WdmX5ca76ggnfAvumzO
# 2ZSFAPFY8X3JfCK1B10CxuYLv6uTk/8nGI4zNn5XNPHDrwTBhPFWs+iHgzb40wox
# 3G4sbTCCBYUwggRtoAMCAQICECeDjyzMAJ09C7Adbyi1uUkwDQYJKoZIhvcNAQEL
# BQAwgZExCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlv
# bjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazFCMEAGA1UEAxM5U3lt
# YW50ZWMgQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIENvZGUgU2lnbmluZyBD
# QSAtIEcyMB4XDTE2MTAwNTAwMDAwMFoXDTE3MTAwNTIzNTk1OVowgdYxEzARBgsr
# BgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVsYXdhcmUxHTAbBgNV
# BA8TFFByaXZhdGUgT3JnYW5pemF0aW9uMRAwDgYDVQQFEwc1MDg0MDMyMQswCQYD
# VQQGEwJVUzERMA8GA1UECAwITmV3IFlvcmsxETAPBgNVBAcMCE5ldyBZb3JrMR8w
# HQYDVQQKDBZLRU1QIFRlY2hub2xvZ2llcyBJbmMuMR8wHQYDVQQDDBZLRU1QIFRl
# Y2hub2xvZ2llcyBJbmMuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# zUcerldV4VKZ+xPtYfy3/HwbSLJu8HS2urs4QUEF41PJYl50P/+ePYKpuOcksc2l
# n45YO5/zrKTcjgzxMxJhrNDDAelPeZjiDlkidj6a79msxMXjRzIAI8A4b5SpKBKc
# 7GVANCt0HZlEWjYegiaVjA6fRJFTRuJVr+K1fc1M79mgARNPCLOuy21N7d+MNvOl
# nfBlvRGJZC2CQeeXHjhh/q8RdPmVqXliG8zkIIX+wq+kyVSO1ngYsDJZ4iMmjpCA
# QzdT564zK8potK4fjPblYDiiEtUR1wGg6g4l2X18Mci21of4RbWBKQ/hxQm6oprA
# XBraFsYnwwwt8QSl9+UtmQIDAQABo4IBkDCCAYwwLgYDVR0RBCcwJaAjBggrBgEF
# BQcIA6AXMBUME1VTLURFTEFXQVJFLTUwODQwMzIwCQYDVR0TBAIwADAOBgNVHQ8B
# Af8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N3LnN5bWNiLmNvbS9z
# dy5jcmwwYAYDVR0gBFkwVzBVBgVngQwBAzBMMCMGCCsGAQUFBwIBFhdodHRwczov
# L2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZDBdodHRwczovL2Quc3ltY2Iu
# Y29tL3JwYTAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAWgBQWZt5K
# NONQpxGGA7FsqcaszVlumzAdBgNVHQ4EFgQUu/UpUEJhq9Dx+3CC/n6LPC3FyRYw
# WAYIKwYBBQUHAQEETDBKMB8GCCsGAQUFBzABhhNodHRwOi8vc3cuc3ltY2QuY29t
# MCcGCCsGAQUFBzAChhtodHRwOi8vc3cxLnN5bWNiLmNvbS9zdy5jcnQwDQYJKoZI
# hvcNAQELBQADggEBAF/gxzrK67CSW740OGSXAC4/NzRVcP5RmONNEXIjmYEowtgN
# UtXAns9olC+uzborP1Pq7MvZKMC0CW5P8GsloeqVGjRQ2IPFiEvLAagQO5HVzDMA
# NZeuTNS5At5i+MkqkW+sLoVH+tBVDhbn17sH2mX0wXid4NCOojyVA1FarE0gup+v
# XjhwBlXQPRU2K49cmd6dryN1GGufmiXJC25fggZ+2lc0A+j1mBfN9lsMVe7ZYgvW
# o1WyWM/K66ga8FC9MIpv2tzVQc5Oy0UysQtnHykfRuAA5yXHaiXejx2uF5/5LWR1
# s53Zchz0LXsZ+ndn4Utg0e2T9iRyuW7Sw7jek4sxghCAMIIQfAIBATCBpjCBkTEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYD
# VQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMUIwQAYDVQQDEzlTeW1hbnRlYyBD
# bGFzcyAzIEV4dGVuZGVkIFZhbGlkYXRpb24gQ29kZSBTaWduaW5nIENBIC0gRzIC
# ECeDjyzMAJ09C7Adbyi1uUkwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEM
# MQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgTWpulaW38EfEXNeVA1fN7aFp
# SKe1UWvCrZzj5nHvoBIwDQYJKoZIhvcNAQEBBQAEggEAa+FCIrOPR8sC+zW/IcXY
# 0xRkJTlKobcyIXBSH0UMIWNRVuBYwxeBRGxiqiz5KAQctQn4otz7K+aCkBo/Am2S
# cFuLkVKdhHQwpFWykuEtApgd1GG1jE1aCAZ2g2TTwzjnQDtg9Eah60MpzJe6xr4Q
# WyDqbclITMgq8vtVkvRSrmFF3i5FjZpQUL2P2uBD62X9aSrsmbo1GVHIGk6+hrwZ
# Px2hLlWJmrnKWa499kxH3Vroy9i6x5rSzSqjnDO+pPBrSCputzbFmW5e5CFVB1qh
# f9fFmA8SxRoq/peUU/ZuBn2y95U89ELMg7e48dc60T9BBShw4034J02IxkD6iliz
# aqGCDiwwgg4oBgorBgEEAYI3AwMBMYIOGDCCDhQGCSqGSIb3DQEHAqCCDgUwgg4B
# AgEDMQ0wCwYJYIZIAWUDBAIBMIH/BgsqhkiG9w0BCRABBKCB7wSB7DCB6QIBAQYL
# YIZIAYb4RQEHFwMwITAJBgUrDgMCGgUABBQxGASFalxI+VWDHJNvgB4WzOE3jQIV
# APgqvBCcWXGiLkinDGW+Q62VwJNrGA8yMDE3MDYwMjE3MTIyOVowAwIBHqCBhqSB
# gzCBgDELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u
# MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1h
# bnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIFNpZ25lciAtIEcyoIIKizCCBTgwggQg
# oAMCAQICEHsFsdRJaFFE98mJ0pwZnRIwDQYJKoZIhvcNAQELBQAwgb0xCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNp
# Z24gVHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIElu
# Yy4gLSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24g
# VW5pdmVyc2FsIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEy
# MDAwMDAwWhcNMzEwMTExMjM1OTU5WjB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMU
# U3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5l
# dHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0Ew
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61Xz
# sAGtPHGsMo8Fa4aaJwAyl2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/
# Xm1AONSRBudBfHkcy8utG7/YlZHz8O5s+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q
# 0pi1Oh8eOZ3D9Jqo9IThxNF8ccYGKbQ/5IMNJsN7CD5N+Qq3M0n/yjvU9bKbS+GI
# mRr1wOkzFNbfx4Dbke7+vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1
# inisGTKPI8EyQRtZDqk+scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3
# AgMBAAGjggF3MIIBczAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
# ADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBz
# Oi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1j
# Yi5jb20vcnBhMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Mu
# c3ltY2QuY29tMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91
# bml2ZXJzYWwtcm9vdC5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEw
# H6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqj
# ToVy4Ke8QfMpojh/gHViMB8GA1UdIwQYMBaAFLZ3+mlIR59TEtXC6gcydgfRlwcZ
# MA0GCSqGSIb3DQEBCwUAA4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociB
# iPenjxXmQCmt5l30otlWZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7
# zJAv1gpsTjPs1rSTyEyQY0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzK
# EHhsQm7wtsX4YVxS9U72a433Snq+8839A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gG
# V+HGDvbor9rsmxgfqrnjOgC/zoqUywHbnsc4uw9Sq9HjlANgCk2g/idtFDL8P5dA
# 4b+ZidvkORS92uTTw+orWrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIB
# AgIQVFjyqtdB1kS8hKl7oJZS5jANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFu
# dGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0EwHhcNMTcwMTAyMDAwMDAwWhcNMjgwNDAxMjM1OTU5WjCBgDEL
# MAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYD
# VQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBT
# SEEyNTYgVGltZVN0YW1waW5nIFNpZ25lciAtIEcyMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAmfP82AQJA4b511ymk8BCfOp8Y89dAOKO88CQ348p9Rjq
# lLeS5dewoHOB6OkKm0p8Af+dj6Q5pw7qRfQiDDpw7TlFi+TFG1zwRWhGJAVjdpsc
# /J5sKrFW5Yp/UnGu8jXVRiMGHM9ILR20zbjZdiOOHP8+v7sGXGkHpmUO+F6ufS7t
# Ta4178nXAEL9KJUOn11yQgm8w9pE0u3MR4Tk/MotrFi+rveu2UQNCLfCd9YaQ3DR
# bgPeUpLEEAhx2boiVfIfvO2bnTviXh1Mg/+XD3sL51WDTtIN677X7K5uR7mf36XW
# UbwEVe3/J3BMye0qSxPhsblMD8kB7lVlX2kCeGbLPwIDAQABo4IBxzCCAcMwDAYD
# VR0TAQH/BAIwADBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBz
# Oi8vZC5zeW1jYi5jb20vcnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1j
# cmwud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDB3BggrBgEFBQcBAQRrMGkwKgYI
# KwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA7BggrBgEF
# BQcwAoYvaHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1j
# YS5jZXIwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTUw
# HQYDVR0OBBYEFAm1wf6WcpcpQ5rJ4AK6rvj9L7r2MB8GA1UdIwQYMBaAFK9j1sqj
# ToVy4Ke8QfMpojh/gHViMA0GCSqGSIb3DQEBCwUAA4IBAQAXswqI6VxaXiBrOwoV
# smzFqYoyh9Ox9BxTroW+P5v/17y3lIW0x1J+lOi97WGy1KeZ5MPJk8E1PQvoaApd
# Vpi9sSI70UR617/wbVEyitUj3zgBN/biUyt6KxGPt01sejMDG3xrCZQXu+TbWNQh
# E2Xn7NElyix1mpx//Mm7KmirxH20z6PJbKfZxACciQp3kfRNovsxO4Zu9uYfUAOG
# m7/LQqvmdptyWhEBisbvpW+V592uuuYiZfAYWRsRyc2At9iXRx9CCPiscR+wRlOz
# 1LLVo6tQdUgSF4Ktz+BBTzJ+zZUcv5GKCD2kp2cClt8kTKXQQcCCYKOKFzJL07zP
# pLSMMYICWjCCAlYCAQEwgYswdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFu
# dGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3Jr
# MSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhBUWPKq
# 10HWRLyEqXugllLmMAsGCWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTE3MDYwMjE3MTIyOVowLwYJKoZIhvcN
# AQkEMSIEIOw2a6U50/47tGXS4vTeEw645pE3ZGClFmSZdIAZBwjpMDcGCyqGSIb3
# DQEJEAIvMSgwJjAkMCIEIM96wXrQR+zV/cNoIgMbEtTvB4tvK0xea6Qfj/LPS61n
# MAsGCSqGSIb3DQEBAQSCAQB6HE9H+Hy0EB+bAyTu3NlzLqTMMpcpBSroC+ntHCDh
# uBTmbn8qPjSqQRRTFLXvHH5kuVzUseHX2LOhADDOze29Nh2H8ibzRnFap3aGOy6n
# nyb1vcumA7OT8GdXCJhEXo2uBBOvAA4qozxiv40tGb9VR1jtjO3WckhxOUg3KXnY
# CVx/4HD4+yutxhLQ/Z7L2Q4zDxVjArjoW0vFX1sr6eNfWEQ776x9zym/7hi3rzAG
# vvn5yqtAMBmv1yIssa+YAFHQCfRWTq7CZmpifXJQweH8AXkPycBSloUpqklpNPUA
# ydgpD7Wy2KWu8OrLCehNdotebYawEkpYo2AnyDM+l9D3
# SIG # End signature block
