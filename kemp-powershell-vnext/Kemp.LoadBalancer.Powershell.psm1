#
# $Id: Kemp.LoadBalancer.Powershell.psm1 20682 2021-04-21 06:46:56Z spower $
#

$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path
Import-Module $ScriptDir\deprecated.psm1

####################
# MODULE VARIABLES #
####################
[System.Reflection.Assembly]::LoadWithPartialName("system.web") | Out-Null

New-Variable -Name LoadBalancerAddress -Scope Script -Force
New-Variable -Name LBAccessPort -Scope Script -Force -Value 443

New-Variable -Name Cred -Scope Script -Force

New-Variable -Name SubjectCN -Scope Script -Force
New-Variable -Name CertificateStoreLocation -Scope Script -Force -Value $null

$IgnoredParameters = @("Verbose", "Debug", "WarningAction", "WarningVariable", "ErrorAction",
  "ErrorVariable", "OutVariable", "OutBuffer", "WhatIf", "Confirm", "RuleType",
  "LoadBalancer", "LBPort", "Credential", "SubjectCN", "CertificateStoreLocation")

$ParamReplacement = @{VSIndex = "vs"; VirtualService = "vs"; Protocol = "prot"; VSProtocol = "prot"; VSPort = "port";
	RSIndex = "rs"; RealServer = "rs"; RealServerPort = "rsport";
	RuleName = "rule";
	InterfaceID = "iface"; IPAddress = "addr";
	NameServer = "nameserver"; NamServer = "namserver";
	HAMode = "hamode"; Partner = 'partner'; Hcp = "hcp";
	Location = "location"; GeoTraffic = "geotraffic"; Mapaddress = "mapaddress"; Mapport = "mapport"; Cluster = "clust";
	KempId = "kempid"; Password = "password"; OrderId = "orderid";
	ConnectTimeout = "timeout";
	WuiNetworkInterfaceId = "wuiiface"; WuiPort = "wuiport"; WuiDefaultGateway = "wuidefaultgateway";
	CurrentPassword = "currpassword"; NewPassword = "password";
	Permissions = "perms";
	SyslogPort = "syslogport";
	StatisticsDisplaySize = "wuidisplaylines";
	ClusterIp = "IP"; ClusterName = "Name";
	SiteAddress = "IP";
	HostIP = "hostip"; HostFQDN = "hostfqdn";
	GeoInterfaceId = "geo_ssh_iface";
	ScalingOver64KConnections = "localbind"; AddPortToActiveCookie = "addcookieport"; RFCConform = "rfcconform";
	CloseOnError = "closeonerror"; AddViaHeaderInCacheResponses = "addvia"; RSAreLocal = "rsarelocal";
	DropOnRSFail = "droponfail"; DropAtDrainEnd = "dropatdrainend"; L7AuthTimeoutSecs = "authtimeout";
	L7ClientTokenTimeoutSecs = "clienttokentimeout"; L7ConnectionDrainTimeoutSecs = "finalpersist";
	AllowEmptyPosts = "allowemptyposts"; AllowEmptyHttpHeaders = "AllowEmptyHttpHeaders";
	ForceCompleteRSMatch = "ForceFullRSMatch"; SlowStart = "slowstart"; ShareSubVSPersistance = "ShareSubVSPersist";
	SSHPreAuthBanner = "SSHPreAuth"; MultiHomedWui = "multihomedwui"; AllowUpdateChecks = "tethering"; LocalBindAddresses = "localbindaddrs"}

$SystemRuleType = @{MatchContentRule=0; AddHeaderRule=1; DeleteHeaderRule=2; ReplaceHeaderRule=3; ModifyUrlRule=4; ReplaceBodyRule=5}

$loginMethodHT = @{"PasswordOnly" = 0; "PasswordOrClientCertificate" = 1; "ClientCertificateRequired" = 2; "ClientCertificateRequiredOCSP" = 3;}

$WuiCertMapHT = @{"UserPrincipalName" = 0; "Subject" = 1; "IssuerandSubject" = 2; "IssuerandSerialNumber" = 3;}

$preferredServerHT = @{"No Preferred Host" = 0; "Prefer First HA" = 1; "Prefer Second HA" = 2;}

$global:PSDefaultParameterValues = @{"Confirm-LicenseEULA:Type"="trial"}

$LmTestServerConnectionFlag = $false
# ----------------------------------------------------------------------------------------------------------------

# region - UTILITY FUNCTIONS
# Do not export these functions. Internal use only

# --------------------------------------------------------------------------------------------
# LM answer helper function
# --------------------------------------------------------------------------------------------
# Internal use only
Function GetSuccessString($lmRawAnswer)
{
	$str = $null
	if ($lmRawAnswer) {
		$sIndex = $lmRawAnswer.IndexOf("<Success>")
		if ($sIndex -ne -1) {
			$sIndex += 9
			$eIndex = $lmRawAnswer.IndexOf("</Success>") 
			$str = $lmRawAnswer.Substring($sIndex, $eIndex - $sIndex)
			return $str
		}
	}
	return $str
}

# Internal use only
Function setKempAPIReturnObject($retCode, $apiResponse, $data)
{
	$tempApiRetObj = [ordered]@{}
	$tempApiRetObj.PSTypeName = "KempAPI"
	$tempApiRetObj.ReturnCode = $retCode
	$tempApiRetObj.Response = $apiResponse
	$tempApiRetObj.Data = $data

	$kempApiRetObject = New-Object -TypeName PSObject -Prop $tempApiRetObj

	$kempApiRetObject
}

# --------------------------------------------------------------------------------------------
# LM XML answer helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function AddXmlNodeToDictionary($dictionary, $keyname, $actualValue, $newValue)
{
	if ($actualValue -is [array]) {
		$actualValue += $newValue
		$dictionary[$keyName] = $actualValue
	}
	else {
		$tmpA = @()
		$tmpA += $actualValue
		$tmpA += $newValue
		$dictionary[$keyName] = $tmpA
	}
}

# Internal use only
Function GetPSObjectFromXml($NodeInfoType, $xmlNode, $notrim)
{
	if ( ([String]::IsNullOrEmpty($xmlNode)) ) {
		return
	}

	$NodeInfo = [ordered]@{}
	$NodeInfo.PSTypeName = "$NodeInfoType"

	foreach ($item in $xmlNode.GetEnumerator()) {
		$check = $item.FirstChild.HasChildNodes
		if ($check -eq $false) {
			if ($NodeInfo.Contains($item.Name) -eq $true) {
				$kval = $NodeInfo.Get_Item($item.Name)
				if (([String]::IsNullOrEmpty($notrim))) {
					$nodeValue = $item.InnerXml -replace "`n","" -replace "`r",""
				}
				else {
					# CERTS case
					$nodeValue = $item.InnerXml
				}
				AddXmlNodeToDictionary $NodeInfo $item.Name $kval $nodeValue
			}
			else {
				if (([String]::IsNullOrEmpty($notrim))) {
					$nodeValue = $item.InnerXml -replace "`n","" -replace "`r",""
				}
				else {
					# CERTS case
					$nodeValue = $item.InnerXml
				}
				$NodeInfo.Add($item.Name, $nodeValue)
			}
		}
		else {
			$LocalNodeInfoType = $($item.LocalName)
			$childNodeData = GetPSObjectFromXml $LocalNodeInfoType $item
			if ($NodeInfo.Contains($item.LocalName) -eq $true) {
				$kval = $NodeInfo.Get_Item($item.LocalName)
				AddXmlNodeToDictionary $NodeInfo $item.LocalName $kval $childNodeData
			}
			else {
				$NodeInfo.Add($item.LocalName, $childNodeData)
			}
		}
	}
	New-Object -TypeName PSObject -Prop $NodeInfo
}

# Internal use only
Function GetPSSdnDataFromXml($NodeInfoType, $xmlNode, $notrim)
{
	if ( ([String]::IsNullOrEmpty($xmlNode)) ) {
		return
	}

	$NodeInfo = [ordered]@{}
	$NodeInfo.PSTypeName = "$NodeInfoType"

	foreach ($item in $xmlNode.GetEnumerator()) {
		$check = $item.HasChildNodes
		if ($check -eq $false) {
			if ($item.HasAttributes) {
				$attrs = $item | gm -MemberType Property | Select Name
				$NodeInfo2 = [ordered]@{}
				$NodeInfo2.PSTypeName = $item.LocalName
				foreach($a in $attrs) {
					$p = $a.Name
					if ($item.LocalName -eq "cluster" -and $a.Name -eq "id") {
						$NodeInfo2.Add("clusterid", $item.$p)
					}
					else {
						$NodeInfo2.Add($a.Name, $item.$p)
					}
				}
				$tempObj = New-Object -TypeName PSObject -Prop $NodeInfo2
				if ($NodeInfo.Contains($item.LocalName) -eq $true) {
					$kval = $NodeInfo.Get_Item($item.LocalName)
					AddXmlNodeToDictionary $NodeInfo $item.LocalName $kval $tempObj
				}
				else {
					$NodeInfo.Add($item.LocalName, $tempObj)
				}
			}
		}
		else {
			if ($item.HasAttributes) {
				$attrs = $item | gm -MemberType Property | Select Name
				$NodeInfo3 = [ordered]@{}
				$NodeInfo3.PSTypeName = $item.LocalName
				foreach($a in $attrs) {
					$p = $a.Name
					if ($a.Name -eq "id") {
						if ($item.LocalName -eq "controller") {
							$NodeInfo3.Add("controllerid", $item.$p)
						}
						else {
							$NodeInfo3.Add("clusterid", $item.$p)
						}
					}
					else {
						if ($a.Name -ne "controller") {
							$NodeInfo3.Add($a.Name, $item.$p)
						}
					}
				}
				if ($item.LocalName -eq "controller") {
					return $NodeInfo3
				}
				$childNodeData = GetPSSdnDataFromXml "controller" $item
				if ($childNodeData) {
					foreach($elem in $childNodeData.GetEnumerator()) {
						if ($elem.Name -ne "PSTypeName") {
							$NodeInfo3.Add($elem.Name, $elem.Value)
						}
					}
				}
				$tempObj = New-Object -TypeName PSObject -Prop $NodeInfo3
				if ($NodeInfo.Contains($item.LocalName) -eq $true) {
					$kval = $NodeInfo.Get_Item($item.LocalName)
					AddXmlNodeToDictionary $NodeInfo $item.LocalName $kval $tempObj
				}
				else {
					$NodeInfo.Add($item.LocalName, $tempObj)
				}
			}
		}
	}
	New-Object -TypeName PSObject -Prop $NodeInfo
}

# --------------------------------------------------------------------------------------------
# LM IP/FQDN checker functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function checkLmIpFqdn($LmIP)
{
	if ( ([String]::IsNullOrEmpty($LmIP)) ) {
		$errStr = "ERROR: Load Master IP address/FQDN is a mandatory input parameter."
		Write-Verbose $errStr
		Throw $errStr
	}
}

# Internal use only
Function validateConnectionParameters($LmIP, $LmPort)
{
	checkLmIpFqdn $LmIP

	if ($LmPort -lt 3 -or $LmPort -gt 65530) {
		$errStr = "ERROR: Load Master Port value [$LmPort] is invalid. Allowed values: 3, 65530."
		Write-Verbose $errStr
		Throw $errStr
	}
}

# --------------------------------------------------------------------------------------------
# Login method checker functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function getCertPathFromCert($Certificate)
{
	if ($Certificate) {
			$tmp = $Certificate.PSPath.Split('::')
			$tpath = "Cert:\" + $tmp[2]
			$idx = $tpath.LastIndexOf('\')
			$certPath = $tpath.Substring(0, $idx)
	}
	else {
		# It should never happen
		$errStr = "ERROR: the certificate is NULL."
		Write-Verbose $errStr
		Throw $errStr
	}
	$certPath
}

# Internal use only
Function Get-LoginCertificate($certStoreLoc, $certCN)
{
	if (([String]::IsNullOrEmpty($certStoreLoc))) {
		$certStoreLoc = "Cert:\CurrentUser\My"
	}

	if ($certCN -eq "" -or $certCN -eq $false) {
		$errStr = "ERROR: SubjectCN is NULL."
		Write-Verbose $errStr
		Throw $errStr
	}

	$certs_list = Get-ChildItem -Recurse -Path $certStoreLoc

	$found = $false
	$certificate = $null
	$location = "Cert:\"	# Certificates base dir
	foreach ($item in $certs_list) {
		$item.Subject | Where {$check = $_ -Like "*CN=$certCN, OU=support*"}
		if ($check) {
			$index = $item.PSPath.IndexOf("::")
			$location += ($item.PSPath).Substring($index + 2)
			$certificate = $item
			$found = $true
			break
		}
	}
	$certificate
}

# Internal use only
Function checkLoginMethod($Cred, $SubjectCN)
{
	if ( ([String]::IsNullOrEmpty($Cred)) -and ([String]::IsNullOrEmpty($SubjectCN)) ) {
		$errStr = "ERROR: login method param is empty. Credentials or SubjectCN must be specified."
		Write-Verbose $errStr
		Throw $errStr
	}

	if ( (-not [String]::IsNullOrEmpty($Cred)) -and (-not [String]::IsNullOrEmpty($SubjectCN)) ) {
		$errStr = "ERROR: only one login method (Credentials or SubjectCN) can be used."
		Write-Verbose $errStr
		Throw $errStr
	}
}

# Internal use only
Function validateLoginParameters($Cred, $SubjectCN, $CertLocation)
{
	checkLoginMethod $Cred $SubjectCN

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$loginCert = Get-LoginCertificate $CertLocation $SubjectCN
		if ($loginCert -ne $null) {
			$certPath = getCertPathFromCert $loginCert
		}
		else {
			if ($CertLocation) {
				$errStr = "ERROR: Can't find a certificate with `"$SubjectCN`" as CN in $CertLocation store."
				Write-Verbose $errStr
				Throw $errStr
			}
			else {
				$errStr = "ERROR: Can't find a certificate with `"$SubjectCN`" as CN in the default Cert:\CurrentUser\My store."
				Write-Verbose $errStr
				Throw $errStr
			}
		}
	}
}

# Internal use only
Function validateCommonInputParams($LmIp, $LmPort, $Credential, $SubjectCN, $CertLoc, $File, $Output, $skipLoginMethodCheck)
{
	validateConnectionParameters $LmIp $LmPort

	if (([String]::IsNullOrEmpty($skipLoginMethodCheck))) {
		validateLoginParameters $Credential $SubjectCN $CertLoc
	}

	validateFile2Upload $File $Output
	validateDownloadFileName $Output
}

# --------------------------------------------------------------------------------------------
# Get connection parameters checker functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function getConnParameters($LMaster, $LMasterPort, $LMCred, $LMLoginCert, $LMLoginCertLoc, $version)
{
	$params = [ordered]@{}

	if ($version -eq "getConnParameters_2") {
		$params.Add("LoadBalancer", $LMaster)
		$params.Add("LBPort", $LMasterPort -as [int])

		if (-not ([String]::IsNullOrEmpty($LMLoginCert))) {
			$params.Add("SubjectCN", $LMLoginCert)
			if (-not ([String]::IsNullOrEmpty($LMLoginCertLoc))) {
				$params.Add("CertificateStoreLocation", $LMLoginCertLoc)
			}
		}
		else {
			$params.Add("Credential", $LMCred)
		}
	}
	else {
		$params.Add("LmIp", $LMaster)
		$params.Add("LmPort", $LMasterPort -as [int])

		if ($LMLoginCert) {
			$params.Add("SubjectCN", $LMLoginCert)
			if ($LMLoginCertLoc) {
				$params.Add("CertLoc", $LMLoginCertLoc)
			}
		}
		else {
			$params.Add("Cred", $LMCred)
		}
	}
	return $params
}

# Internal use only
Function getConnParameters_2($LMaster, $LMasterPort, $LMCred, $LMLoginCert, $LMLoginCertLoc)
{
	getConnParameters $LMaster $LMasterPort $LMCred $LMLoginCert $LMLoginCertLoc "getConnParameters_2"
}

# --------------------------------------------------------------------------------------------
# Networking helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function checkInterface($interfaceDetails, $WuiIface)
{
	if ($interfaceDetails) {
		if ($interfaceDetails -is [array]) {
			foreach($intf in $interfaceDetails) {
				if ($intf.Id -eq $WuiIface) {
					return $true
				}
			}
		}
		else {
			if ($interfaceDetails.Id -eq $WuiIface) {
				return $true
			}
		}
	}
	return $false
}

# Internal use only
Function getCurrentIntfId($interfaceDetails, $LoadBalancer)
{
	if ($interfaceDetails) {
		if ($interfaceDetails -is [array]) {
			foreach($intf in $interfaceDetails) {
				$lmIP = $intf.IPAddress
				if ($lmIP.Contains($LoadBalancer) -eq $true) {
					return $intf.Id
				}
			}
		}
		else {
			$lmIP = $interfaceDetails.IPAddress
			if ($lmIP.Contains($LoadBalancer) -eq $true) {
				return $interfaceDetails.Id
			}
		}
	}
	return "-1"
}

# Internal use only
Function getIpFromCidrNotation($ipCidr)
{
	if ($ipCidr) {
		$sIdx = $ipCidr.IndexOf("/")
		if ($sIdx -gt 0) {
			$ip = $ipCidr.Substring(0, $sIdx)
			return $ip
		}
		else {
			Throw "ERROR: the given ip [$ipCidr] is not in CIDR notation"
		}
	}
	else {
		Throw "ERROR: NULL ip address"
	}
}

# Internal use only
Function GetLmNetworkInterface($InterfaceID, $LoadBalancer, $LBPort, $Credential, $SubjectCN, $CertSL)
{
	$params = [ordered]@{
		InterfaceID = $InterfaceID
		LoadBalancer = $LoadBalancer
		LBPort = $LBPort
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$params.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertSL))) {
			$params.Add("CertificateStoreLocation", $CertSL)
		}
	}
	else {
		$params.Add("Credential", $Credential)
	}
	Get-NetworkInterface @params
}

# Internal use only
Function SetNetworkInterfaceParam($cmd2exec, $networkParams, $ConnParams)
{
	try {
		$response = SendCmdToLm -Command "$cmd2exec" -ParameterValuePair $networkParams -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}

# --------------------------------------------------------------------------------------------
# Get/Set helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function GetLmParameter($Param, $LoadBalancer, $LBPort, $Credential, $SubjectCN, $CertSL)
{
	$params = [ordered]@{
		Param = $param
		LoadBalancer = $LoadBalancer
		LBPort = $LBPort
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$params.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertSL))) {
			$params.Add("CertificateStoreLocation", $CertSL)
		}
	}
	else {
		$params.Add("Credential", $Credential)
	}
	Get-LmParameter @params
}

# Internal use only
Function SetLmParameter($ParamName, $ParamValue, $LoadBalancer, $LBPort, $Credential, $SubjectCN, $CertSL)
{
	$params = [ordered]@{
		Param = $ParamName
		Value = $ParamValue
		LoadBalancer = $LoadBalancer
		LBPort = $LBPort
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$params.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertSL))) {
			$params.Add("CertificateStoreLocation", $CertSL)
		}
	}
	else {
		$params.Add("Credential", $Credential)
	}
	Set-LmParameter @params
}

# Internal use only
Function GetLmParameterSet($queryParams, $objectPSName, $lmInputParams)
{
	$configContainer = [ordered]@{}
	$configContainer.PSTypeName = $objectPSName

	Foreach ($param in $queryParams) {
		$lmInputParams.Add("param", $param)

		$response = Get-LmParameter @lmInputParams
		if ($response.ReturnCode -eq 200) {
			$value = $response.Data.$param
			if ($param -ne "wuidisplaylines") {
				$configContainer.Add($param, $value)
			}
			else {
				# Statistics Display Size
				$configContainer.Add("StatisticsDisplaySize", $value)
			}
		}
		else {
			# ERROR
			return $response
		}
		$lmInputParams.Remove("param")
		Start-Sleep -m 200
	}
	$data = New-Object -TypeName PSObject -Property $configContainer

	$settingsContainer = [ordered]@{}
	$settingsContainer.PSTypeName = $objectPSName
	$settingsContainer.Add($objectPSName, $data)

	$finalObject = New-Object -TypeName PSObject -Property $settingsContainer

	setKempAPIReturnObject 200 "Command successfully executed." $finalObject
}

# Internal use only
Function SetParameterSet($paramsSet, $connParams, [ref]$params2Get)
{
	if ($paramsSet) {

		foreach ($param in $paramsSet.Keys) {

			$connParams.Add("param", $param)
			$connParams.Add("value", $paramsSet[$param])
			$params2Get.value += $param

			$response = Set-LmParameter @connParams
			if ($response.ReturnCode -ne 200) {
				return $response
			}

			$connParams.Remove("param")
			$connParams.Remove("value")
		
			Start-Sleep -m 200
		}
		$response
	}
}

# --------------------------------------------------------------------------------------------
# LM ANSWER helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function checkLmOkResponse($LmResponse)
{
	$retValue = $false
	if ($LmResponse -eq "OK" -or
	    $LmResponse -eq "ok" -or
	    $LmResponse -eq "Ok"	) {
		$retValue = $true
	}
	return $retValue
}

# Internal use only
Function getErrorCode($errMsg)
{
	if ($errMsg) {

		$errMsg = [string]$errMsg
		if ($errMsg.Contains("Unauthorized")) {
			$errCode = 401
		}
		else {
			$errCode = 400
		}

	}
	else {
		$errCode = 400
	}
	return $errCode
}

# --------------------------------------------------------------------------------------------
# EULA helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function SetEulaResponseObject($rawAnswer, $EulaType)
{
	if ($rawAnswer) {
		try {
			$EulaCmdResponse = [xml]([System.Web.HttpUtility]::HtmlDecode($rawAnswer))
			$answerCode = $EulaCmdResponse.Response.stat

			if ($answerCode -eq 200) {
				$answerDes = "Command successfully executed"
				try {
					$mstr = $EulaCmdResponse.Response.Success.Data.Magic
					# NOTE we can't access the eula directly
					#      due to the HTML tags.
					$eulaStartIndex = $rawAnswer.IndexOf("`<Eula`>") + 6
					$eulaEndIndex = $rawAnswer.IndexOf("`</Eula`>")
					$eula = $rawAnswer.Substring($eulaStartIndex, $eulaEndIndex - $eulaStartIndex)

					$tempEulaAnswer = [ordered]@{}
					$tempEulaAnswer.PSTypeName = $EulaType
					$tempEulaAnswer.MagicString = $mstr
					<#
					if ($mstr) {
						$tempEulaAnswer.MagicString = $mstr
					}
					#>
					$tempEulaAnswer.$EulaType = $eula
					$eulaAnswer = New-Object -TypeName PSObject -Prop $tempEulaAnswer

					$eulaHT = [ordered]@{}
					$eulaHT.PSTypeName = $EulaType
					$eulaHT.Add($EulaType, $eulaAnswer)
					$eulaObject = New-Object -TypeName PSObject -Prop $eulaHT

					$answer = setKempAPIReturnObject $answerCode $answerDes $eulaObject
					return $answer
				}
				catch {
					$errorString = $_.Exception.Message
					$errorAnswer = setKempAPIReturnObject 401 "$errorString" $null
					return $errorAnswer
				}
			}
			else {
				# ERROR
				$answerDes = $EulaCmdResponse.Response.Error
				$errorAnswer = setKempAPIReturnObject $answerCode $answerDes $null
				return $errorAnswer
			}
		}
		catch {
			$errorAnswer = setKempAPIReturnObject 401 $rawAnswer $null
			return $errorAnswer
		}
	}
	$errorAnswer = setKempAPIReturnObject 401 "ERROR: no answer from the LM." $null
	return $errorAnswer
}

# Internal use only
Function SetEulaErrorResponseObject($rawError)
{
	if ($rawError) {

		try {
			$err = [xml]$rawError
			$errCode = $err.Response.stat
			$errDes  = $err.Response.Error
		}
		catch {
			$errCode = 400
			$errDes  = $rawError
		}
	}
	else {
		$errCode = 400
		$errDes = "ERROR: Unknown error."
	}
	setKempAPIReturnObject $errCode $errDes $null
}

# --------------------------------------------------------------------------------------------
# LICENSE helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function GetLicenseCmdErrorCode($errorString)
{
	if ($errorString.Contains("invalid username")) {
		$errCode = 422
	}
	elseif ($errorString.Contains("Unauthorized")) {
		$errCode = 401
	}
	elseif ($errorString.Contains("Unable to connect") -or
		      $errorString.Contains("The remote name could not be resolved") -or
		      $errorString.Contains("Can't find a certificate") -or
		      $errorString.Contains("The underlying connection was closed")) {
		$errCode = 400
	}
	else {
		Write-Debug "Unknown error message [$errorString]"
		$errCode = 400
	}
	$errCode
}

# --------------------------------------------------------------------------------------------
# Cmdlets response "HANDLER" functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function SetGetLicenseAccessKeyReturnObject($response)
{
	$accessKey = $([xml]$response).Response.Success.Data.AccessKey

	$tempAKA = @{}
	$tempAKA.PSTypeName = "AccessKey"
	$tempAKA.AccessKey = $accessKey
	New-Object -TypeName PSObject -Prop $tempAKA
}

# Internal use only
Function AddLicenseObject($licItem, $pOrderId)
{
	$LicVector = @()

	$licDes = $licItem.description
	if ($licDes.Contains("from OrderID")) {
		$licDes += " $pOrderId"
	}
	$buymore = $licItem.purchaseOptions[0].link -replace "`n","" -replace "`r",""

	foreach($lic in $licItem.licenseTypes) {
		$LicData = [ordered]@{}
		$LicData.PSTypeName = "License"

		foreach($item in $lic.PSObject.Properties) {
			$value = $item.Value -replace "`n","" -replace "`r",""
			$LicData.Add($item.Name, $value)
		}
		if ($licDes.Contains("Temp")) {
			$LicData.Add("LicenseStatus", $licDes)
			$LicData.Add("description", $LicData.name)
		}
		else {
			$LicData.Add("LicenseStatus", "Permanent License")
		}
		$LicData.Add("BuyMoreAt", $buymore)

		$licObj = New-Object -TypeName PSObject -Prop $LicData
		$LicVector += $LicObj
	}
	return $LicVector
}

# Internal use only
Function SetGetLicenseTypeReturnObject($xmlAnsw, $pOrderId)
{
	$data = $xmlAnsw.Response.Success

	if ( ([String]::IsNullOrEmpty($data)) ) {
		return $null
	}

	$LicHt = [ordered]@{}
	$LicHt.PSTypeName = "License"

	if ($data.Contains("License type information not available") -or $data -eq "[]") {
		$LicHt.Add("Licenses", "License type information not available")
		New-Object -TypeName PSObject -Prop $LicHt
		return
	}

	$TempLicObject = $data | ConvertFrom-Json
	$licenseArray = @()
	foreach($item in $TempLicObject.categories) {
		$tmp = AddLicenseObject $item $pOrderId
		foreach($item in $tmp) {
			$licenseArray += $item
		}
	}
	$LicHt.Add("License", $licenseArray)
	New-Object -TypeName PSObject -Prop $LicHt
}

# Internal use only
Function SetGetLicenseInfoReturnObject($response)
{
	$LicInfo = [ordered]@{}
	$LicInfo.PSTypeName = "LicenseInfo"
	
	$data = $([xml]$response).Response.Success.Data

	$licenseData = GetPSObjectFromXml "LicenseInfo" $data
	$LicInfo.Add("LicenseInfo", $licenseData) | Out-null

	New-Object -TypeName PSObject -Property $LicInfo
}

# Internal use only
Function SetAdcVSSettingsReturnObject($xmlAnsw, $single)
{
	if ($single -eq $true) {
		$vsSettings = [ordered]@{}
		$vsSettings.PSTypeName = "VSSettings"
		$vsData = GetPSObjectFromXml "VS" $xmlAnsw.Response.Success.Data
		$vsSettings.Add("VS", $vsData) | Out-null
		New-Object -TypeName PSObject -Property $vsSettings
	}
	else {
		GetPSObjectFromXml "VS" $xmlAnsw.Response.Success.Data.VS
	}
}

# Internal use only
Function SetRSSettingReturnObject($xmlAnsw)
{
	$rsSettings = [ordered]@{}
	$rsSettings.PSTypeName = "Real Server settings"

	$vsData = GetPSObjectFromXml "VS" $xmlAnsw.Response.Success.Data.Rs

	$rsSettings.Add("RsSettings", $vsData) | Out-null
	New-Object -TypeName PSObject -Property $rsSettings
}

# Internal use only
Function SetAdcContentRuleReturnObject($xmlAnsw)
{
	$crSettings = [ordered]@{}
	$crSettings.PSTypeName = "ContentRules"

	if ($xmlAnsw.Response.Success.Data.MatchContentRule) {
		$data = $([xml]$response).Response.Success.Data.MatchContentRule
		$mCrData = GetPSObjectFromXml "MatchContentRule" $data
		if ($mCrData.MatchContentRule) {
			$crSettings.Add("MatchContentRule", $mCrData.MatchContentRule) | Out-null
		}
		else {
			$crSettings.Add("MatchContentRule", $mCrData) | Out-null
		}
	}

	if ($xmlAnsw.Response.Success.Data.AddHeaderRule) {
		$data = $([xml]$response).Response.Success.Data.AddHeaderRule
		$ahCrData = GetPSObjectFromXml "AddHeaderRule" $data
		if ($ahCrData.AddHeaderRule) {
			$crSettings.Add("AddHeaderRule", $ahCrData.AddHeaderRule) | Out-null
		}
		else {
			$crSettings.Add("AddHeaderRule", $ahCrData) | Out-null
		}
	}

	if ($xmlAnsw.Response.Success.Data.DeleteHeaderRule) {
		$data = $([xml]$response).Response.Success.Data.DeleteHeaderRule
		$dhCrData = GetPSObjectFromXml "DeleteHeaderRule" $data
		if ($dhCrData.DeleteHeaderRule) {
			$crSettings.Add("DeleteHeaderRule", $dhCrData.DeleteHeaderRule) | Out-null
		}
		else {
			$crSettings.Add("DeleteHeaderRule", $dhCrData) | Out-null
		}
	}

	if ($xmlAnsw.Response.Success.Data.ReplaceHeaderRule) {
		$data = $([xml]$response).Response.Success.Data.ReplaceHeaderRule
		$rhCrData = GetPSObjectFromXml "ReplaceHeaderRule" $data
		if ($rhCrData.ReplaceHeaderRule) {
			$crSettings.Add("ReplaceHeaderRule", $rhCrData.ReplaceHeaderRule) | Out-null
		}
		else {
			$crSettings.Add("ReplaceHeaderRule", $rhCrData) | Out-null
		}
	}

	if ($xmlAnsw.Response.Success.Data.ModifyURLRule) {
		$data = $([xml]$response).Response.Success.Data.ModifyURLRule
		$muRData = GetPSObjectFromXml "ModifyURLRule" $data
		if ($muRData.ModifyURLRule) {
			$crSettings.Add("ModifyURLRule", $muRData.ModifyURLRule) | Out-null
		}
		else {
			$crSettings.Add("ModifyURLRule", $muRData) | Out-null
		}
	}

	if ($xmlAnsw.Response.Success.Data.ReplaceBodyRule) {
		$data = $([xml]$response).Response.Success.Data.ReplaceBodyRule
		$repBodyData = GetPSObjectFromXml "ReplaceBodyRule" $data
		if ($repBodyData.ReplaceBodyRule) {
			$crSettings.Add("ReplaceBodyRule", $repBodyData.ReplaceBodyRule) | Out-null
		}
		else {
			$crSettings.Add("ReplaceBodyRule", $repBodyData) | Out-null
		}
	}

	$crRetObj = New-Object -TypeName PSObject -Property $crSettings

	$crConf = [ordered]@{}
	$crConf.PSTypeName = "ContentRules"
	$crConf.Add("ContentRules", $crRetObj) | Out-null
	New-Object -TypeName PSObject -Property $crConf
}

# Internal use only
Function SetAdcServiceHealthReturnObject($xmlAnsw)
{
	$srvHConf = [ordered]@{}
	$srvHConf.PSTypeName = "AdcServiceHealth"

	$data = $([xml]$response).Response.Success.Data
	$srvHData = GetPSObjectFromXml "AdcServiceHealth" $data

	if ($srvHData.RetryInterval) {
		renameCustomObjectProperty $srvHData "RetryInterval" "CheckInterval"
	}
	if ($srvHData.Timeout) {
		renameCustomObjectProperty $srvHData "Timeout" "ConnectionTimeout"
	}
	if ($srvHData.RetryCount) {
		renameCustomObjectProperty $srvHData "RetryCount" "RetryCount"
	}

	$srvHConf.Add("AdcServiceHealth", $srvHData) | Out-null
	New-Object -TypeName PSObject -Property $srvHConf
}

# Internal use only
Function SetAdcAdaptiveHealthCheckReturnObject($xmlAnsw)
{
	$ahcConf = [ordered]@{}
	$ahcConf.PSTypeName = "AdcAdaptiveHealthCheck"

	$data = $([xml]$response).Response.Success.Data
	$ahcData = GetPSObjectFromXml "AdcAdaptiveHealthCheck" $data

	$ahcConf.Add("AdcAdaptiveHealthCheck", $ahcData) | Out-null
	New-Object -TypeName PSObject -Property $ahcConf
}

# Internal use only
Function SetAdcWafVSRulesReturnObject($xmlAnsw, $rulename)
{
	$vsWafRule = [ordered]@{}
	$vsWafRule.PSTypeName = "AdcWafVSRules"

	$data = $([xml]$response).Response.Success.Data
	$vsWafRuleData = GetPSObjectFromXml "AdcWafVSRules" $data

	$vsWafRule.Add("AdcWafVSRules", $vsWafRuleData) | Out-null
	New-Object -TypeName PSObject -Property $vsWafRule
}

# Internal use only
Function SetLicenseOnPremiseReturnObject($xmlAnsw)
{
	#$AslServerIpAddr = $xmlAnsw.Response.Success.Data.aslipaddr
	$AslServerHost = $xmlAnsw.Response.Success.Data.aslhost
	$AslServerPort = $xmlAnsw.Response.Success.Data.aslport
	#$AslServerFqdn = $xmlAnsw.Response.Success.Data.aslname

	$aslConf = [ordered]@{}
	$aslConf.PSTypeName = "Asl Server Data"

	#$aslConf.Add("AslServerIpAddress", $AslServerIpAddr) | Out-null
	$aslConf.Add("AslHost", $AslServerHost) | Out-null
	$aslConf.Add("AslPort", $AslServerPort) | Out-null
	#$aslConf.Add("AslServerFqdn", $AslServerFqdn) | Out-null

	New-Object -TypeName PSObject -Prop $aslConf
}

# Internal use only
Function SetGetSecUserReturnObject($xmlAnsw)
{
	$secUserConf = [ordered]@{}
	$secUserConf.PSTypeName = "SecureUserSettings"

	$secUserData = GetPSObjectFromXml "SecureUserSettings" $xmlAnsw.Response.Success.Data.User
	if ($secUserData) {
	
		if ($secUserData.User) {
			foreach ($user in $secUserData.User) {
				$user.Perms = $user.Perms.Trim(",", " ")
			}
			$secUserConf.Add("SecureUserSettings", $secUserData.User) | Out-null
		}
		else {
			$secUserData.Perms = $secUserData.Perms.Trim(",", " ")
			$secUserConf.Add("SecureUserSettings", $secUserData) | Out-null
		}
	}
	New-Object -TypeName PSObject -Property $secUserConf
}

# Internal use only
Function SetGetRemoteGroupReturnObject($xmlAnsw)
{
	$remoteGroupConf = [ordered]@{}
	$remoteGroupConf.PSTypeName = "RemoteGroupSettings"

	$remoteGroupData = GetPSObjectFromXml "RemoteGroupSettings" $xmlAnsw.Response.Success.Data.RemoteUserGroup
	if ($remoteGroupData) {
	
		if ($remoteGroupData.RemoteUserGroup) {
			foreach ($user in $remoteGroupData.RemoteUserGroup) {
				$user.Perms = $user.Perms.Trim(",", " ")
			}
			$remoteGroupConf.Add("RemoteGroupSettings", $remoteGroupData.RemoteUserGroup) | Out-null
		}
		else {
			$remoteGroupData.Perms = $remoteGroupData.Perms.Trim(",", " ")
			$remoteGroupConf.Add("RemoteGroupSettings", $remoteGroupData) | Out-null
		}
	}
	New-Object -TypeName PSObject -Property $remoteGroupConf
}

# Internal use only
Function SetNetworkInterfaceReturnObject($xmlAnsw, $interfaceId)
{
	$networkInterfaceData = GetPSObjectFromXml "NetworkInterfaceSettings" $xmlAnsw.Response.Success.Data.Interface
	if ($interfaceId -ge 0) {
		# specific interface
		$networkInterfaceConf = [ordered]@{}
		$networkInterfaceConf.PSTypeName = "NetworkInterfaceSettings"

		$networkInterfaceConf.Add("Interface", $networkInterfaceData) | Out-null
		New-Object -TypeName PSObject -Property $networkInterfaceConf
	}
	else {
		# all interfaces
		return $networkInterfaceData
	}
}

# Internal use only
Function SetGetAllParametersReturnObject($xmlAnsw, $typeName)
{
	$ht = [ordered]@{}

	if ($typeName -eq "AllParameters") {
		$ht.PSTypeName = $typeName
		$allParamsData = GetPSObjectFromXml $typeName $xmlAnsw.Response.Success.Data
		$ht.Add($typeName, $allParamsData) | Out-null
	}
	else {
		$ht.PSTypeName = "Parameter"
		$node = $xmlAnsw.Response.Success.Data
		foreach($item in $node.GetEnumerator()) {
			$paramValue = $item.InnerText -replace "`n","" -replace "`r",""	# LM s..t
			$ht.add($item.Name, $paramValue)
		}
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGetApiSecurityKeysObject($xmlAnsw, $typeName)
{
	$data = GetPSObjectFromXml "SecApiKeys" $xmlAnsw.Response.Success.Data.apikeys

	$ht = [ordered]@{}
	$ht.PSTypeName = "SecApiKeys"
	if ($data.key -is [array]) {
		$ht.add("key", $data.key)
	}
	else {
		$ht.add("key", $data)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmNetworkInterfaceReturnObject($xmlAnsw)
{
	GetPSObjectFromXml "InterfaceSettings" $xmlAnsw.Response.Success.Data.Network
}

# Internal use only
Function SetTLSCertificateReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data
	if ($data) {
		GetPSObjectFromXml "TlsCertificate" $data "notrim"
	}
	else {
		return $null
	}
}

# Internal use only
Function SetGetTLSCipherSetReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data.cipherset

	if ($data) {
		$data = $data.split(":")
	}

	$tlsCS = [ordered]@{}
	$tlsCS.PSTypeName = "TlsCipherSet"

	$tlsCS.Add("TlsCipherSet", $data) | Out-null

	New-Object -TypeName PSObject -Prop $tlsCS
}

# Internal use only
Function doRemoveNonSamlData($singleSSODomain)
{
	if ($singleSSODomain.auth_type -eq "SAML") {
		$singleSSODomain.PSObject.Properties.Remove("testuser")
		$singleSSODomain.PSObject.Properties.Remove("ldap_version")
		$singleSSODomain.PSObject.Properties.Remove("server_side")
		$singleSSODomain.PSObject.Properties.Remove("logon_fmt")
		$singleSSODomain.PSObject.Properties.Remove("logon_fmt2")
		$singleSSODomain.PSObject.Properties.Remove("logon_transcode")
		$singleSSODomain.PSObject.Properties.Remove("logon_domain")
		$singleSSODomain.PSObject.Properties.Remove("kerberos_domain")
		$singleSSODomain.PSObject.Properties.Remove("kerberos_kdc")
		$singleSSODomain.PSObject.Properties.Remove("kcd_username")
		$singleSSODomain.PSObject.Properties.Remove("max_failed_auths")
		$singleSSODomain.PSObject.Properties.Remove("reset_fail_tout")
		$singleSSODomain.PSObject.Properties.Remove("unblock_tout")
		$singleSSODomain.PSObject.Properties.Remove("sess_tout_idle_priv")
		$singleSSODomain.PSObject.Properties.Remove("sess_tout_duration_priv")
		$singleSSODomain.PSObject.Properties.Remove("cert_asi")
		$singleSSODomain.PSObject.Properties.Remove("cert_check_cn")
	}
}

# Internal use only
Function removeNonSamlData($SSODomainData)
{
	if ($SSODomainData) {

		if ($SSODomainData.Domain) {
			# array case
			$domainsArray = $SSODomainData.Domain
			foreach ($singleDomain in $domainsArray) {
				doRemoveNonSamlData($singleDomain)
			}
		}
		else {
			# scalar case
			doRemoveNonSamlData($SSODomainData)
		}
	}
}

# Internal use only
Function SetGetSSODomainReturnObject($xmlAnsw)
{
	$ssoData = $xmlAnsw.Response.Success.Data.Domain
	$data = GetPSObjectFromXml "SSODomain" $ssoData

	removeNonSamlData $data

	$ht = [ordered]@{}
	$ht.PSTypeName = "SSODomain"

	if ($data.Domain) {
		$ht.add("Domain", $data.Domain)
	}
	else {
		$ht.add("Domain", $data)
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetSSOSamlDomainReturnObject($xmlAnsw)
{
	$ssoData = $xmlAnsw.Response.Success.Data.Domain

	$data = GetPSObjectFromXml "SSODomain" $ssoData

	removeNonSamlData $data

	$ht = [ordered]@{}
	$ht.PSTypeName = "SSODomain"
	$ht.add("Domain", $data)
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetSSODomainLockUnLockAnswerReturnObject($xmlAnsw, $Cmd)
{
	$dht = [ordered]@{}

	if ($Cmd -eq "showdomainlockedusers") {
		$dht.PSTypeName = "SSODomainsLockedUsers"
		$data = $xmlAnsw.Response.Success.Data.LockedUsers

		$lockedUser = GetPSObjectFromXml "LockedUsers" $data
		if ($lockedUser) {
			$dht.Add("LockedUsers", $lockedUser) | Out-null
		}
		else {
			$dht = $null
		}
	}
	elseif ($Cmd -eq "unlockdomainusers") {
		$dht.PSTypeName = "SSODomainsUnlockedUsers"
		$data = $xmlAnsw.Response.Success.Data.UnlockedUsers

		$unlockedUser = GetPSObjectFromXml "UnlockedUsers" $data
		if ($unlockedUser) {
			$dht.Add("UnlockedUsers", $unlockedUser) | Out-null
		}
		else {
			$dht = $null
		}
	}
	else {
		Throw "Unknown SSO Domain command"
		return
	}
	New-Object -TypeName PSObject -Prop $dht
}

# Internal use only
Function SetGetSSODomainSessionReturnObject($xmlAnsw)
{
	$Sessions = [ordered]@{}
	$Sessions.PSTypeName = "SSOSession"

	$nos = $xmlAnsw.Response.Success.Data.NumberOfSessions
	$Sessions.Add("NumberOfSessions", $nos) | Out-null

	if ($nos -eq 0) {
		$Sessions.Add("Session", $null)
	}
	elseif ($nos -eq 1) {
		$data = $xmlAnsw.Response.Success.Data.Session
		$sHt = GetPSObjectFromXml "Session" $data

		$Sessions.Add("Session", $sHt)
	}
	else {
		$data = $xmlAnsw.Response.Success.Data.Session
		$sHt_temp = GetPSObjectFromXml "Session" $data
		$sHt = $sHt_temp.Session

		$Sessions.Add("Session", $sHt)
	}

	$sObj = New-Object -TypeName PSObject -Prop $Sessions

	$ssoSession = [ordered]@{}
	$ssoSession.PSTypeName = "SSOSession"
	$ssoSession.Add("SSOSession", $sObj) | Out-null

	New-Object -TypeName PSObject -Property $ssoSession
}

# Internal use only
Function SetGetSSODomainQuerySessionReturnObject($xmlAnsw)
{
	$Sessions = [ordered]@{}
	$Sessions.PSTypeName = "SSOQuerySession"

	$nos = $xmlAnsw.Response.Success.Data.NumberOfSessions
	$Sessions.Add("NumberOfSessions", $nos) | Out-null

	if ($nos -eq 0) {
		$Sessions.Add("Session", "no sessions")
	}
	elseif ($nos -eq 1) {
		$data = $xmlAnsw.Response.Success.Data.Session
		$sHt = GetPSObjectFromXml "Session" $data

		$Sessions.Add("Session", $sHt)
	}
	else {
		$data = $xmlAnsw.Response.Success.Data.Session
		$sHt_temp = GetPSObjectFromXml "Session" $data
		$sHt = $sHt_temp.Session

		$Sessions.Add("Session", $sHt)
	}

	$sObj = New-Object -TypeName PSObject -Prop $Sessions

	$ssoSession = [ordered]@{}
	$ssoSession.PSTypeName = "SSOQuerySession"
	$ssoSession.Add("SSOQuerySession", $sObj) | Out-null

	New-Object -TypeName PSObject -Property $ssoSession
}

# Internal use only
Function doUpdateLdapEndPointFields($ldapPoint)
{
	if ($ldapPoint) {
		if ($ldapPoint.ldaptype) {
		 	renameCustomObjectProperty $ldapPoint "ldaptype" "LdapProtocol"
		}
		if ($ldapPoint.refcnt) {
		 	renameCustomObjectProperty $ldapPoint "refcnt" "ReferralCount"
		}
	}
}

# Internal use only
Function SetGetLdapEndpointReturnObject($xmlAnsw, $list)
{
	$ht = [ordered]@{}
	$ht.PSTypeName = "LDAPEndPoint"

	$data = $xmlAnsw.Response.Success.Data
	$ldapEPData = GetPSObjectFromXml "LDAPEndPoint" $data
	if ($list) {
		$ldapPoints = $ldapEPData.EndPoint
		foreach ($singleLdapPoint in $ldapPoints) {
			doUpdateLdapEndPointFields $singleLdapPoint
		}
		$ht.Add("LDAPEndPoint", $ldapEPData.EndPoint)
	}
	else {
		doUpdateLdapEndPointFields $ldapEPData
		if ($ldapEPData.server) {
			$ldapEPData.server = $ldapEPData.server.Trim()
		}
		$ht.Add("LDAPEndPoint", $ldapEPData)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetInstallTemplateReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success
	if ($data) {
		$lma = $data -replace "\\n", " "
		Write-Verbose "response: $data"

		$ht = [ordered]@{}
		$ht.PSTypeName = "TemplateData"
		$ht.add("TemplateData", $data)
		New-Object -TypeName PSObject -Property $ht
	}
	else {
		return $null
	}
}

# Internal use only
Function SetGetTemplateReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Templates" $xmlAnsw.Response.Success.Data.template

	if ($data) {
		$ht = [ordered]@{}
		$ht.PSTypeName = "Template"
		if ($data.template) {
			$ht.add("Template", $data.template)
		}
		else {
			$ht.add("Template", $data)
		}
		New-Object -TypeName PSObject -Property $ht
	}
	else {
		return $null
	}
}

# Internal use only
Function SetExportVSTemplateReturnObject($xmlAnsw)
{
	return $null
}

# Internal use only
Function SetGetLogStatisticsReturnObject($xmlAnsw, $stats2collect)
{
	$ht = [ordered]@{}
	$ht.PSTypeName = "Statistics"

	if ($stats2Collect.VS -eq $true) {
		if ($xmlAnsw.Response.Success.Data.Vs) {
			$vsStats = GetPSObjectFromXml "VSStats" $xmlAnsw.Response.Success.Data.Vs
			$ht.Add("Vs", $vsStats.Vs) | Out-null
		}
	}

	if ($stats2Collect.RS -eq $true) {
		if ($xmlAnsw.Response.Success.Data.Rs) {
			$rsStats = GetPSObjectFromXml "RSStats" $xmlAnsw.Response.Success.Data.Rs
			$ht.Add("Rs", $rsStats.Rs) | Out-null
		}
	}

	if ($stats2Collect.Totals -eq $true) {

		if ($xmlAnsw.Response.Success.Data.VStotals) {
			$vsTotalData = GetPSObjectFromXml "VSTStats" $xmlAnsw.Response.Success.Data.VStotals
			$ht.Add("VStotals", $vsTotalData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.CPU) {
			$cpuData = GetPSObjectFromXml "CPUStats" $xmlAnsw.Response.Success.Data.CPU
			$ht.Add("CPU", $cpuData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.Network) {
			$networkData = GetPSObjectFromXml "NetStats" $xmlAnsw.Response.Success.Data.Network
			$ht.Add("Network", $networkData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.Memory) {
			$memoryData = GetPSObjectFromXml "MemStats" $xmlAnsw.Response.Success.Data.Memory
			$ht.Add("Memory", $memoryData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.DiskUsage) {
			$partitionsData = GetPSObjectFromXml "Partitions" $xmlAnsw.Response.Success.Data.DiskUsage
			$ht.Add("DiskUsage", $partitionsData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.TPS) {
			$tpsData = GetPSObjectFromXml "TpsStats" $xmlAnsw.Response.Success.Data.TPS
			$ht.Add("TPS", $tpsData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.ClientLimits) {
			$clientLimitsData = GetPSObjectFromXml "ClientLimits" $xmlAnsw.Response.Success.Data.ClientLimits
			$ht.Add("ClientLimits", $clientLimitsData) | Out-null
		}

		if ($xmlAnsw.Response.Success.Data.CountryCounts) {
			$countryCountsData = GetPSObjectFromXml "CountryCounts" $xmlAnsw.Response.Success.Data.CountryCounts
			$ht.Add("CountryCounts", $countryCountsData) | Out-null
		}
	}

	$ct = $xmlAnsw.Response.Success.Data.ChangeTime
	$ht.Add("ChangeTime", $ct) | Out-null

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetWafRulesReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "WafRules" $xmlAnsw.Response.Success.Data.Rules

	$ht = [ordered]@{}
	$ht.PSTypeName = "WafRules"
	$ht.add("WafRules", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetWafRulesAutoUpdateConfigurationReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "WafConfiguration" $xmlAnsw.Response.Success.Data.WAF

	$ht = [ordered]@{}
	$ht.PSTypeName = "WafConfiguration"
	$ht.add("WafConfiguration", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetWafAuditFilesReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "WafAuditFiles" $xmlAnsw.Response.Success.Data.WAFAuditFiles

	$ht = [ordered]@{}
	$ht.PSTypeName = "WafAuditFiles"
	$ht.add("WafAuditFiles", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetAdcLimitRulesReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Limits" $xmlAnsw.Response.Success.Data.Limits

	$ht = [ordered]@{}
	$ht.PSTypeName = "Limits"
	$ht.add("Limits", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetClientCPSLimitReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "ClientCpsLimit" $xmlAnsw.Response.Success.Data.ClientCpsLimit

	$ht = [ordered]@{}
	$ht.PSTypeName = "ClientCpsLimit"
	$ht.add("ClientCpsLimit", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetClientRPSLimitReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "ClientRpsLimit" $xmlAnsw.Response.Success.Data.ClientRpsLimit

	$ht = [ordered]@{}
	$ht.PSTypeName = "ClientRpsLimit"
	$ht.add("ClientRpsLimit", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetClientMaxcLimitReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "ClientMaxcLimit" $xmlAnsw.Response.Success.Data.ClientMaxcLimit

	$ht = [ordered]@{}
	$ht.PSTypeName = "ClientMaxcLimit"
	$ht.add("ClientMaxcLimit", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetClientBandwidthLimitReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "ClientBandwidthLimit" $xmlAnsw.Response.Success.Data.ClientBandwidthLimit

	$ht = [ordered]@{}
	$ht.PSTypeName = "ClientBandwidthLimit"
	$ht.add("ClientBandwidthLimit", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetModeReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Mode" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "Mode"
	$ht.add("Mode", $data)

	New-Object -TypeName PSObject -Property $ht
}
# Internal use only
Function SetGetNamespaceReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Namespace" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "Namespace"
	$ht.add("Namespace", $data)

	New-Object -TypeName PSObject -Property $ht
}
# Internal use only
Function SetGetWatchTimeoutReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "WatchTimeout" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "WatchTimeout"
	$ht.add("WatchTimeout", $data)

	New-Object -TypeName PSObject -Property $ht
}
# Internal use only
Function SetGetContextReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Context" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "Context"
	$ht.add("Context", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGeneralCaseReturnObject($xmlAnsw)
{
	return $null
}

# Internal use only
Function renameCustomObjectProperty($customPsObject, $oldPropName, $newPropName)
{
	$value = $customPsObject.$oldPropName
	$customPsObject.PSObject.Properties.Remove($oldPropName)
	$customPsObject | Add-Member -NotePropertyName "$newPropName" -NotePropertyValue $value
}

# Internal use only
Function getSelectionCriteriaName($scInternalName)
{
	$name = ""

	switch ($scInternalName)
	{
		"rr"	{ $name = "RoundRobin"; break }
		"wrr"	{ $name = "WeightedRoundRobin"; break }
		"fw"	{ $name = "FixedWeighting"; break }
		"rsr"	{ $name = "RealServerLoad"; break }
		"prx"	{ $name = "Proximity"; break }
		"lb"	{ $name = "LocationBased"; break }
		"all"	{ $name = "AllAvailable"; break }
	}
	return $name
}

# Internal use only
Function UpdateFqdnFieldNames($fqdnData)
{
	if ($fqdnData.fqdn) {
		$Fqdns = $fqdnData.fqdn
	}
	else {
		$Fqdns = $fqdnData
	}

	foreach ($singleFqdn in $Fqdns) {
		foreach ($key in Get-Member -InputObject $singleFqdn -MemberType NoteProperty) {
			switch ($key.Name)
			{
				"FullyQualifiedDomainName"	{
				 	renameCustomObjectProperty $singleFqdn "FullyQualifiedDomainName" "Fqdn"
					break
				}

				"failover" {
				 	renameCustomObjectProperty $singleFqdn "failover" "Failover"
					break
				}

				"publicRequestValue"	{
				 	renameCustomObjectProperty $singleFqdn "publicRequestValue" "PublicRequest"
					break
				}

				"privateRequestValue"	{
				 	renameCustomObjectProperty $singleFqdn "privateRequestValue" "PrivateRequest"
					break
				}

				"FailTime"	{
				 	renameCustomObjectProperty $singleFqdn "FailTime" "SiteFailureDelay"
					break
				}

				"SelectionCriteria"	{
					$value = getSelectionCriteriaName $singleFqdn.SelectionCriteria
					$singleFqdn.SelectionCriteria = $value
					break
				}
			}
		}
	}
}

# Internal use only
Function SetGetGeoFqdnReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoFqdn" $xmlAnsw.Response.Success.Data.fqdn
	UpdateFqdnFieldNames $data

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoFqdn"
	if ($data.fqdn -is [array]) {
		$ht.add("GeoFqdn", $data.fqdn)
	}
	else {
		$ht.add("GeoFqdn", $data)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoStatsReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoStats" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoStats"
	$ht.add("GeoStats", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoClusterReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoCluster" $xmlAnsw.Response.Success.Data.cluster

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoCluster"
	if ($data.cluster) {
		$ht.add("GeoCluster", $data.cluster)
	}
	else {
		$ht.add("GeoCluster", $data)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetAddGeoClusterReturnObject($xmlAnsw, $ClusterName)
{
	$rawData = $xmlAnsw.Response.Success
	$clusterIp = $($rawData.split(" "))[1]

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoCluster"
	$ht.add("IPAddress", $clusterIp)
	$ht.add("Name", $ClusterName)

	$clObj = New-Object -TypeName PSObject -Property $ht

	$cl = [ordered]@{}
	$cl.PSTypeName = "GeoCluster"
	$cl.Add("GeoCluster", $clObj) | Out-null

	New-Object -TypeName PSObject -Property $cl
}

# Internal use only
Function SetSetGeoClusterReturnObject($xmlAnsw)
{
	SetGetGeoClusterReturnObject $xmlAnsw
}

# Internal use only
Function SetGetNetworkRouteReturnObject($xmlAnsw)
{
	$routeData = $xmlAnsw.Response.Success.Data.Route

	if ($routeData -is [array]) {
		GetPSObjectFromXml "Route" $routeData
	}
	else {
		$data = GetPSObjectFromXml "Route" $routeData

		$ht = [ordered]@{}
		$ht.PSTypeName = "Route"
		$ht.add("Route", $data)

		New-Object -TypeName PSObject -Property $ht
	}
}

# Internal use only
Function SetTestNetworkRouteReturnObject($xmlAnsw)
{
	$traceRouteRawData = $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "Traceroute"

	$go = $true
	$pos2 = 0
	$hop = 1
	while ($go -eq $true) {
		$pos = $traceRouteRawData.IndexOf("#")
		if ($pos -lt 0) {
			$go = $false
		}
		elseif ($pos2 -gt 0) {
			$tmp = $traceRouteRawData.Substring(0, $pos)
			$hopString = "Hop " + $hop
			$ht.Add($hopString, $tmp)
			$tmp = $traceRouteRawData.Substring($pos + 1)
			$traceRouteRawData = $tmp
			$hop += 1
		}
		else {
			$tmp = $traceRouteRawData.Substring($pos + 1)
			if (-not ([string]::IsNullOrEmpty($tmp))) {
				$traceRouteRawData = $tmp
				$pos2 = $traceRouteRawData.IndexOf("#")
				$tmp = $traceRouteRawData.Substring(0, $pos2)
				$ht.TracerouteTo = $tmp
				$tmp = $traceRouteRawData.Substring($pos2 + 1)
				$traceRouteRawData = $tmp
			}
		}
	}
	$trRawObj = New-Object -TypeName PSObject -Property $ht

	$trHt = [ordered]@{}
	$trHt.PSTypeName = "Traceroute"
	$trHt.Add("Traceroute", $trRawObj) | Out-null

	New-Object -TypeName PSObject -Property $trHt
}

# Internal use only
Function SetAddNetworkVxLANReturnObject($xmlAnsw, $InterfaceId, $vlanFlag)
{
	$data = $xmlAnsw.Response.Success
	$intfId = $data.split()[4]	# same answer structure for VLan/VxLan

	$ht = [ordered]@{}

	if ($vlanFlag -eq "vlan") {
		$lanType = "VLan"
		$lanIntfLabel = "VLanInterfaceId"
	}
	else {
		$lanType = "VxLan"
		$lanIntfLabel = "VxLanInterfaceId"
	}

	$ht.PSTypeName = $lanType
	$ht.add("NetworkInterfaceId", $InterfaceId)
	$ht.add($lanIntfLabel, $intfId)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetAddNetworkVLANReturnObject($xmlAnsw, $InterfaceId)
{
	SetAddNetworkVxLANReturnObject $xmlAnsw $InterfaceId "vlan"
}

# Internal use only
Function SetGetHostsReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "LocalHosts" $xmlAnsw.Response.Success.Data.HostsEntry

	$ht = [ordered]@{}
	$ht.PSTypeName = "LocalHosts"
	$ht.add("LocalHosts", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetVSTotalsReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "TotalVS" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "TotalVS"
	$ht.add("TotalVS", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetVpnConnectionReturnObject($xmlAnsw, $vpnName)
{
	$ht = [ordered]@{}
	$ht.PSTypeName = "VpnConfiguration"

	if ($vpnName) {
		$check = $xmlAnsw.Response.Success.Data.GetElementsByTagName("name")
		if ([string]::IsNullOrEmpty($check)) {
			$newNode = $xmlAnsw.CreateElement("name")
			$newNodeText = $xmlAnsw.CreateTextNode($vpnName)
			$newNode.AppendChild($newNodeText) | Out-Null

			$nref = $xmlAnsw.Response.Success.Data.Item("status")
			$xmlAnsw.Response.Success.Data.InsertBefore($newNode, $nref) | Out-Null
		}
	}
	$data = $xmlAnsw.Response.Success.Data
	$vpnData = GetPSObjectFromXml "VpnConfiguration" $data

	if ($vpnName) {
		$ht.Add("VpnConfiguration", $vpnData)
	}
	else {
		$ht.Add("VpnConfiguration", $vpnData.VPN)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetInstallLmAddonReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success

	$ht = [ordered]@{}
	$ht.PSTypeName = "Package"
	$ht.add("Package", $data)
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmAddOnReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Package" $xmlAnsw.Response.Success.Data.Packages.Package

	$ht = [ordered]@{}
	$ht.PSTypeName = "Package"

	if ($data) {
	
		if ($data.Package) {
			$ht.add("Package", $data.Package)
		}
		else {
			$ht.add("Package", $data)
		}
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetInstallLmPatchReturnObject($xmlAnsw)
{
	$data = "Patch successfully installed. Please reboot the LM to apply the new software."

	$ht = [ordered]@{}
	$ht.PSTypeName = "PatchData"
	$ht.add("PatchData", $data)
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetUninstallLmPatchReturnObject($xmlAnsw)
{
	$data = "Previous firmware version successfully restored. Please reboot the LM to apply."

	$ht = [ordered]@{}
	$ht.PSTypeName = "PatchData"
	$ht.add("PatchData", $data)
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmPreviousFirmwareVersionReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data.PreviousVersion

	$ht = [ordered]@{}
	$ht.PSTypeName = "PreviousVersion"

	if ($data) {
		$ht.add("PreviousVersion", $data)
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetAddSdnControllerReturnObject($xmlAnsw)
{
	$data = GetPSSdnDataFromXml "Controller" $xmlAnsw.Response.Success.Data.controllers

	$ht = [ordered]@{}
	$ht.PSTypeName = "Controllers"
	$ht.add("Controllers", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetSdnControllerReturnObject($xmlAnsw)
{
	$data = GetPSSdnDataFromXml "Controller" $xmlAnsw.Response.Success.Data.controllers

	$ht = [ordered]@{}
	$ht.PSTypeName = "Controllers"
	$ht.add("Controllers", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetSetSdnControllerReturnObject($xmlAnsw)
{
	$data = GetPSSdnDataFromXml "Controller" $xmlAnsw.Response.Success.Data.controllers

	$ht = [ordered]@{}
	$ht.PSTypeName = "Controllers"
	$ht.add("Controllers", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetRemoveSdnControllerReturnObject($xmlAnsw)
{
	$data = GetPSSdnDataFromXml "Controller" $xmlAnsw.Response.Success.Data.controllers

	$ht = [ordered]@{}
	$ht.PSTypeName = "Controllers"
	$ht.add("Controllers", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetAdcRealServerReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "Rs" $xmlAnsw.Response.Success.Data.Rs

	$ht = [ordered]@{}
	$ht.PSTypeName = "Rs"
	$ht.add("Rs", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetSetGeoFQDNSiteAddressReturnObject($xmlAnsw, $SiteAddress)
{
	$data = GetPSObjectFromXml "GeoFqdnMap" $xmlAnsw.Response.Success.Data.fqdn

	if ($data) {
		foreach($map in $data.map) {
			if ($map.IPAddress -eq $SiteAddress) {
	
				$ht = [ordered]@{}
				$ht.PSTypeName = "GeoFqdnMap"
				$ht.add("GeoFqdnMap", $map)

				New-Object -TypeName PSObject -Property $ht
				return
			}
		}
	}
	return $null
}

# Internal use only
Function SetGetGeoCustomLocationReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoCustomLocation" $xmlAnsw.Response.Success.Data.location

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoCustomLocation"
	if ($data.location) {
		$ht.add("GeoCustomLocation", $data.location)
	}
	else {
		$ht.add("GeoCustomLocation", $data)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoIpRangeReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoIpRange" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "IpRange"
	if ($data.IPAddress) {
		foreach ($item in $data.IPAddress) {
			if ($item.Country -eq -1) {
				$item.Country = ""
			}
		}
		$ht.add("IpRange", $data.IPAddress)
	}
	else {
		if ($data.Country -eq -1) {
			$data.Country = ""
		}
		$ht.add("IpRange", $data)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetTestLmGeoEnabledReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoStatus"

	if ($data) {
		$ht.add("GeoStatus", $data)
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoPartnerStatusReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoPartners" $xmlAnsw.Response.Success.Data.GeoPartners

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoPartners"
	if ($data.Partner) {
		$ht.add("GeoPartners", $data.Partner)
	}
	else {
		$ht.add("GeoPartners", $null)
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoIPBlacklistDatabaseConfigurationReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoBlocklistDbConf" $xmlAnsw.Response.Success.Data.GeoAcl

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoBlacklistDbConf"
	$ht.add("GeoBlacklistDbConf", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoIPBlocklistDatabaseConfigurationReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoBlocklistDbConf" $xmlAnsw.Response.Success.Data.GeoAcl

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoBlocklistDbConf"
	$ht.add("GeoBlocklistDbConf", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoIPWhitelistReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoAllowlist" $xmlAnsw.Response.Success.Data.Allowlist

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoWhiteList"
	$ht.add("GeoWhiteList", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGeoIPAllowlistReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoAllowlist" $xmlAnsw.Response.Success.Data.Allowlist

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoAllowList"
	$ht.add("GeoAllowList", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetExportGeoIPWhitelistDatabaseReturnObject($xmlAnsw, $cmdOptions)
{
	$data = GetPSObjectFromXml "GeoWhitelist" $xmlAnsw.Response.Success.Data.Whitelist

	$filename = $cmdOptions.filename
	$forceSwitch = $cmdOptions.force

	$today = Get-Date

	if ($forceSwitch) {
		Out-File $filename
	}
	else {
		Out-File $filename -NoClobber
	}

	Add-Content $filename "----------------------------------------------"
	Add-Content $filename " Whitelisted IPs ($today)"
	Add-Content $filename "----------------------------------------------"

	if ($data.addr) {
		foreach ($ip in $data.addr) {
			Add-Content $filename "$ip"
		}
	}
	return $null
}

# Internal use only
Function SetExportGeoIPAllowlistDatabaseReturnObject($xmlAnsw, $cmdOptions)
{
	$data = GetPSObjectFromXml "GeoAllowlist" $xmlAnsw.Response.Success.Data.Allowlist

	$filename = $cmdOptions.filename
	$forceSwitch = $cmdOptions.force

	$today = Get-Date

	if ($forceSwitch) {
		Out-File $filename
	}
	else {
		Out-File $filename -NoClobber
	}

	Add-Content $filename "----------------------------------------------"
	Add-Content $filename " Allowlisted IPs ($today)"
	Add-Content $filename "----------------------------------------------"

	if ($data.addr) {
		foreach ($ip in $data.addr) {
			Add-Content $filename "$ip"
		}
	}
	return $null
}

# Internal use only
Function SetGetGeoDNSSECConfigurationReturnObject($xmlAnsw)
{
	$ksk_data    = GetPSObjectFromXml "GeoDNSSECKSk" $xmlAnsw.Response.Success.Data.KSK
	$dnssec_data = GetPSObjectFromXml "GeoDNSSECStatus" $xmlAnsw.Response.Success.Data.DNSSEC

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoDnsSecConfiguration"
	$ht.add("PublicKey", $ksk_data.PublicKey)
	$ht.add("DS_SHA1", $ksk_data.DS_SHA1)
	$ht.add("DS_SHA2", $ksk_data.DS_SHA2)
	if ($dnssec_data.Enable -eq "Y") {
		$ht.add("DNSSECStatus", "enabled")
	}
	else {
		$ht.add("DNSSECStatus", "disabled")
	}

	$dnssecHt = New-Object -TypeName PSObject -Property $ht
	$dnssecConf = [ordered]@{}
	$dnssecConf.PSTypeName = "GeoDnsSecConfiguration"
	$dnssecConf.Add("GeoDnsSecConfiguration", $dnssecHt) | Out-null
	New-Object -TypeName PSObject -Property $dnssecConf
}

# Internal use only
Function SetGetGeoLmMiscParameterReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "GeoMiscParameters" $xmlAnsw.Response.Success.Data

	if ( ([String]::IsNullOrEmpty($data.soa.Zone)) ) {
		$data.soa | Add-Member -NotePropertyName "Zone" -NotePropertyValue ""
	}

	if ( ([String]::IsNullOrEmpty($data.soa.SourceOfAuthority)) ) {
		$data.soa | Add-Member -NotePropertyName "SourceOfAuthority" -NotePropertyValue ""
	}

	if ( ([String]::IsNullOrEmpty($data.soa.NameSrv)) ) {
		$data.soa | Add-Member -NotePropertyName "NameSrv" -NotePropertyValue ""
	}

	if ( ([String]::IsNullOrEmpty($data.soa.SOAEmail)) ) {
		$data.soa | Add-Member -NotePropertyName "SOAEmail" -NotePropertyValue ""
	}

	if ( ([String]::IsNullOrEmpty($data.soa.GlueIP)) ) {
		$data.soa | Add-Member -NotePropertyName "GlueIP" -NotePropertyValue ""
	}

	if ( ([String]::IsNullOrEmpty($data.soa.TXT)) ) {
		$data.soa | Add-Member -NotePropertyName "TXT" -NotePropertyValue ""
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "GeoMiscParameters"
	$ht.add("GeoMiscParameters", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetVSPacketFilterACLReturnObject($xmlAnsw, $aclType)
{
	$data = GetPSObjectFromXml "VsAclData" $xmlAnsw.Response.Success.Data.VS

	$ht = [ordered]@{}
	$ht.PSTypeName = "VsAclConfiguration"
	$ht.add("VS_IP", $data.VS_IP)
	$ht.add("VS_Port", $data.VS_Port)
	$ht.add("VS_Protocol", $data.VS_Protocol)
	switch ($aclType)
	{
		"black" {
			$ht.add("Blacklist", $data.Blacklist.IP)
			break
		}

		"white" {
			$ht.add("Whitelist", $data.WhiteList.IP)
			break
		}

		"allow" {
			$ht.add("Allowlist", $data.AllowList.IP)
			break
		}

		"block" {
			$ht.add("Blocklist", $data.BlockList.IP)
			break
		}
	}

	$vsAclData = New-Object -TypeName PSObject -Property $ht
	$vsAclConf = [ordered]@{}
	$vsAclConf.PSTypeName = "VsAclConfiguration"
	$vsAclConf.Add("VsAclConfiguration", $vsAclData) | Out-null

	New-Object -TypeName PSObject -Property $vsAclConf
}

# Internal use only
Function SetNewVSPacketFilterACLReturnObject($xmlAnsw)
{
	return $null
}

# Internal use only
Function SetRemoveVSPacketFilterACLReturnObject($xmlAnsw)
{
	return $null
}

# Internal use only
Function SetGetPacketFilterOptionReturnObject($xmlAnsw, $Type)
{
	switch ($Type)
	{
		"isenabled" {
			$dataString = "aclstatus"
			break
		}
		"isdrop" {
			$dataString = "aclmethod"
			break
		}
		"isifblock" {
			$dataString = "aclblockall"
			break
		}
		"iswuiblock" {
			$dataString = "aclwuiblock"
			break
		}
		"wuiaddr" {
			$dataString = "wuiaddr"
			break
		}
	}
	$data = $xmlAnsw.Response.Success.Data.$dataString

	$ht = [ordered]@{}
	$ht.PSTypeName = "PacketFilterOption"
	$ht.add($dataString, $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetGlobalPacketFilterACLReturnObject($xmlAnsw, $aclType)
{
	$ht = [ordered]@{}
	switch ($aclType)
	{
		"black" {
			$ht.PSTypeName = "AclBlacklist"
			$data = GetPSObjectFromXml "AclData" $xmlAnsw.Response.Success.Data.Blacklist
			$ht.add("Blacklist", $data.IP)
			break
		}

		"white" {
			$ht.PSTypeName = "AclWhitelist"
			$data = GetPSObjectFromXml "AclData" $xmlAnsw.Response.Success.Data.Whitelist
			$ht.add("Whitelist", $data.IP)
			break
		}

		"allow" {
			$ht.PSTypeName = "AclAllowlist"
			$data = GetPSObjectFromXml "AclData" $xmlAnsw.Response.Success.Data.Allowlist
			$ht.add("Allowlist", $data.IP)
			break
		}

		"block" {
			$ht.PSTypeName = "AclBlocklist"
			$data = GetPSObjectFromXml "AclData" $xmlAnsw.Response.Success.Data.Blocklist
			$ht.add("Blocklist", $data.IP)
			break
		}
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmIPConnectionLimitReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "LmIPConnectionLimit" $xmlAnsw.Response.Success.Data.ClientLimit

	$ht = [ordered]@{}
	$ht.PSTypeName = "LmIPConnectionLimit"
	if ($data.ClientLimit) {
		$ht.add("LmIPConnectionLimit", $data.ClientLimit)
	}
	else {
		$ht.add("LmIPConnectionLimit", $data)
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetCloudHAConfigurationReturnObject($xmlAnsw)
{
	if ($xmlAnsw.Response.Success.Data.AzureHA) {
		return SetGetAzureHAConfigurationReturnObject $xmlAnsw
	}

	if ($xmlAnsw.Response.Success.Data.AwsHA) {
		return SetGetAwsHAConfigurationReturnObject $xmlAnsw
	}

	$tmp = $xmlAnsw.Response.Success.Data
	try {
		$check = $tmp.InnerXml
		if ($check) {
			if ($check.Contains("cloud")) {
				$index1 = $check.IndexOf("cloud")
				$index2 = $check.IndexOf(">")
				$cloudName = $check.Substring($index1, $index2 - $index1)
			}
			elseif ($check.Contains("Cloud")) {
				$index1 = $check.IndexOf("Cloud")
				$index2 = $check.IndexOf(">")
				$cloudName = $check.Substring($index1, $index2 - $index1)
			}
			elseif ($check.Contains("CLOUD")) {
				$index1 = $check.IndexOf("CLOUD")
				$index2 = $check.IndexOf(">")
				$cloudName = $check.Substring($index1, $index2 - $index1)
			}
			else {
				$index1 = $check.IndexOf("<")
				$index2 = $check.IndexOf(">")
				$cloudName = $check.Substring($index1 + 1, $index2 - $index1 - 1)
			}
		}
		if ($cloudName) {
			$data = GetPSObjectFromXml "$cloudName" $xmlAnsw.Response.Success.Data."$cloudName"
			if ($data.Port) {
				renameCustomObjectProperty $data "Port" "HealthCheckPort"
			}
			if ($data.HaPrefered) {
				renameCustomObjectProperty $data "HaPrefered" "Hapreferred"
			}
			if ($data.HealthCheckAllInterfaces) {
				if ($data.HealthCheckAllInterfaces -eq "unset") {
					$data.HealthCheckAllInterfaces = "no"
				}
			}
			$ht = [ordered]@{}
			$ht.PSTypeName = "$cloudName" + "Configuration"
			$ht.add("$cloudName" + "Configuration", $data)

			New-Object -TypeName PSObject -Property $ht

			return
		}
	}
	catch {
		Throw "Unknow cloud platform or not a cloud VLM."
		return
	}
	Throw "Unknow cloud platform or not a cloud VLM."
	return
}

# Internal use only
Function SetGetAzureHAConfigurationReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "AzureHAConfiguration" $xmlAnsw.Response.Success.Data.AzureHA

	if ($data.Port) {
		renameCustomObjectProperty $data "Port" "HealthCheckPort"
	}

	if ($data.HaPrefered) {
		renameCustomObjectProperty $data "HaPrefered" "Hapreferred"
	}

	if ($data.HealthCheckAllInterfaces) {
		if ($data.HealthCheckAllInterfaces -eq "unset") {
			$data.HealthCheckAllInterfaces = "no"
		}
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "AzureHAConfiguration"
	$ht.add("AzureHAConfiguration", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetAwsHAConfigurationReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "AwsHAConfiguration" $xmlAnsw.Response.Success.Data.AwsHA

	if ($data.Port) {
		renameCustomObjectProperty $data "Port" "HealthCheckPort"
	}

	if ($data.HealthCheckAllInterfaces) {
		if ($data.HealthCheckAllInterfaces -eq "unset") {
			$data.HealthCheckAllInterfaces = "no"
		}
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "AwsHAConfiguration"
	$ht.add("AwsHAConfiguration", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmCloudHaConfiguration($xmlAnsw)
{
	if ($xmlAnsw.Response.Success.Data.AzureHA) {
		return SetGetAzureHAConfigurationReturnObject $xmlAnsw
	}

	if ($xmlAnsw.Response.Success.Data.AwsHA) {
		return SetGetAwsHAConfigurationReturnObject $xmlAnsw
	}

	Throw "Unknow cloud platform or not a cloud VLM."
	return
}

# Internal use only
Function SetGetLmDebugInformationReturnObject($xmlAnsw, $type)
{
	if ($type -eq "slabinfo") {
		$data = GetPSObjectFromXml $type $xmlAnsw.Response.Success.Data.$type "notrim"
		if ($data.$type.data) {
			$data.$type.data = $data.$type.data.split("`n")
		}
	}
	else {
		$data = $xmlAnsw.Response.Success.Data.$type
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = $type
	$ht.add($type, $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetPingHostReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success

	if ($data) {
		$StatsPos1 = $data.IndexOf("ping statistics") + "ping statistics --- ".Length
		$StatsPos2 = $data.IndexOf("received") + "received".Length
		$trPcksString = $data.Substring($StatsPos1, $StatsPos2 - $StatsPos1)
		$cPos = $trPcksString.IndexOf(",")
		$tPackets = $trPcksString.Substring(0, $cPos)
		$rPackets = $trPcksString.Substring($cPos + 2)

		$PLPos = $data.IndexOf("packet loss") + "packet loss".Length
		$lossPackets = $data.Substring($StatsPos2 + 2, ($PLPos - $StatsPos2 - 2))

		$timePos = $data.IndexOf("time ")
		$rttPos = $data.IndexOf("rtt min/avg/max/mdev")
		$timeStr = $data.Substring($timePos, ($rttPos - $timePos))
		$rtt = $data.Substring($rttPos)

		$endPingResult = $data.IndexOf(" --- ")
		$PingResult = $data.Substring(0, $endPingResult)

		$pingData = [ordered]@{}

		$pingData.Add("PingResult", $PingResult)
		$pingData.Add("PacketsTransmitted", $tPackets)
		$pingData.Add("PacketsReceived", $rPackets)
		$pingData.Add("PacketsLoss", $lossPackets)
		$pingData.Add("Time", $timeStr)
		$pingData.Add("Rtt", $rtt)

		$PingObject = New-Object -TypeName PSObject -Prop $pingData

		$ht = [ordered]@{}
		$ht.PSTypeName = "PingData"
		$ht.add("PingData", $PingObject)

		New-Object -TypeName PSObject -Property $ht
	}
	else {
		return $null
	}
}

# Internal use only
Function SetGetAslLicenseTypeReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success

	if (([String]::IsNullOrEmpty($data))) {
		return $null
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "AslLicenseType"

	if ($data.Contains("License type information not available")) {
		$ht.add("License", $data)
	}
	elseif ($data -ne "[]") {
		$TempLicObject = $data | ConvertFrom-Json
		$LicObject = [ordered]@{}
		$LicObject.PSTypeName = "LicenseData"
		$licNumber = $TempLicObject.categories.licenseTypes.Length
		if (([String]::IsNullOrEmpty($licNumber))) {
			$licNumber = 1
		}
		#$LicObject.Add("OrderID", $OrderId)
		$LicObject.Add("AvailableLicenses", $licNumber)
		$LicObject.Add("Licenses", $TempLicObject.categories.licenseTypes)

		$licData = New-Object -TypeName PSObject -Prop $LicObject

		$ht.add("License", $licData.Licenses)
		$ht.add("AvailableLicenses", $licData.AvailableLicenses)
	}
	else {
		# No licenses available
		$emptyLicObject = [ordered]@{}
		$emptyLicObject.PSTypeName = "LicenseData"
		#$emptyLicObject.Add("OrderID", $OrderId)
		$emptyLicObject.Add("AvailableLicenses", 0)
		$emptyLicObject.Add("Licenses", $null)
		$licData = New-Object -TypeName PSObject -Prop $emptyLicObject

		$ht.add("License", $licData)
		$ht.add("AvailableLicenses", 0)
	}
	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmVpnIkeDaemonStatusReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "IkeDaemonStatus" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "IkeDaemonStatus"
	$ht.add("IkeDaemonStatus", $data.status)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetNewLmVpnConnectionReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "NewVpnConfiguration" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "NewVpnConfiguration"
	$ht.add("status", $data.status)
	$ht.add("defaultLocalIP", $data.defaultLocalIP)
	$ht.add("defaultLocalSubnets", $data.defaultLocalSubnets)
	$ht.add("defaultLocalID", $data.defaultLocalID)

	$vpnData = New-Object -TypeName PSObject -Property $ht

	$vpnConf = [ordered]@{}
	$vpnConf.PSTypeName = "NewVpnConfiguration"
	$vpnConf.Add("NewVpnConfiguration", $vpnData) | Out-null

	New-Object -TypeName PSObject -Property $vpnConf
}

# Internal use only
Function SetNewGlobalPacketFilterACLReturnObject($xmlAnsw)
{
	return $null
}

# Internal use only
Function SetGetClusterStatusReturnObject($xmlAnsw)
{
	$data = GetPSObjectFromXml "ClusterConfiguration" $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "ClusterConfiguration"

	$ht.add("ClusterConfiguration", $data.status)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetNewClusterReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success

	$ht = [ordered]@{}
	$ht.PSTypeName = "NewCluster"

	$ht.add("NewCluster", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetRaidControllerReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "RaidController"

	$ht.add("RaidController", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetRaidControllerDiskReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data

	$ht = [ordered]@{}
	$ht.PSTypeName = "RaidControllerDisk"

	$ht.add("RaidControllerDisk", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetExtEspLogConfReturnObject($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success.Data

	$status = "disabled"
	if (-not ([String]::IsNullOrEmpty($data)) ) {
		if ($data.Contains("enabled") -eq $true) {
			$status = "enabled"
		}
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "ExtEspLogConfiguration"

	$ht.add("ExtEspLogStatus", $status)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmLogFilesList($xmlAnsw)
{
	$data = GetPSObjectFromXml "LmLogFilesList" $xmlAnsw.Response.Success.Data.SyslogFiles

	$ht = [ordered]@{}
	$ht.PSTypeName = "LmLogFilesList"

	$ht.add("SyslogFiles", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmLogResetFilesList($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success -replace "`n",", " -replace "`r",", "
	if (-not ([String]::IsNullOrEmpty($data)) ) {
		if ($data -ne "Command completed ok") {
			$len = $data.Length
			if ($data.Substring($len - 1) -eq ",") {
				$data = $data -replace ".$" 
			}
			$len = $data.Length
			if ($data.Substring($len - 1) -eq " ") {
				$data = $data -replace ".$" 
			}
			$data = "Reset files: $data"
		}
		else {
			$data = "Reset files: all"
		}
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "LmLogResetFilesList"

	if (-not ([String]::IsNullOrEmpty($data)) ) {
		if ($data -ne "Command completed ok") {
			$ht.add("SyslogResetFiles", $data)
		}
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmExtendedLogFilesList($xmlAnsw)
{
	$data = GetPSObjectFromXml "LmExtendedLogFilesList" $xmlAnsw.Response.Success.Data.ExtlogFiles

	$ht = [ordered]@{}
	$ht.PSTypeName = "LmExtendedLogFilesList"

	$ht.add("ExtendedLogFiles", $data)

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmExtendedLogResetFilesList($xmlAnsw)
{
	$data = $xmlAnsw.Response.Success -replace "`n",", " -replace "`r",", "
	if (-not ([String]::IsNullOrEmpty($data)) ) {
		if ($data -ne "Command completed ok") {
			$len = $data.Length
			if ($data.Substring($len - 1) -eq ",") {
				$data = $data -replace ".$" 
			}
			$len = $data.Length
			if ($data.Substring($len - 1) -eq " ") {
				$data = $data -replace ".$" 
			}
			$data = "Reset files: $data"
		}
		else {
			$data = "Reset files: all"
		}
	}

	$ht = [ordered]@{}
	$ht.PSTypeName = "LmExtendedLogResetFilesList"

	if (-not ([String]::IsNullOrEmpty($data)) ) {
		if ($data -ne "Command completed ok") {
			$ht.add("ExtendedLogResetFiles", $data)
		}
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLmApiList($xmlAnsw)
{
	$ht = [ordered]@{}
	$ht.PSTypeName = "LmApiList"

	$version = $xmlAnsw.Response.Success.Data.version
	$t_cmds = $xmlAnsw.Response.Success.Data.commands

	$cmds = @()
	foreach ($cmd in $t_cmds.cmd) {
		$cmds += $cmd
	}

	$ht.add("Version", $version) | Out-null
	$ht.add("Commands", $cmds) | Out-null

	$data = GetPSObjectFromXml "LmApiList" $xmlAnsw.Response.Success.Data

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLECertificateReturnObject($xmlAnsw, $certName)
{
	$ht = [ordered]@{}
	$ht.PSTypeName = "LECertificate"

	if ($certName) {
		$check = $xmlAnsw.Response.Success.Data.GetElementsByTagName("Identifier")
		if ([string]::IsNullOrEmpty($check)) {
			$newNode = $xmlAnsw.CreateElement("Identifier")
			$newNodeText = $xmlAnsw.CreateTextNode($certName)
			$newNode.AppendChild($newNodeText) | Out-Null
		}
	}
	$data = $xmlAnsw.Response.Success.Data
	$certData = GetPSObjectFromXml "LECertificate" $data

	if ($certName) {
		$ht.Add("LECertificate", $certData)
	}
	else {
		$ht.Add("LECertificate", $CertData.Certificate)
	}

	New-Object -TypeName PSObject -Property $ht
}

# Internal use only
Function SetGetLEAccountInfoReturnObject($xmlAnsw)
{
	$LEInfo = [ordered]@{}
	$LEInfo.PSTypeName = "LEAccountInfo"
	
	$data = GetPSObjectFromXml "LEAccountInfo" $xmlAnsw.Response.Success.Data

	$LEInfo.Add("LEAccountInfo", $data) | Out-null

	New-Object -TypeName PSObject -Property $LEInfo
}

# Function "pointers" hashtable: success lm answer handlers
$successHandlerList = [ordered]@{
	GeneralCase = (gi function:SetGeneralCaseReturnObject)

	SetInitialPasswd = (gi function:SetGeneralCaseReturnObject)

	GetLicenseAccessKey = (gi function:SetGetLicenseAccessKeyReturnObject)
	GetLicenseType = (gi function:SetGetLicenseTypeReturnObject)
	GetLicenseInfo = (gi function:SetGetLicenseInfoReturnObject)
	RequestLicenseOnPremise = (gi function:SetLicenseOnPremiseReturnObject)
	GetAslLicenseType = (gi function:SetGetAslLicenseTypeReturnObject)

	NewAdcVS = (gi function:SetAdcVSSettingsReturnObject)
	SetAdcVS = (gi function:SetAdcVSSettingsReturnObject)
	GetAdcVS_Single = (gi function:SetAdcVSSettingsReturnObject)
	GetAdcVS_List = (gi function:SetAdcVSSettingsReturnObject)
	NewAdcRS = (gi function:SetRSSettingReturnObject)
	RemoveAdcVS = (gi function:SetGeneralCaseReturnObject)
	GetVSTotals = (gi function:SetGetVSTotalsReturnObject)
	GetAdcRealServer = (gi function:SetGetAdcRealServerReturnObject)

	AddAdcContentRule = (gi function:SetAdcContentRuleReturnObject)
	SetAdcContentRule = (gi function:SetAdcContentRuleReturnObject)
	GetAdcContentRule = (gi function:SetAdcContentRuleReturnObject)

	GetAdcServiceHealth = (gi function:SetAdcServiceHealthReturnObject)
	AdcAdaptiveHealthCheck = (gi function:SetAdcAdaptiveHealthCheckReturnObject)

	AdcWafVSRules = (gi function:SetAdcWafVSRulesReturnObject)

	GetAllSecUser = (gi function:SetGetSecUserReturnObject)
	GetSingleSecUser = (gi function:SetGetSecUserReturnObject)

	GetRemoteGroup = (gi function:SetGetRemoteGroupReturnObject)
	GetAllRemoteGroups = (gi function:SetGetRemoteGroupReturnObject)

	GetNetworkInterface = (gi function:SetNetworkInterfaceReturnObject)
	GetLmNetworkInterface = (gi function:SetGetLmNetworkInterfaceReturnObject)

	GetTlsCertificate = (gi function:SetTLSCertificateReturnObject)
	GetTlsCipherSet = (gi function:SetGetTLSCipherSetReturnObject)

	GetExtEspLogConfiguration =  (gi function:SetGetExtEspLogConfReturnObject)
	GetLmLogFilesList =  (gi function:SetGetLmLogFilesList)
	GetLmLogResetFilesList =  (gi function:SetGetLmLogResetFilesList)
	GetLmExtendedLogFilesList =  (gi function:SetGetLmExtendedLogFilesList)
	GetLmExtendedLogResetFilesList =  (gi function:SetGetLmExtendedLogResetFilesList)
	GetLmApiList =  (gi function:SetGetLmApiList)

	GetSSODomain = (gi function:SetGetSSODomainReturnObject)
	GetSSOSamlDomain = (gi function:SetGetSSOSamlDomainReturnObject)
	GetSSODomainLockedUser = (gi function:SetSSODomainLockUnLockAnswerReturnObject)
	SetSSODomainLockedUser = (gi function:SetSSODomainLockUnLockAnswerReturnObject)
	GetSSODomainSession = (gi function:SetGetSSODomainSessionReturnObject)
	GetSSODomainQuerySession = (gi function:SetGetSSODomainQuerySessionReturnObject)

	GetLdapEndpoint = (gi function:SetGetLdapEndpointReturnObject)

	InstallTemplate = (gi function:SetInstallTemplateReturnObject)
	GetTemplate = (gi function:SetGetTemplateReturnObject)
	ExportVSTemplate = (gi function:SetExportVSTemplateReturnObject)

	GetLogStatistics = (gi function:SetGetLogStatisticsReturnObject)

	GetWafRules = (gi function:SetGetWafRulesReturnObject)
	GetWafRulesAutoUpdateConfiguration = (gi function:SetGetWafRulesAutoUpdateConfigurationReturnObject)
	GetWafAuditFiles = (gi function:SetGetWafAuditFilesReturnObject)

	GetAllParameters = (gi function:SetGetAllParametersReturnObject)

	NewApiSecurityKey = (gi function:SetGetGetApiSecurityKeysObject)
	GetApiSecurityKeys = (gi function:SetGetGetApiSecurityKeysObject)
	RemoveApiSecurityKeys = (gi function:SetGetGetApiSecurityKeysObject)

	GetNetworkRoute = (gi function:SetGetNetworkRouteReturnObject)
	TestNetworkRoute = (gi function:SetTestNetworkRouteReturnObject)

	AddNetworkVxLAN = (gi function:SetAddNetworkVxLANReturnObject)
	AddNetworkVLAN = (gi function:SetAddNetworkVLANReturnObject)
	GetLmVpnIkeDaemonStatus = (gi function:SetGetLmVpnIkeDaemonStatusReturnObject)
	NewLmVpnConnection = (gi function:SetNewLmVpnConnectionReturnObject)
	GetVpnConnection = (gi function:SetGetVpnConnectionReturnObject)

	GetHosts = (gi function:SetGetHostsReturnObject)

	AddSdnController = (gi function:SetAddSdnControllerReturnObject)
	GetSdnController = (gi function:SetGetSdnControllerReturnObject)
	SetSdnController = (gi function:SetSetSdnControllerReturnObject)
	RemoveSdnController = (gi function:SetRemoveSdnControllerReturnObject)

	InstallLmPatch = (gi function:SetInstallLmPatchReturnObject)
	UninstallLmPatch = (gi function:SetUninstallLmPatchReturnObject)
	GetLmPreviousFirmwareVersion = (gi function:SetGetLmPreviousFirmwareVersionReturnObject)

	InstallLmAddon = (gi function:SetInstallLmAddonReturnObject)
	GetLmAddOn = (gi function:SetGetLmAddOnReturnObject)

	GetGeoFQDN = (gi function:SetGetGeoFqdnReturnObject)
	GetGeoCluster = (gi function:SetGetGeoClusterReturnObject)
	AddGeoCluster = (gi function:SetAddGeoClusterReturnObject)
	SetGeoCluster = (gi function:SetSetGeoClusterReturnObject)
	SetGeoFQDNSiteAddress = (gi function:SetSetGeoFQDNSiteAddressReturnObject)
	GetGeoCustomLocation = (gi function:SetGetGeoCustomLocationReturnObject)
	GetGeoIpRange = (gi function:SetGetGeoIpRangeReturnObject)
	TestLmGeoEnabled = (gi function:SetTestLmGeoEnabledReturnObject)
	GetGeoPartnerStatus = (gi function:SetGetGeoPartnerStatusReturnObject)
	GetGeoIPBlacklistDatabaseConfiguration = (gi function:SetGetGeoIPBlacklistDatabaseConfigurationReturnObject)
	GetGeoIPBlocklistDatabaseConfiguration = (gi function:SetGetGeoIPBlocklistDatabaseConfigurationReturnObject)
	GetGeoIPWhitelist = (gi function:SetGetGeoIPWhitelistReturnObject)
	GetGeoIPAllowlist = (gi function:SetGetGeoIPAllowlistReturnObject)
	ExportGeoIPWhitelistDatabase = (gi function:SetExportGeoIPWhitelistDatabaseReturnObject)
	ExportGeoIPAllowlistDatabase = (gi function:SetExportGeoIPAllowlistDatabaseReturnObject)
	GetGeoDNSSECConfiguration = (gi function:SetGetGeoDNSSECConfigurationReturnObject)
	GetGeoLmMiscParameter = (gi function:SetGetGeoLmMiscParameterReturnObject)
	GetGeoStats = (gi function:SetGetGeoStatsReturnObject)

	GetVSPacketFilterACL = (gi function:SetGetVSPacketFilterACLReturnObject)
	NewVSPacketFilterACL = (gi function:SetNewVSPacketFilterACLReturnObject)
	RemoveVSPacketFilterACL = (gi function:SetRemoveVSPacketFilterACLReturnObject)
	GetPacketFilterOption = (gi function:SetGetPacketFilterOptionReturnObject)
	GetGlobalPacketFilterACL = (gi function:SetGetGlobalPacketFilterACLReturnObject)
	NewGlobalPacketFilterACL = (gi function:SetNewGlobalPacketFilterACLReturnObject)

	GetLmIPConnectionLimit = (gi function:SetGetLmIPConnectionLimitReturnObject)

	GetAzureHAConfiguration = (gi function:SetGetAzureHAConfigurationReturnObject)
	GetAwsHaConfiguration = (gi function:SetGetAwsHAConfigurationReturnObject)
	GetLmCloudHaConfiguration = (gi function:SetGetCloudHAConfigurationReturnObject)

	GetLmDebugInformation = (gi function:SetGetLmDebugInformationReturnObject)
	PingHost = (gi function:SetPingHostReturnObject)

	NewCluster = (gi function:SetNewClusterReturnObject)
	GetClusterStatus = (gi function:SetGetClusterStatusReturnObject)

	GetRaidController = (gi function:SetGetRaidControllerReturnObject)
	GetRaidControllerDisk = (gi function:SetGetRaidControllerDiskReturnObject)
	GetAdcLimitRules = (gi function:SetGetAdcLimitRulesReturnObject)
	GetClientCPSLimit = (gi function:SetGetClientCPSLimitReturnObject)
	GetClientRPSLimit = (gi function:SetGetClientRPSLimitReturnObject)
	GetClientMaxcLimit = (gi function:SetGetClientMaxcLimitReturnObject)
	GetClientBandwidthLimit = (gi function:SetGetClientBandwidthLimitReturnObject)

	GetMode = (gi function:SetGetModeReturnObject)
	GetNamespace = (gi function:SetGetNamespaceReturnObject)
	GetWatchTimeout = (gi function:SetGetWatchTimeoutReturnObject)
	GetContext = (gi function:SetGetContextReturnObject)

	GetLECertificate = (gi function:SetGetLECertificateReturnObject)
	GetLEAccountInfo = (gi function:SetGetLEAccountInfoReturnObject)
}

# Internal use only
Function HandleSuccessAnswer($Command2ExecClass, $xmlAnsw, $AdditionalData)
{
	$SuccessString = "Command successfully executed."

	& $successHandlerList.$Command2ExecClass $xmlAnsw $AdditionalData | Tee-Object -Variable response | Out-null

	setKempAPIReturnObject 200 $SuccessString $response
}

# Internal use only
Function SetPingErrorResponse($pingErrorResponse)
{
	$StatsPos1 = $pingErrorResponse.IndexOf("ping statistics") + "ping statistics --- ".Length
	$StatsPos2 = $pingErrorResponse.IndexOf("received") + "received".Length
	$trPcksString = $pingErrorResponse.Substring($StatsPos1, $StatsPos2 - $StatsPos1)

	$cPos = $trPcksString.IndexOf(",")
	$tPackets = $trPcksString.Substring(0, $cPos)
	$rPackets = $trPcksString.Substring($cPos + 2)

	$errStringCheck = $pingErrorResponse.IndexOf("errors")
	if ($errStringCheck -gt 0) {
		$ErrorPos = $pingErrorResponse.IndexOf("errors") + "errors,".Length
		$Errors = $pingErrorResponse.Substring($StatsPos2 + 2, ($ErrorPos - $StatsPos2 - 3))
	}
	else {
		$Errors = ""
	}

	$PLPos = $pingErrorResponse.IndexOf("packet loss") + "packet loss".Length
	if ($errStringCheck -gt 0) {
		$lossPackets = $pingErrorResponse.Substring($ErrorPos + 1, ($PLPos - $ErrorPos - 1))
	}
	else {
		$lossPackets = $pingErrorResponse.Substring($StatsPos2 + 2, ($PLPos - $StatsPos2 - 2))
		$tmp = $pingErrorResponse.Substring($StatsPos2 + 2)
		$eTPos = $tmp.IndexOf(", time ") + ", time ".Length
		$elapsedTime = $tmp.Substring($eTPos)
	}

	$endPingResult = $pingErrorResponse.IndexOf(" --- ")
	$PingResult = $pingErrorResponse.Substring(0, $endPingResult)

	$pingData = [ordered]@{}

	$pingData.Add("PingResult", $PingResult)
	$pingData.Add("PacketsTransmitted", $tPackets)
	$pingData.Add("PacketsReceived", $rPackets)
	$pingData.Add("Errors", $Errors)
	$pingData.Add("PacketsLoss", $lossPackets)
	$pingData.Add("Time", $elapsedTime)

	New-Object -TypeName PSObject -Prop $pingData
}

# Internal use only
Function HandleErrorAnswer($Command2ExecClass, $xmlAnsw)
{
	#
	# FIXME: to change the logic: if the cmd does not need a specific handler,
	#        then the answer will be handled by the default case.
	#
	switch ($Command2ExecClass)
	{
		{ ($_ -in "GeneralCase", "NewAdcVS", "GetAdcVS_Single", "GetAdcVS_List", "SetAdcVS", "NewAdcRS", "VirtualServiceRule", "RealServerRule", "EnableDisableRS", "GetSetAdcRS", "RemoveAdcRS", "AddAdcContentRule", "RemoveAdcContentRule", "SetAdcContentRule", "GetAdcContentRule", "GetAdcServiceHealth","AdcHttpExceptions", "AdcAdaptiveHealthCheck", "AdcWafVSRules", "AddRemoveAdcWafRule", "GetLicenseAccessKey", "GetLicenseType", "GetLicenseInfo", "RequestLicenseOnline", "RequestLicenseOffline", "UpdateLicenseOnline", "UpdateLicenseOffline", "RequestLicenseOnPremise", "GetAllSecUser", "GetSingleSecUser", "GetRemoteGroup", "GetAllRemoteGroups", "GetNetworkInterface", "GetAllParameters", "GetLmNetworkInterface", "GetTlsCertificate", "GetTlsCipherSet", "GetSSODomain", "GetSSOSamlDomain", "GetSSODomainLockedUser", "SetSSODomainLockedUser", "GetSSODomainSession", "GetSSODomainQuerySession", "InstallTemplate", "ExportVSTemplate", "GetTemplate", "GetLogStatistics", "GetWafRules", "GetWafRulesAutoUpdateConfiguration", "GetWafAuditFiles", "GetGeoFQDN", "GetGeoStats", "AddGeoCluster", "SetGeoCluster", "AddNetworkVxLAN", "AddNetworkVLAN", "GetNetworkRoute", "TestNetworkRoute", "GetHosts", "GetVSTotals", "GetLdapEndpoint", "GetVpnConnection", "InstallLmAddon", "GetLmAddOn", "InstallLmPatch", "UninstallLmPatch", "GetLmPreviousFirmwareVersion", "AddSdnController", "SetSdnController", "GetSdnController", "RemoveSdnController", "GetAdcRealServer", "SetGeoFQDNSiteAddress", "GetGeoCustomLocation", "GetGeoIpRange", "TestLmGeoEnabled", "GetGeoPartnerStatus", "GetGeoIPBlacklistDatabaseConfiguration", "GetGeoIPBlocklistDatabaseConfiguration", "GetGeoIPWhitelist", "GetGeoIPAllowlist", "ExportGeoIPWhitelistDatabase","ExportGeoIPAllowlistDatabase", "GetGeoDNSSECConfiguration", "GetGeoLmMiscParameter", "GetVSPacketFilterACL", "GetPacketFilterOption", "GetGlobalPacketFilterACL", "GetLmIPConnectionLimit", "GetAzureHAConfiguration", "GetAwsHaConfiguration", "GetLmCloudHaConfiguration", "GetLmDebugInformation", "GetAslLicenseType", "GetLmVpnIkeDaemonStatus", "NewLmVpnConnection", "GetClusterStatus", "NewCluster", "GetRaidController", "GetRaidControllerDisk", "GetExtEspLogConfiguration", "GetLmLogFilesList", "GetLmLogResetFilesList", "GetLmExtendedLogFilesList", "GetLmExtendedLogResetFilesList", "GetLmApiList", "NewApiSec_curityKey", "GetApiSecurityKeys", "RemoveApiSecurityKeys", "GetAdcLimitRules", "GetClientCPSLimit", "GetClientRPSLimit", "GetClientMaxcLimit", "GetClientBandwidthLimit", "GetMode", "GetNamespace", "GetWatchTimeout", "GetContext", "GetLECertificate", "GetLEAccountInfo") } {
			$errMsg = $xmlAnsw.Response.Error
		}

		{ ($_ -in "RemoveAdcVS") } {
			$errMsg = $xmlAnsw.Response.Error
			if ($errMsg -and $errMsg.Contains("Unknown VS")) {
				$errMsg += ". Has it already been deleted?"
			}
		}

		{ ($_ -in "SetInitialPasswd") } {
			if ($xmlAnsw.Response.stat -eq 405) {
				$errMsg = "Method not allowed"
			}
			elseif ($xmlAnsw.Response.stat -eq 500) {
				$errMsg = "Method not allowed"
			}
			else {
				$errMsg = $xmlAnsw.Response.Error
			}
		}

		{ ($_ -in "GetGeoCluster") } {
			$errMsg = $xmlAnsw.Response.Error
			if ($errMsg -and $errMsg.Contains("No geo data found")) {	#NOTE: this must be fixed on the LM side
				$errMsg = "Cluster NOT found."
			}
		}

		{ ($_ -in "NewVSPacketFilterACL", "NewGlobalPacketFilterACL") } { #NOTE: this must be fixed on the LM side
			$errMsg = $xmlAnsw.Response.Error
			if ($errMsg -and $errMsg.Contains("Invalid address")) {
				$xmlAnsw.Response.stat = "422"
				if ($errMsg.Contains("+")) {
					$errMsg = "Invalid Virtual Service."
				}
				else {
					$errMsg = "Invalid ACL address."
				}
			}
		}

		{ ($_ -in "RemoveVSPacketFilterACL") } {
			$errMsg = $xmlAnsw.Response.Error
			if ($errMsg -and $errMsg.Contains("vipdump")) {	#NOTE: this must be fixed on the LM side
				$errMsg = "Invalid Virtual Service."
			}
		}

		{ ($_ -in "PingHost") } {
			$errMsg = "Command Failed"
			if ($xmlAnsw.Response.Error) {
				if ($xmlAnsw.Response.Error.Contains("Invalid address format")) {
					$errMsg += ": Invalid address format"
				}
				elseif ($xmlAnsw.Response.Error.Contains("Unknown command")) {
					$errMsg += ": Unknown command"
				}
				else {
					$pingErrorObject = SetPingErrorResponse $xmlAnsw.Response.Error
				}
			}
			setKempAPIReturnObject $xmlAnsw.Response.stat "$errMsg" $pingErrorObject
			return
		}

		default {
			$errMsg = "[HandleErrorAnswer] Unknown Object class [$Command2ExecClass]"
		}
	}
	setKempAPIReturnObject $xmlAnsw.Response.stat "$errMsg" $null
}

# Internal use only
Function isXml($rawData)
{
	if ($rawData) {
		try {
			$xmlData = [xml]$rawData
			return $true
		}
		catch {
			return $false
		}
	}
	return $false
}

# Internal use only
Function getXmlData($rawData)
{
	if ($rawData) {
		if ( (isXml $rawData) ) {
			$xmlData = [xml]$rawData
			return $xmlData
		}
		else {
			try {
				$rt = $rawData.Response.stat
				if ($rt -eq 200 -or $rt -ge 400) {
					return $rawData
				}
				else {
					return $null
				}
			}
			catch {
				return $null
			}
		}
		return $null
	}
	return $null
}

# Internal use only
Function HandleLmAnswerSimpleAnswer
{
	Param(
		[Parameter(Mandatory=$true)]
		$LmResponse
	)

	$xmlAnsw = getXmlData $LmResponse
	if ($xmlAnsw) {
		if ($xmlAnsw.Response.stat -eq 200 -or $xmlAnsw.Response.stat -eq "ok") {
			$success = $xmlAnsw.Response.Success 
			setKempAPIReturnObject 200 "Command successfully executed." $success
		}
		else {
			$errMsg = ([xml]$LmResponse).Response.Error
			$errCode = ([xml]$LmResponse).Response.stat
			setKempAPIReturnObject $errCode "$errMsg" $null
		}
	}
	else {
		$check = checkLmOkResponse $LmResponse
		if ($check -eq $true) {
			$success = $xmlAnsw.Response.Success 
			setKempAPIReturnObject 200 "Command successfully executed." $success
		}
		else {
			# COMMON errors (i.e. Unauthorized)
			if ($Command2ExecClass -eq "ExportVSTemplate" -and $LmResponse -eq "Unauthorized") {
				$LmResponse = "The remote server returned an error: (401) Unauthorized."
			}
			$errMsg = $LmResponse
			$errCode = getErrorCode $errMsg
			setKempAPIReturnObject $errCode "$errMsg" $null
		}
	}
}

# Internal use only
Function HandleLmAnswer
{
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Command2ExecClass,

		[Parameter(Mandatory=$true)]
		$LmResponse,

		$AdditionalData
	)

	$xmlAnsw = getXmlData $LmResponse
	if ($xmlAnsw) {
		if ($xmlAnsw.Response.stat -eq 200 -or $xmlAnsw.Response.stat -eq "ok") {
			# command successfully executed: the answer can be cmdlet specific
			HandleSuccessAnswer $Command2ExecClass $xmlAnsw $AdditionalData
		}
		else {
			# command failure: the error can be cmdlet specific
			HandleErrorAnswer $Command2ExecClass $xmlAnsw
		}
	}
	else {
		$check = checkLmOkResponse $LmResponse
		if ($check -eq $true) {
			setKempAPIReturnObject 200 "Command successfully executed." $null
		}
		else {
			# COMMON errors (i.e. Unauthorized)
			if ($Command2ExecClass -eq "ExportVSTemplate" -and $LmResponse -eq "Unauthorized") {
				$LmResponse = "The remote server returned an error: (401) Unauthorized."
			}
			$errMsg = $LmResponse
			$errCode = getErrorCode $errMsg
			setKempAPIReturnObject $errCode "$errMsg" $null
		}
	}
}

# --------------------------------------------------------------------------------------------
# SendCmdToLm helper functions
# --------------------------------------------------------------------------------------------
# Internal use only
Function validateFile2Upload($file, $Output)
{
	if ($file -and -not($Output)) {
		if ( -not (Test-Path -Path $file) ) {
			$errStr = "ERROR: The input file does not exist. Please check your input."
			Write-Verbose $errStr
			Throw $errStr
		}
	}
}

# Internal use only
Function validateDownloadFileName($Output)
{
	if ($Output) {
		# FIXME To check:
		#       1) if the containing folder exist
		#       2) if it's possible to write in that folder
		#
	}
}

# Internal use only
Function SetSingleParamUrl($LmIp, $LmPort, $Cmd, $ParamName, $ParamValue)
{
	$tmpUrl = New-Object Text.StringBuilder

	$tmpUrl.Append("https://$LmIp`:$LmPort/access/$Cmd`?") | Out-Null

	if ($ParamValue) {
		$tmpUrl.Append("param=$ParamName&value=$ParamValue") | Out-Null
	}
	else {
		if ($ParamName) {
			$tmpUrl.Append("param=$ParamName") | Out-Null
		}
		else {
			if ($Cmd -eq "Get" -or $Cmd -eq "get") {
				$errStr = "ERROR: missing parameter name."
				Write-Verbose $errStr
				Throw $errStr
			}
			else {
				# NOTHING TODO
			}
		}
	}
	$url = $tmpUrl.ToString() -replace "\&$"

	$urlLen = $url.Length
	$urlLastChar = $url[$urlLen - 1]
	if ($urlLastChar -eq "?") {
		$url = $url.Substring(0, $urlLen - 1)
	}
	Write-Verbose "[SetSingleParamUrl] command url: $url"

	return $url
}

# Internal use only
Function SetMultipleParamUrl($LmIp, $LmPort, $Cmd, $ParamValuePair)
{
	$tmpUrl = New-Object Text.StringBuilder
	$tmpUrl2Print = New-Object Text.StringBuilder

	$tmpUrl.Append("https://$LmIp`:$LmPort/access/$Cmd`?") | Out-Null
	$tmpUrl2Print.Append("https://$LmIp`:$LmPort/access/$Cmd`?") | Out-Null

	ForEach ($key in $ParamValuePair.keys) {

		if ($key -eq "password" -or $key -eq "passwd") {
			Write-Verbose "ParamName=`"$key`" - ParamValue=`"*****`""
			$tmpUrl2Print.Append("$key=*****&") | Out-Null
		}
		else {
			Write-Verbose "ParamName=`"$key`" - ParamValue=`"$($ParamValuePair[$key])`""
			$tmpUrl2Print.Append("$key=$($ParamValuePair[$key])&") | Out-Null
		}
		$tmpUrl.Append("$key=$($ParamValuePair[$key])&") | Out-Null
	}
	$url = $tmpUrl.ToString() -replace "\&$"
	$url2print = $tmpUrl2Print.ToString() -replace "\&$"

	$urlLen = $url.Length
	$urlLastChar = $url[$urlLen - 1]
	if ($urlLastChar -eq "?") {
		$url = $url.Substring(0, $urlLen - 1)
	}

	$urlLen = $url2print.Length
	$urlLastChar = $url2print[$urlLen - 1]
	if ($urlLastChar -eq "?") {
		$url2print = $url2print.Substring(0, $urlLen - 1)
	}
	Write-Verbose "[SetMultipleParamUrl] command url: $url2print"

	return $url
}

# Internal use only
Function SetCmdUrl($PSetName, $LmIp, $LmPort, $Command, $ParameterValuePair, $ParameterName, $ParameterValue)
{
	if ($PSetName -eq "SingleParam") {
		$url = SetSingleParamUrl $LmIp $LmPort $Command $ParameterName $ParameterValue
	}
	elseif ($PSetName -eq "MultiParam") {
		$url = SetMultipleParamUrl $LmIp $LmPort $Command $ParameterValuePair
	}
	else {
		$errStr = "ERROR: NULL parameter set."
		Write-Verbose $errStr
		Throw $errStr
	}
	return $url
}

# Internal use only
Function SetBaseUrl($LmIp, $LmPort, $Cmd)
{
	$tmpUrl = New-Object Text.StringBuilder

	$tmpUrl.Append("https://$LmIp`:$LmPort/access/$Cmd`?") | Out-Null

	$url = $tmpUrl.ToString() -replace "\&$"

	$urlLen = $url.Length
	$urlLastChar = $url[$urlLen - 1]
	if ($urlLastChar -eq "?") {
		$url = $url.Substring(0, $urlLen - 1)
	}
	return $url
}

# Internal use only
Function CreateLmHttpsRequest($url, $cred, $loginCert, $loginCertStore)
{
	if (([String]::IsNullOrEmpty($url))) {
		$errStr = "ERROR: the url to connect to is null."
		Write-Verbose $errStr
		Throw $errStr
	}

	[System.Net.ServicePointManager]::Expect100Continue = $true
	[System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
	Write-Verbose "setting ServerCertificateValidationCallback to TRUE."
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	[System.Net.ServicePointManager]::SecurityProtocol = 'Tls11','Tls12'

	$request = [System.Net.HttpWebRequest]::Create($url)
	$request.UserAgent = "KempLoadBalancerPowershellModule"
	$request.KeepAlive = $false

	if (-not ([String]::IsNullOrEmpty($loginCert))) {

		$LCert = Get-LoginCertificate $loginCertStore $loginCert
		if ($LCert -ne $null) {
			$tmp = $request.ClientCertificates.Add($LCert)
		}
		else {
			$errStr = "ERROR: Can't find certificate with $SubjectCN."
			Write-Verbose $errStr
			Throw $errStr
		}
		Write-Verbose "Running the API command using the certificate `"$loginCert`" as login credential."
	}
	else {
		if ($cred) {
			Write-Verbose "Running the API command using the specified login/password (user: `"$($cred.UserName)`") as login credential."
			$request.Credentials = $cred
		}
		else {
			Write-Verbose "WARNING: Running the API command with NO credential. Is it OK?"
		}
	}
	return $request
}

# Internal use only
Function UploadFile2Lm($File, $request)
{
	Write-Verbose "There is a file to upload."

	if (-not (Test-Path $File) ) {
		Throw "ERROR: the file $File does not exist"
		return
	}

	$fd = Get-Item -Path $File

	$datalength = $fd.Length
	Write-Verbose "File length: $datalength"

	#$request.SendChunked = $true
	$request.KeepAlive = $false
	$request.Timeout = 500000

	#$request.protocolversion = [System.Net.HttpVersion]::Version10

	$request.method = "POST"
	$request.ContentType = "application/x-www-form-urlencoded"

	Write-Verbose "Reading file..."

	$dn = $fd.DirectoryName
	$fn = $fd.Name
	$ft = $dn + "\" + $fn
	Write-Verbose "File to upload: $ft"

	$fileStream = New-Object IO.FileStream($ft, "Open", "Read")
	$binaryReader = New-Object IO.BinaryReader($fileStream)
	$data = $binaryReader.ReadBytes([int]$datalength)

	Write-Verbose "Cleaning up readers."
	$binaryReader.close()

	Write-Verbose "Getting request stream."
	$stream = $request.GetRequestStream()
	$binaryWriter = New-Object IO.BinaryWriter($stream)

	$sd = date -Format HH:mm:ss:ms
	Write-Verbose "START Writing the data to the stream (time: $sd)"
	$binaryWriter.Write($data, 0, $data.length)
	$ed = date -Format HH:mm:ss:ms
	Write-Verbose "END Writing the data to the stream (time: $ed)"

	$binaryWriter.Flush()
	$binaryWriter.Close()
}

# Internal use only
Function SendPostRequest($request, $PSetName, $ParameterValuePair, $ParameterName, $ParameterValue)
{
	$body = ""
	if ($PSetName -eq "SingleParam") {
		$body = "$ParameterName=$ParameterValue"
	}
	elseif ($PSetName -eq "MultiParam") {
		ForEach ($key in $ParameterValuePair.keys) {
			$value = $ParameterValuePair[$key]
			if ($body -ne "") {
				$body = "$body&$key=$value"
			}
			else {
				$body = "$key=$value"
			}
		}
	}
	else {
		$errStr = "ERROR: NULL parameter set."
		Write-Verbose $errStr
		Throw $errStr
	}
	Write-Verbose "body == `"$body`""
	$body_len = $body.Length
	$request.KeepAlive = $false
	$request.Timeout = 500000
	$request.method = "POST"
	$request.ContentType = "text/xml"
	$stream = $request.GetRequestStream()
	$binaryWriter = New-Object IO.BinaryWriter($stream)
	$binaryWriter.Write($body, 0, $body_len)
	$binaryWriter.Flush()
	$binaryWriter.Close()
}

# Internal use only
Function SetLoginConnectionErrorAnswer($ExError)
{
	$errMsg1 = $ExError.Exception.Message
	$errMsg2 = $ExError.Exception.InnerException.Message

	if (!$errMsg2) {
		if ($LmTestServerConnectionFlag -eq $false) {
			Write-Verbose "Exception Message......: [$errMsg1]."
		}
		$response = $ExError.Exception.Response
	}
	else {
		Write-Verbose "Inner Exception Message: [$errMsg2]."
		$response = $null
	}
	Write-Verbose "setting ServerCertificateValidationCallback to NULL."
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
	return $response
}

# Internal use only
Function CloseConnectionWithLm($reader, $stream, $filestream, $response)
{
	Write-Verbose "setting ServerCertificateValidationCallback to NULL."
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

	Write-Verbose "closing connection."
	if ($reader) {
		$reader.Close()
		$reader.Dispose()
	}

	if ($stream) {
		$stream.Close()
		$stream.Dispose()
	}

	if ($fileStream) {
		$fileStream.Close()
		$fileStream.Dispose()
	}

	if ($response) {
		$response.Close()
		$response.Dispose()
	}
}

# Internal usage only
Function WriteOutputFile($response, $fileName)
{
	$datalength = $response.ContentLength
	$reader     = $response.GetResponseStream()

	try {
		$writer = New-Object io.FileStream $fileName, "Create"
		$buffer = New-Object byte[] 4096

		do {
			$count = $reader.Read($buffer, 0, $buffer.length)
			$writer.Write($buffer, 0, $count)
		} while ($count -gt 0)

		$writer.Flush()
		$writer.Close()
	}
	catch {
		if ($_.Exception.InnerException) {
			$errorAnswer = $_.Exception.InnerException
		}
		else {
			$errorAnswer = $_.Exception.Message
		}
		Write-Verbose "errorAnswer: $errorAnswer"
		return $errorAnswer
	}
}

# Internal usage only
Function writeDataFromLm2File($file, $Force, $response)
{
	$check = ""
	$fileCheck = Test-Path -Path $file

	if ($file[0] -eq ".") {
		if ($file[1] -eq ".") {
			$d = Get-Location
			$file = $d.Path + "\" + $file
		}
		else {
			$d = Get-Location
			$file = $d.Path + $file.Substring(1)
		}
	}

	if ($file[1] -ne ":") {
		$d = Get-Location
		$file = $d.Path + "\" + $file.Substring(0)
	}

	Write-Verbose "File to write: $file"

	if (-not $fileCheck) { # The output file does not exist
		$check = WriteOutputFile $response $file
		if ($check) {
			return $check
		}
	}
	else {
		if ($Force) { # The output file exists and force is true
			$check = WriteOutputFile $response $file
			if ($check) {
				return $check
			}
		}
		else { # The output file exists and force is false
			$eStr1 = "ERROR: The specified file already exists."
			$eStr2 = "To use the same filename, either delete the file or use the -Force switch."
			$errorAnswer = "$eStr1 $eStr2"
			Write-Verbose "errorAnswer: $errorAnswer"
			return $errorAnswer
		}
	}
	return ""
}

# Internal use only
Function uploadGeoDnssecKeyFiles($url, $privateKeyFile, $publicKeyFile, $creds, $cert, $certStore)
{
	[System.Net.ServicePointManager]::Expect100Continue = $true
	[System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
	Write-Verbose "setting ServerCertificateValidationCallback to TRUE."
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	[System.Net.ServicePointManager]::SecurityProtocol = 'Tls11','Tls12'

	$pageCoding = "UTF-8"
	$enc = [System.Text.Encoding]::GetEncoding($pageCoding)

	$pubKF = Get-Item -Path $publicKeyFile
	$fileBin1 = [System.IO.File]::ReadAllBytes($pubKF.FullName)
	$fileEnc1 = $enc.GetString($fileBin1)

	$privKF = Get-Item -Path $privateKeyFile
	$fileBin2 = [System.IO.File]::ReadAllBytes($privKF.FullName)
	$fileEnc2 = $enc.GetString($fileBin2)

  $LF = "`r`n"
  $boundary = [System.Guid]::NewGuid().ToString()

	$bodyLines = (
		"--$boundary",
		"Content-Disposition: form-data; name=`"publickey`"; filename=`"publickey`"",
		"Content-Type: application/octet-stream$LF", $fileEnc1,
		"--$boundary",
		"Content-Disposition: form-data; name=`"privatekey`"; filename=`"privatekey`"",
		"Content-Type: application/octet-stream$LF", $fileEnc2,
		"--$boundary--$LF"
	) -join $LF

	$ct = "multipart/form-data; boundary=`"$boundary`""
	$params = @{
		Uri = $url
		Method = "Post"
		ContentType = $ct
		Body = $bodyLines
	}
	if ($creds) {
		$params.Add("Credential", $creds)
	}
	else {
		$rCert = Get-LoginCertificate $certStore $cert
		if ($rCert) {
			$params.Add("Certificate", $rCert)
		}
		else {
			Throw "ERROR: the provide certificate and/or its location is invalid"
			return
		}
	}

	try {
		$response = Invoke-RestMethod @params
	}
	catch {
		if ( ($_.Exception.Message) -and
		     ($_.Exception.Message -is [string]) -and
				 (($_.Exception.Message.Contains("Unable to connect")) -or
				  ($_.Exception.Message.Contains("could not be resolved")) -or
		      ($_.Exception.Message.Contains("Unauthorized")))) {
			$errorAnswer = $_.Exception.Message
			Write-Verbose "ERROR: $errorAnswer"
			Write-Verbose "setting ServerCertificateValidationCallback to NULL."
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
			Throw $errorAnswer
			return
		}
		try {
			$result = $_.Exception.Response.GetResponseStream()
		}
		catch {
			$errorAnswer = $_.Exception.Message
			Write-Verbose "ERROR: $errorAnswer"
			Write-Verbose "setting ServerCertificateValidationCallback to NULL."
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
			Throw $errorAnswer
			return
		}
		$reader = New-Object System.IO.StreamReader($result)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Verbose "ERROR: $responseBody"
		Write-Verbose "setting ServerCertificateValidationCallback to NULL."
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
		return $responseBody
	}
	Write-Verbose "$($response.Innerxml)"
	Write-Verbose "setting ServerCertificateValidationCallback to NULL."
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
	return $response
}

# Internal use only
# This function sends the command to the LM
Function SendCmdToLm
{
	[CmdletBinding(DefaultParameterSetName="SingleParam")]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Command,

		[Parameter(ParameterSetName="SingleParam")]
		[string]$ParameterName,

		[Parameter(ParameterSetName="SingleParam")]
		[string]$ParameterValue,

		[Parameter(ParameterSetName="MultiParam")]
		[hashtable]$ParameterValuePair,

		[Parameter(ParameterSetName="MultiParam")]
		[string]$File,

		[hashtable]$ConnParams,

		[switch]$Output,
		[switch]$pTest,
		[switch]$Post
	)

	if ($ConnParams) {
		if ($ConnParams.ContainsKey("LmIp")) {
			$LmIp = $ConnParams.Get_Item("LmIp")
		}
		if ($ConnParams.ContainsKey("LmPort")) {
			$LmPort = $ConnParams.Get_Item("LmPort")
		}
		if ($ConnParams.ContainsKey("Cred")) {
			$Credential = $ConnParams.Get_Item("Cred")
		}
		if ($ConnParams.ContainsKey("SubjectCN")) {
			$SubjectCN = $ConnParams.Get_Item("SubjectCN")
		}
		if ($ConnParams.ContainsKey("CertLoc")) {
			$CertLoc = $ConnParams.Get_Item("CertLoc")
		}
	}

	if ($script:cred -eq $Credential -and ($SubjectCN -and $script:SubjectCN -ne $SubjectCN) ) {
		# this is an overwrite of the stored credentials with a local login certificate
		$Credential = $null
	}

	if ($script:SubjectCN -eq $SubjectCN -and ($Credential -and $script:cred -ne $Credential) ) {
		# this is an overwrite of the stored certificate with local credentials
		$SubjectCN = $null
	}

	Write-Verbose "Input params are OK, moving on . . ."

	# the following function can throw
	if (-not $Post) {
		$url = SetCmdUrl $PsCmdlet.ParameterSetName $LmIp $LmPort $Command $ParameterValuePair $ParameterName $ParameterValue
	}

	if ($pTest) {		# Testing purpose: don't remove
		return $true
	}

	$response = $null
	$errorAnswer = $null
	try {
		if ($Post) {
			$url = SetBaseUrl $LmIp $LmPort $Command
			Write-Verbose "POST requested . . . "
			Write-Verbose "URL: $url"
			$request = CreateLmHttpsRequest $url $Credential $SubjectCN $CertLoc
			SendPostRequest $request $PsCmdlet.ParameterSetName $ParameterValuePair $ParameterName $ParameterValue
		}
		else {
			$request = CreateLmHttpsRequest $url $Credential $SubjectCN $CertLoc
		}

		if (($File) -and (-not ($Output))) {
			UploadFile2Lm $File $request
		}

		$response = $request.GetResponse()
		Write-Verbose "Response received."

		$HTTP_STATUS = $response.StatusCode
		Write-Verbose "HTTP STATUS: $HTTP_STATUS"
	}
	catch [Exception] {
		$err = $_		# we need to save the exception object for further procesing
		$errorAnswer = SetLoginConnectionErrorAnswer $err
	}

	finally {
		if (!$response) {
			if (!$errorAnswer) {
				CloseConnectionWithLm $reader $stream $filestream $response
				Throw $err.Exception.Message
			}
			else {
				$response = $errorAnswer
			}
		}

		try {
			$stream = $response.GetResponseStream()
		}
		catch {
			CloseConnectionWithLm $reader $stream $filestream $response
			$errorAnswer = $_.Exception.Message
			Write-Verbose "errorAnswer (2): $errorAnswer"
			Throw $errorAnswer
		}

		$found = $false
		if ($response.contenttype -eq "text/xml") {
			$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
			$reader = New-Object system.io.StreamReader($stream, $Encoding)
			$result = $reader.REadToEnd()

			if (-not ($Command.Contains("eula"))) {
				Write-Verbose "result: $result"
			}
			Write-Output $result

			$found = $true
		}

		if (-not ($found) -and
		    ($response.ContentType -eq "application/octet-stream" -or
		    $response.ContentType -eq "application/x509-cert" -or
		    $response.ContentType -eq "application/vnd.tcpdump.pcap" -or
		    $Command -eq "exportvstmplt")) {
			if ($response.StatusCode -eq 200) {
				try {
					$errorAnswer = writeDataFromLm2File $file $Force $response
					if ($errorAnswer -ne "") {
						CloseConnectionWithLm $reader $stream $filestream $response
						Throw $errorAnswer
					}
				}
				catch {
					CloseConnectionWithLm $reader $stream $filestream $response
					Throw $errorAnswer
				}
			}
			Write-Output $response.StatusCode

			$found = $true
		}

		if (-not $found) {
			$errorString = [string]$err
			Write-Output $errorString
		}
		CloseConnectionWithLm $reader $stream $filestream $response
	}
}

# Internal use only
Function ConvertBoundParameters
{
	[CmdletBinding()]
	Param(
		[hashtable]$hashtable,

		[switch]$SkipEncoding,

		[string[]]$DontEncode
	)

	$propertyTable = @{}

	foreach ($param in $IgnoredParameters) {
		$hashtable.Remove($param)
	}

	foreach ($param in $hashtable.keys) {
		if ($hashtable[$param] -is [bool]) {
			if ($ParamReplacement.Keys -contains $param) {
				$paramValue = $hashtable[$param] -as [int]
				$param = $ParamReplacement[$param]
				$propertyTable.Add($param, $paramValue)
			}
			else {
				$propertyTable.Add(($param), $hashtable[$param] -as [int])
			}
		}
		else {
			if ($SkipEncoding -eq $false ) {
				if($DontEncode){
					if ($param -In $DontEncode){
						$value = $hashtable[$param]
					}
					else{
						$value = [System.Web.HttpUtility]::UrlEncode($hashtable[$param])
					}
				}
				else{
					$value = [System.Web.HttpUtility]::UrlEncode($hashtable[$param])
				}
			}
			else {
				$value = $hashtable[$param]
			}

			if ($param -eq "BondMode") {
				if ($hashtable[$param].ToLowerInvariant() -eq "802.3ad") {$value = 4}
				if ($hashtable[$param].ToLowerInvariant() -eq "active-backup") {$value = 1}
			}

			if ($ParamReplacement.Keys -contains $param) {
				# Special case: Add the "!" prefix to the RSIndex value.
				if ($param -eq "RSIndex") {
					$value = "!" + $value
				}
				$param = $ParamReplacement[$param]
			}
			$propertyTable.Add($param, $value)
		}
	}
	return $propertyTable
}

# Internal usage only
Function CheckLmConnection($LmIp, $LmNewIp, $LmPort)
{
	$check = $true
	$counter = 2
	$connStatus = $true
	while ($check) {
		if (-not (Test-LmServerConnection -ComputerName $LmIp -Port $LmPort)) {
			$connStatus = $false
			Start-Sleep -s 5
			$counter -= 1
			if ($counter -eq 0) {
				$check = $false
			}
		}
		else {
			$connStatus = $true
			$check = $false
		}
	}

	if ($connStatus -eq $false) {
		$check = $true
		$counter = 5
		$LmIp = $($LmNewIp.Split('/'))[0]
		while ($check) {
			if (-not (Test-LmServerConnection -ComputerName $LmIp -Port $LmPort)) {
				Start-Sleep -s 5
				$counter -= 1
				if ($counter -eq 0) {
					$check = $false
				}
			}
			else {
				$check = $false
				$connStatus = $true
			}
		}
	}

	if ($connStatus -eq $false) {
		Throw "ERROR: not able to reconnect to the LM"
	}
	else {
		$LmIp
	}
}

# Internal usage only
Function throwIfEmpty($param)
{
	if ( ([String]::IsNullOrEmpty($param)) ) {
		Throw "ERROR: $param is a required parameter"
	}
}

# endregion - UTILITY FUNCTION


# ==================================================
# region - EULA
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Read-LicenseEULA
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $null $null $null $null "skipLoginCheck"
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential

	try {
		$response =	SendCmdToLm -Command "readeula" -ParameterValuePair $params -ConnParams $ConnParams
		SetEulaResponseObject $response "Eula"
	}
	catch {
		SetEulaErrorResponseObject $_.Exception.Message
	}
}
Export-ModuleMember -function Read-LicenseEULA

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Confirm-LicenseEULA
{
	[CmdletBinding()]
	Param(
		[ValidateSet("trial", "perm", "free")]
		[String]$Type = "trial",

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Magic,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,
		
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $null $null $null $null "skipLoginCheck"
	$propertyTable = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential

	try {
		$response =	SendCmdToLm -Command "accepteula" -ParameterValuePair $propertyTable -ConnParams $ConnParams
		SetEulaResponseObject $response "Eula2"
	}
	catch {
		SetEulaErrorResponseObject $_.Exception.Message
	}
}
Export-ModuleMember -function Confirm-LicenseEULA

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Confirm-LicenseEULA2
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Magic,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("yes", "no")]
		[String]$Accept,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $null $null $null $null "skipLoginCheck"
	$propertyTable = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential

	try {
		$response =	SendCmdToLm -Command "accepteula2" -ParameterValuePair $propertyTable -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		SetEulaErrorResponseObject $_.Exception.Message
	}
}
Export-ModuleMember -function Confirm-LicenseEULA2

# ==================================================
# endregion - EULA
# ==================================================


# ==================================================
# region - LICENSE
# ==================================================

Function Set-LicenseInitialPassword
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Passwd,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $null $null $null $null "skipLoginCheck"
	$propertyTable = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential

	try {
		$response =	SendCmdToLm -Command "set_initial_passwd" -ParameterValuePair $propertyTable -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "SetInitialPasswd" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 $errMsg $null
	}
}
Export-ModuleMember -function Set-LicenseInitialPassword

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Request-LicenseOnline
{
	[CmdletBinding()]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,

		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$KempId = $KempId,

		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$Password = $Password,

		[ValidateNotNullOrEmpty()]
		[string]$OrderId,

		[ValidateNotNullOrEmpty()]
		[string]$LicenseTypeId,

		[string]$http_proxy
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $null $null $null $null "skipLoginCheck"
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential

	if ($LicenseTypeId) {
		$params.Remove("LicenseTypeId")
		$params.Add("licensetypeid", $LicenseTypeId)
	}

	try {
		$response = SendCmdToLm -Command "alsilicense" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errorString = $_.Exception.Message
		$errorCode = GetLicenseCmdErrorCode $errorString
		setKempAPIReturnObject $errorCode "$errorString" $null
	}
}
Export-ModuleMember -function Request-LicenseOnline

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Request-LicenseOffline
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $null $null $null $null "skipLoginCheck"
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential

	try {
		$response = SendCmdToLm -Command "license" -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		if ($errMsg -eq "ERROR: The input file does not exist. Please check your input.") {
			Throw $errMsg
		}
		$errorString = $_.Exception.Message
		$errorCode = GetLicenseCmdErrorCode $errorString
		setKempAPIReturnObject $errorCode "$errorString" $null
	}
}
Export-ModuleMember -function Request-LicenseOffline

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LicenseAccessKey
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -command "accesskey" -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLicenseAccessKey" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LicenseAccessKey

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LicenseType
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$KempId = $KempId,

		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$Password = $Password,

		[ValidateNotNullOrEmpty()]
		[string]$OrderId,

		[ValidateNotNullOrEmpty()]
		[string]$http_proxy,

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
	validateCommonInputParams $LoadBalancer $LBPort $null $null $null $null $null "skipLoginCheck"

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -command "alsilicensetypes" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLicenseType" -LMResponse $response -AdditionalData $OrderId
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LicenseType

Function Get-LicenseInfo
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -command "licenseinfo" -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLicenseInfo" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LicenseInfo

Function Update-LicenseOnline
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$KempId = $KempId,

		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Password = $Password,

		[ValidateNotNullOrEmpty()]
		[string]$OrderId,

		[string]$http_proxy,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ($OrderId) {
		$params.Remove("OrderId")
		$params.Add("orderid", $OrderId)
	}

	try {
		$response = SendCmdToLm -command "alsilicense" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		$errCode = GetLicenseCmdErrorCode $errMsg
		setKempAPIReturnObject $errCode "$errMsg" $null
	}
}
Export-ModuleMember -function Update-LicenseOnline

Function Update-LicenseOffline
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "license" -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		if ($errMsg -eq "ERROR: The input file does not exist. Please check your input.") {
			Throw $errMsg
		}
		$errCode = GetLicenseCmdErrorCode $errMsg
		setKempAPIReturnObject $errCode "$errMsg" $null
	}
}
Export-ModuleMember -function Update-LicenseOffline

Function Request-LicenseOnPremise
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$aslhost,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(1, 65535)]
		[int]$aslport,

		[ValidateNotNullOrEmpty()]
		[string]$LicenseTypeId,

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
	validateCommonInputParams $LoadBalancer $LBPort $null $null $null $null $null "skipLoginCheck"
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($LicenseTypeId) {
		$params.Remove("LicenseTypeId")
		$params.Add("lic_type_id", $LicenseTypeId)
	}

	try {
		$response = SendCmdToLm -Command "aslactivate" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "RequestLicenseOnPremise" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Request-LicenseOnPremise

Function Get-AslLicenseType
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		#[ValidateNotNullOrEmpty()]
		#[String]$aslipaddr,

		[ValidateNotNullOrEmpty()]
		[String]$aslhost,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(1, 65535)]
		[int]$aslport,

		#[ValidateNotNullOrEmpty()]
		#[String]$aslname,

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
	validateCommonInputParams $LoadBalancer $LBPort $null $null $null $null $null "skipLoginCheck"
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	try {
		$response = SendCmdToLm -Command "aslgetlicensetypes" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAslLicenseType" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AslLicenseType

Function Stop-AslInstance
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "killaslinstance" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Stop-AslInstance

Function Remove-SplaInstance
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$KempId = $KempId,

		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Password = $Password,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("KempId")
	$params.Add("name", $KempId)
	$params.Remove("Password")
	$params.Add("passwd", $Password)
	$params.Add("kill", 1)

	try {
		$response = SendCmdToLm -Command "kill_spla_instance" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswerSimpleAnswer -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-SplaInstance

Function Remove-Instance
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[string]$KempId = $KempId,

		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Password = $Password,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("KempId")
	$params.Add("name", $KempId)
	$params.Remove("Password")
	$params.Add("passwd", $Password)
	$params.Add("kill", 1)

	try {
		$response = SendCmdToLm -Command "kill_instance" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswerSimpleAnswer -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-Instance

# ==================================================
# endregion - LICENSE
# ==================================================


# ==================================================
# region TEMPLATES
# ==================================================

# Internal use only
Function setExportVsTemplatesInputParams($VirtualService, $VSIndex, $Port, $Protocol, $params)
{
	if ($VirtualService -and $VSIndex) {
		Throw "Cannot set both parameters VirtualService and VSIndex"
	}

	if ($VirtualService) {
		if ($Port -and $Protocol) {
			$params.Add("vs", $VirtualService)
		}
		else {
			Throw "Cannot set VirtualService without Port and Protocol"
		}
	}
	elseif ($VSIndex) {
		$params.Add("vs", $VSIndex)
		return
	}
	else {
		Throw "One parameter VirtualService or VSIndex must be set"
	}

	if ($Port) {
		if ($Port -lt 3 -or $Port -gt 65530) {
			Throw "The port value is less than the minimum allowed value (0) or it is greater than the maximun allowed value (65530)"
		}
		if ($Protocol) {
			$params.Add("port", $Port)
			$params.Add("prot", $Protocol)
		}
		else {
			Throw "The port/protcol parameters must be specified"
		}
		$check = $true
	}
	else {
		if ($protocol) {
			Throw "The port/protcol parameters must be specified"
		}
	}
}

Function Export-VSTemplate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = @{}
	setExportVsTemplatesInputParams $VirtualService $VSIndex $Port $Protocol $params

	try {
		$response = SendCmdToLm -Command "exportvstmplt" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "ExportVSTemplate" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-VSTemplate, ExportVSTemplate

Function Install-Template
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "uploadtemplate" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "InstallTemplate" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-Template, UploadTemplate

Function Remove-Template
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "deltemplate" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-Template, DeleteTemplate

Function Get-Template
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "listtemplates" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetTemplate" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-Template, ListTemplates

# ==================================================
# endregion TEMPLATES
# ==================================================


# ==================================================
# region LOGGING
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LogEmailConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params2get = @("EmailEnable", "EmailServer", "EmailPort", "EmailUser", "EmailPassword", "EmailDomain", "EmailSSLMode",
	                "EmailEmergency", "EmailCritical", "EmailError", "EmailWarn", "EmailNotice", "EmailInfo")

	$ht = [ordered]@{}
	$ht.PSTypeName = "EmailConfiguration"
	foreach($param in $params2get) {
		$params.Add("param", $param)

		$lma = Get-LmParameter @params
		if ($lma.ReturnCode -eq 200) {
			$paramValue = $lma.Data.$param
			$ht.Add($param, $paramValue)
		}
		else {
			return $lma
		}
		$params.Remove("param")
		Start-Sleep -m 200
	}
	$tmpObj = New-Object -TypeName PSObject -Property $ht

	$emConf = [ordered]@{}
	$emConf.PSTypeName = "EmailConfiguration"
	$emConf.Add("EmailConfiguration", $tmpObj)
	$emConfObject = New-Object -TypeName PSObject -Property $emConf

	setKempAPIReturnObject 200 "Command successfully executed" $emConfObject
}
Export-ModuleMember -function Get-LogEmailConfiguration, Get-EmailOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LogEmailConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	foreach($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$paramValue = $parameters2set[$param]
		$params.Add("value", "$paramValue")

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")
		Start-Sleep -m 200
	}

	Get-LogEmailConfiguration @params
}
Export-ModuleMember -function Set-LogEmailConfiguration, Set-EmailOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LogSyslogConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params2get = @("SyslogEmergency", "SyslogCritical", "SyslogError", "SyslogWarn", "SyslogNotice", "SyslogInfo", "SyslogPort")

	$ht = [ordered]@{}
	$ht.PSTypeName = "SyslogSettings"
	foreach($param in $params2get) {
		$params.Add("param", $param)

		$lma = Get-LmParameter @params
		if ($lma.ReturnCode -eq 200) {
			$paramValue = $lma.Data.$param
			$ht.Add($param, $paramValue)
		}
		else {
			return $lma
		}
		$params.Remove("param")
		Start-Sleep -m 200
	}
	$tmpObj = New-Object -TypeName PSObject -Property $ht

	$syslogConf = [ordered]@{}
	$syslogConf.PSTypeName = "SyslogSettings"
	$syslogConf.Add("SyslogSettings", $tmpObj)
	$syslogConfObject = New-Object -TypeName PSObject -Property $syslogConf

	setKempAPIReturnObject 200 "Command successfully executed" $syslogConfObject
}
Export-ModuleMember -function Get-LogSyslogConfiguration, Get-SyslogOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LogSyslogConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$SyslogCritical,
		[string]$SyslogEmergency,
		[string]$SyslogError,
		[string]$SyslogInfo,
		[string]$SyslogNotice,
		[string]$SyslogWarn,
		[string]$SysLogNone,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	foreach($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$paramValue = $parameters2set[$param]
		$params.Add("value", "$paramValue")

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")
		Start-Sleep -m 200
	}

	Get-LogSyslogConfiguration @params
}
Export-ModuleMember -function Set-LogSyslogConfiguration, Set-SyslogOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LogStatistics
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ((!$VirtualService) -and (!$Totals) -and (!$RealServer)) {
		$VirtualService = $true
		$Totals = $true
		$RealServer = $true
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$addData = [ordered]@{VS = $VirtualService; RS = $RealServer; Totals = $Totals;}

		$response = SendCmdToLm -Command "stats" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLogStatistics" -LMResponse $response -AdditionalData $addData
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-LogStatistics, Get-Statistics

Function Reset-LogStatistics
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$cmd = "logging/resetstats"
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Reset-LogStatistics

Function Export-LmWafDebugLogs
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Path,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$OutputFileName,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\LM-WafDebugLogs_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}

	if ($OutputFileName.Contains(".tar.gz") -eq $false) {
			$OutputFileName = $OutputFileName + ".tar.gz"
	}

	$Path = validatePath $Path $OutputFileName

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "logging/downloadwafdebuglogs" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Export-LmWafDebugLogs

Function Reset-LmWafDebugLogs
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$cmd = "logging/resetwafdebuglogs"
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Reset-LmWafDebugLogs

Function Get-EspExtendedLogConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$cmd = "logging/isextesplogenabled"
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetExtEspLogConfiguration" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-EspExtendedLogConfiguration

Function Set-EspExtendedLogConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateSet("yes", "no")]
		[string]$EspExtendedLogEnable,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($EspExtendedLogEnable -eq "yes") {
			$cmd = "logging/enableextesplog"
		}
		else {
			$cmd = "logging/disableextesplog"
		}
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Set-EspExtendedLogConfiguration

Function Get-LmSyslogFile
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$cmd = "logging/listsyslogfiles"
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmLogFilesList" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-LmSyslogFile

Function Reset-LmSyslogFile
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$FileToReset,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	try {
		$cmd = "logging/clearlogs"
		if (-not ([String]::IsNullOrEmpty($FileToReset))) {
			$params.Remove("FileToReset")
			$params.Add("fsel", $FileToReset)
		}
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmLogResetFilesList" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Reset-LmSyslogFile

Function Export-LmSyslogFile
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$FileToExport,

		[string]$Path,

		[string]$OutputFileName,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\"
	}

	if (-not ($OutputFileName)) {
		$OutputFileName = "LM-SyslogFile_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).tar.gz"
	}

	if ($OutputFileName.Contains(".tar.gz") -eq $false) {
			$OutputFileName = $OutputFileName + ".tar.gz"
	}

	$Path = validatePath $Path $OutputFileName

	try {
		$cmd = "logging/savelogs"
		if (-not ([String]::IsNullOrEmpty($FileToExport))) {
			$params.Remove("FileToExport")
			$params.Add("fsel", $FileToExport)
		}
		if (-not ([String]::IsNullOrEmpty($Path))) {
			$params.Remove("Path")
		}
		if (-not ([String]::IsNullOrEmpty($OutputFileName))) {
			$params.Remove("OutputFileName")
		}
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Export-LmSyslogFile

Function Get-LmExtendedLogFile
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$cmd = "logging/listextlogfiles"
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmExtendedLogFilesList" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-LmExtendedLogFile

Function Reset-LmExtendedLogFile
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$FileToReset,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	try {
		$cmd = "logging/clearextlogs"
		if (-not ([String]::IsNullOrEmpty($FileToReset))) {
			$params.Remove("FileToReset")
			$params.Add("fsel", $FileToReset)
		}
		$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmExtendedLogResetFilesList" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Reset-LmExtendedLogFile

Function Export-LmExtendedLogFile
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$FileToExport,

		[string]$Path,

		[string]$OutputFileName,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\"
	}

	if (-not ($OutputFileName)) {
		$OutputFileName = "LM-EspLogFile_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).tar.gz"
	}

	if ($OutputFileName.Contains(".tar.gz") -eq $false) {
			$OutputFileName = $OutputFileName + ".tar.gz"
	}

	$Path = validatePath $Path $OutputFileName

	try {
		$cmd = "logging/saveextlogs"
		if (-not ([String]::IsNullOrEmpty($FileToExport))) {
			$params.Remove("FileToExport")
			$params.Add("fsel", $FileToExport)
		}
		if (-not ([String]::IsNullOrEmpty($Path))) {
			$params.Remove("Path")
		}
		if (-not ([String]::IsNullOrEmpty($OutputFileName))) {
			$params.Remove("OutputFileName")
		}
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Export-LmExtendedLogFile

Function Export-LmWafTempRemoteLog
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Path,

		[string]$OutputFileName,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\"
	}

	if (-not ($OutputFileName)) {
		$OutputFileName = "LM-WafTempRemoteFile_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).tar.gz"
	}

	if ($OutputFileName.Contains(".tar.gz") -eq $false) {
			$OutputFileName = $OutputFileName + ".tar.gz"
	}

	$Path = validatePath $Path $OutputFileName

	try {
		$cmd = "logging/savemlogcdata"
		if (-not ([String]::IsNullOrEmpty($FileToExport))) {
			$params.Remove("FileToExport")
		}
		if (-not ([String]::IsNullOrEmpty($Path))) {
			$params.Remove("Path")
		}
		if (-not ([String]::IsNullOrEmpty($OutputFileName))) {
			$params.Remove("OutputFileName")
		}
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Export-LmWafTempRemoteLog

Function Reset-LmWafTempRemoteLog
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	try {
		$cmd = "logging/clearmlogcdata"
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Reset-LmWafTempRemoteLog

Function Get-LmApiList
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	try {
		$cmd = "listapi"
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmApiList" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-LmApiList

# ==================================================
# endregion LOGGING
# ==================================================


# ==================================================
# region SSO
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-SSODomain
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Domain,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "showdomain" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetSSODomain" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-SSODomain

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-SSODomain
{
	[CmdletBinding()]
	Param(
		[Parameter(ParameterSetName="Single",ValueFromPipelineByPropertyName=$true)]
		[Alias("Name")]
		[string]$Domain,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,

		[ValidateNotNullOrEmpty()]
		[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[ValidateNotNullOrEmpty()]
		[String]$SubjectCN = $script:SubjectCN
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "adddomain" -ParameterValuePair @{domain = $Domain} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response

		if ($lma.ReturnCode -eq 200) {
			$lma.Response = "Command successfully executed (Domain `"$Domain`" created)"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-SSODomain

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-SSODomain
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[Alias("Name")]
		[string]$Domain,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (($Force) -or ($PsCmdlet.ShouldProcess($Domain, "Remove SSO Domain"))) {

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		try {
			$response = SendCmdToLm -Command "deldomain" -ParameterValuePair @{domain = $Domain} -ConnParams $ConnParams
			$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response

			if ($lma.ReturnCode -eq 200) {
				$lma.Response = "Command successfully executed (Domain `"$Domain`" deleted)"
			}
			$lma
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}

	}
}
Export-ModuleMember -function Remove-SSODomain

# Internal use only
Function CheckSetSSODomainLoginFmtParam($logon_fmt, $iparams)
{
	# RESTful API mapping
	if ($logon_fmt -eq "Notspecified") {
		$iparams.Remove("logon_fmt")
		$iparams.Add("logon_fmt", "Not specified")
	}

	if ($logon_fmt -eq "Usernameonly") {
		$iparams.Remove("logon_fmt")
		$iparams.Add("logon_fmt", "Username only")
	}

	if ($logon_fmt2 -eq "Notspecified") {
		$iparams.Remove("logon_fmt2")
		$iparams.Add("logon_fmt2", "Not specified")
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-SSODomain
{
	[CmdletBinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("Name")]
		[string]$Domain,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Unencrypted", "StartTLS", "LDAPS")]
		[string]$TLS,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[String[]]$Server,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[String[]]$Server2,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("LDAP-Unencrypted", "LDAP-StartTLS", "LDAP-LDAPS",
		             "RADIUS", "RADIUS and LDAP-Unencrypted", "RADIUS and LDAP-StartTLS", "RADIUS and LDAP-LDAPS",
		             "RSA-SECURID", "RSA-SECURID and LDAP-Unencrypted", "RSA-SECURID and LDAP-StartTLS", "RSA-SECURID and LDAP-LDAPS",
		             "Certificates", "KCD", "SAML", "OIDC-OAUTH")]
		[string]$auth_type,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(0, 999)]
		[int]$max_failed_auths,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(60, 86400)]
		[int]$reset_fail_tout,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateRange(60, 86400)]
		[int]$unblock_tout,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Notspecified", "Not specified", "Principalname", "Username", "Usernameonly", "Username only")]
		[string]$logon_fmt,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("Notspecified", "Not specified", "Principalname", "Username")]
		[string]$logon_fmt2,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[string]$logon_domain,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("stt")][ValidateSet("idle time", "max duration")]
		[string]$sess_tout_type,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("stipub")][ValidateRange(60, 604800)]
		[int]$sess_tout_idle_pub,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("stdpub")][ValidateRange(60, 604800)]
		[int]$sess_tout_duration_pub,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("stipriv")][ValidateRange(60, 604800)]
		[int]$sess_tout_idle_priv,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("stdpriv")][ValidateRange(60, 604800)]
		[int]$sess_tout_duration_priv,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[string]$testuser,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[string]$testpass,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, 1)]
		[int]$ldapephc,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, 1)]
		[int]$radius_send_nas_id = 0,

		[ValidateNotNullOrEmpty()]
		[string]$radius_nas_id,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("Secret")]
		[string]$radius_shared_secret,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("KerberosDomain")]
		[string]$kerberos_domain,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("SKerberosKDC")]
		[string]$kerberos_kdc,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("KCDUsername")]
		[string]$kcd_username,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("KCDPassword")]
		[string]$kcd_password,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("ServerSide")]
		[string]$server_side,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[ValidateSet("UserPrincipalName", "Subject", "IssuerandSubject", "IssuerandSerialNumber")]
		[string]$cert_asi,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("CertCheckCn")]
		[string]$cert_check_cn,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("LogonTranscode")]
		[bool]$Logon_Transcode,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("LdapEndpoint")]
		[string]$ldap_endpoint,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("UserAccControl")]
		[int]$user_acc_control,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("OIDCAppID")]
		[string]$oidc_app_id,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("OIDCAuthEpURL")]
		[string]$oidc_auth_ep_url,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("OIDCLogoffURL")]
		[string]$oidc_logoff_url,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("OIDCTokenEpURL")]
		[string]$oidc_token_ep_url,

		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[Alias("OIDCSecret")]
		[string]$oidc_secret,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	CheckSetSSODomainLoginFmtParam $logon_fmt $psboundparameters

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($cert_asi) {
		$params.Remove("cert_asi")
		$params.Add("cert_asi", $WuiCertMapHT[$cert_asi]) 
	}
	try {
		$response = SendCmdToLm -Command "moddomain" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetSSODomain" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SSODomain

Function Get-SSODomainLockedUser
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Alias("Name")]
		[string]$Domain,

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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = ConvertBoundParameters -hashtable $psboundparameters

		try {
			$response = SendCmdToLm -Command "showdomainlockedusers" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GetSSODomainLockedUser" -LMResponse $response -AdditionalData "showdomainlockedusers"
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
		return
	}
}
Export-ModuleMember -function Get-SSODomainLockedUser

Function Set-SSODomainUnlockUser
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[Alias("Name")]
		[string]$Domain,

		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[string]$Users,

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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = ConvertBoundParameters -hashtable $psboundparameters

		try {
			$response = SendCmdToLm -Command "unlockdomainusers" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "SetSSODomainLockedUser" -LMResponse $response -AdditionalData "unlockdomainusers"
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
		return
	}
}
Export-ModuleMember -function Set-SSODomainUnlockUser

Function Install-SSORSAConfigurationFile
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = @{}

	try {
		$response = SendCmdToLm -Command "setrsaconfig" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Authentication Manager Config successfully loaded."
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Install-SSORSAConfigurationFile, UploadRSAConfigurationFile

Function Install-SSORSANodeSecretAndPassword
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = @{}
	$params.Add("rsanspwd",[System.Web.HttpUtility]::UrlEncode($Password))

	try {
		$response = SendCmdToLm -Command "setrsanodesecret" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Node Secret successfully loaded."
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Install-SSORSANodeSecretAndPassword, UploadRSANodeSecretAndPassword

Function Get-SSODomainSession
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Alias("Name")]
		[string]$Domain,

		[Parameter(Mandatory=$false)]
		[string]$User,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{}
	$params.Add("domain", $Domain)

	if (-not ([String]::IsNullOrEmpty($User))) {
		$params.Add("user", $User)
		$ssodcmd = "ssodomain/search"
	}
	else {
		$ssodcmd = "ssodomain/queryall"
	}

	try {
		$response = SendCmdToLm -Command $ssodcmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetSSODomainSession" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-SSODomainSession

Function Stop-SSODomainSession
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Domain,

		[Parameter(Mandatory=$false)]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{}
	$params.Add("domain", $Domain)

	if (-not ([String]::IsNullOrEmpty($Key))) {
		$params.Add("key", $Key)
		$ssodcmd = "ssodomain/killsession"
	}
	else {
		$ssodcmd = "ssodomain/killallsessions"
	}

	try {
		$response = SendCmdToLm -Command $ssodcmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Stop-SSODomainSession

Function Clear-SSOCache
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "logging/ssoflush" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Clear-SSOCache, FlushSsoCache

Function Get-SSODomainQuerySession
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Alias("Name")]
		[string]$Domain,

		[int]$startsession = -1,

		[int]$stopsession = -1,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{}
	$params.Add("domain", $Domain)

	if ($startsession -gt 0) {
		$params.Add("startsession", $startsession)
	}

	if ($stopsession -gt 0) {
		$params.Add("stopsession", $stopsession)
	}

	try {
		$response = SendCmdToLm -Command "ssodomain/querysessions" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetSSODomainQuerySession" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-SSODomainQuerySession

# ==================================================
# endregion SSO
# ==================================================


# ==================================================
# region NETWORKING
# ==================================================

# Internal use only
Function validateIp($ip)
{
	$retValue = $false

	if ($ip) {
		try {
			$check = [ipaddress]::Parse($ip)
			if ($check) {
				$retValue = $true
			}
		}
		catch {
			$errMsg = $_.Exception.Message
			Write-Verbose "ERROR: $errMsg"
		}
	}

	return $retValue
}

Function Get-LmNetworkInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = @{}

	try {
		$response = SendCmdToLm -Command "listifconfig" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmNetworkInterface" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmNetworkInterface, ListIfconfig

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-NetworkConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$networkParameters = @("snat", "allowupload", "conntimeout", "keepalive",
	                       "multigw", "nonlocalrs", "onlydefaultroutes", "resetclose",
	                       "subnetorigin", "subnetoriginating", "tcptimestamp",
	                       "routefilter", "dhkeysize", "http_proxy")

	GetLmParameterSet $networkParameters "NetworkConfiguration" $params
}
Export-ModuleMember -function Get-NetworkConfiguration, Get-NetworkOptions

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-NetworkConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding
	$params2Get = @()

	foreach($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")
		Start-Sleep -m 200
	}
	GetLmParameterSet $params2Get "Parameters" $params
}
Export-ModuleMember -function Set-NetworkConfiguration, Set-NetworkOptions

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-NetworkDNSConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$lma = GetLmParameter "Hamode" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	$hamode = $lma.Data.Hamode
	if ($hamode -eq 0) {
		$dnsParameters = @("Hostname", "NamServer", "SearchList")
	}
	else {
		$dnsParameters = @("Hostname", "HA1Hostname", "HA2Hostname", "NamServer", "SearchList")
	}

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	GetLmParameterSet $dnsParameters "NetworkDNSConfiguration" $params
}
Export-ModuleMember -function Get-NetworkDNSConfiguration, Get-DNSConfiguration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-NetworkDNSConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding
	$params2Get = @()

	foreach($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")
		Start-Sleep -m 200
	}
	GetLmParameterSet $params2Get "Parameters" $params
}
Export-ModuleMember -function Set-NetworkDNSConfiguration, Set-DNSConfiguration

Function Update-NetworkDNSCache
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "resolvenow" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Update-NetworkDNSCache, Update-LmDNSCache

# Internal use only
Function checkGetSnmpParam($type, $key, $param)
{
	if ($type -eq "SnmpV3") {
		if (($key -eq "no") -and
		    ($param -eq "SNMPv3user" -or $param -eq "SNMPv3userpasswd" -or $param -eq "snmpAuthProt" -or $param -eq "snmpPrivProt")) {
			return $false
		}
		else {
			return $true
		}
	}

	if ($type -eq "HaTrap") {
		if (($key -eq 0) -and ($param -eq "SNMPHaTrap")) {
			return $false
		}
		else {
			return $true
		}
	}

	if ($type -eq "SnmpTrap") {
		if (($key -eq "no") -and ($param -eq "SNMPv1Sink" -or $param -eq "SNMPv2Sink")) {
			return $false
		}
		else {
			return $true
		}
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-NetworkSNMPConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$lma = GetLmParameter "snmpenable" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	$snmpenable = $lma.Data.snmpenable
	if ($snmpenable -eq "no") {
		return $lma
	}

	$lma = GetLmParameter "SNMPv3enable" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	$snmpv3enable = $lma.Data.SNMPv3enable

	$lma = GetLmParameter "hamode" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	$hamode = $lma.Data.hamode

	$lma = GetLmParameter "SNMPTrapEnable" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	$snmptrapenable = $lma.Data.SNMPTrapEnable

	$snmpParams = @("SNMPEnable", "SNMPv3enable", "SNMPv3user", "SNMPv3userpasswd", "snmpAuthProt", "snmpPrivProt",
	                "SNMPClient", "SNMPCommunity", "SNMPContact", "SNMPLocation",
	                "SNMPTrapEnable", "SNMPHaTrap", "SNMPv1Sink", "SNMPv2Sink")

	$snmpConf = [ordered]@{}
	$snmpConf.PSTypeName = "SNMPConfiguration"
	foreach ($param in $snmpParams) {

		if ($param -eq "SNMPEnable") {
			$snmpConf.add($param, $snmpenable)
			continue
		}

		if ($param -eq "SNMPv3enable") {
			$snmpConf.add($param, $snmpv3enable)
			continue
		}

		if ($param -eq "SNMPTrapEnable") {
			$snmpConf.add($param, $snmptrapenable)
			continue
		}

		if ((checkGetSnmpParam "SnmpV3" $snmpv3enable $param) -eq $false) {
			continue
		}

		if ((checkGetSnmpParam "HaTrap" $hamode $param) -eq $false) {
			continue
		}

		if ((checkGetSnmpParam "SnmpTrap" $snmptrapenable $param) -eq $false) {
			continue
		}

		$lma = GetLmParameter "$param" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$snmpConf.add($param, $lma.Data.$param)

		Start-Sleep -m 150
	}
	$data = New-Object -TypeName PSObject -Property $snmpConf
	setKempAPIReturnObject 200 "Command successfully executed" $data
}
Export-ModuleMember -function Get-NetworkSNMPConfiguration, Get-SNMPOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-NetworkSNMPConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	foreach ($param in $params.Keys)
	{
		$lma = SetLmParameter $param $params[$param] $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		Start-Sleep -m 200
	}

	$ConnParams2 = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	Get-NetworkSNMPConfiguration @ConnParams2
}
Export-ModuleMember -function Set-NetworkSNMPConfiguration, Set-SNMPOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-NetworkInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		if ($InterfaceID -ne -1) {
			$param = [ordered]@{}
			$param.Add("iface", $InterfaceID)
			$response = SendCmdToLm -Command "showiface" -ParameterValuePair $param -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GetNetworkInterface" -LMResponse $response $InterfaceID
		}
		else {
			$response = SendCmdToLm -Command "showiface"  -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GetNetworkInterface" -LMResponse $response $InterfaceID
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-NetworkInterface, Get-Interface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-NetworkInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params.Remove("iface")
	foreach($param in $params.Keys) {

		$networkParams = @{iface=$InterfaceID}
		$networkParams.Add($param, $params[$param])

		$response = SetNetworkInterfaceParam "modiface" $networkParams $ConnParams
		if ($response.ReturnCode -ne 200) {
			Write-Verbose "error occurred: $($response.ReturnCode), $($response.Response)"
			return $response
		}
	}

	# The machine can have now a new address
	# we need to check the connection first
	Write-Verbose "Checking LM connection . . ."
	$LoadBalancer = CheckLmConnection $LoadBalancer $IPAddress $LBPort
	Write-Verbose "Successfully connect to the LM"

	# Get Interface details
	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}
	$intfDetails
}
Export-ModuleMember -function Set-NetworkInterface, Set-Interface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-NetworkInterfaceAdditionalAddress
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$cidr = $intfDetails.Data.Interface.IPAddress.Split("/")[1]
	if ($Address.IndexOf('/') -eq -1) {
		$Address += "/$cidr"
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$response = SetNetworkInterfaceParam "addadditional" @{iface=$InterfaceID; addr=$Address} $ConnParams
	if ($response.ReturnCode -ne 200) {
		return $response
	}

	GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function New-NetworkInterfaceAdditionalAddress, Add-InterfaceAddress

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-NetworkInterfaceAdditionalAddress
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	if (($Force) -or ($PsCmdlet.ShouldProcess($InterfaceID, "Remove Interface Address"))) {

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$response = SetNetworkInterfaceParam "deladditional" @{iface=$InterfaceID; addr=$Address} $ConnParams
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		# Get Interface details
		GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	}
}
Export-ModuleMember -function Remove-NetworkInterfaceAdditionalAddress, Remove-InterfaceAddress

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-NetworkRoute		# TODO to change name to Get-NetworkAdditionalRoute ?????
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "showroute" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetNetworkRoute" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-NetworkRoute, Get-Route

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-NetworkRoute
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	throwIfEmpty $Destination
	throwIfEmpty $CIDR
	throwIfEmpty $Gateway

	$DestIP = "$Destination/$CIDR"

	try {
		$response = SendCmdToLm -Command "addroute" -ParameterValuePair @{dest=$DestIP; gateway=$Gateway} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
	$ConnParams2 = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	Get-NetworkRoute @ConnParams2
}
Export-ModuleMember -function New-NetworkRoute, New-Route

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-NetworkRoute		# TODO to change name to Remove-NetworkAdditionalRoute ?????
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "delroute" -ParameterValuePair @{dest=$Destination} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
	$ConnParams2 = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	Get-NetworkRoute @ConnParams2
}
Export-ModuleMember -function Remove-NetworkRoute, Remove-Route

Function Test-NetworkRoute
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ( ([String]::IsNullOrEmpty($Address)) ) {
		Throw "ERROR: The address parameter is mandatory"
	}
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "logging/traceroute" -ParameterValuePair @{addr=$Address} -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "TestNetworkRoute" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Test-NetworkRoute

# Internal usage only
Function reconnectToLm($LoadBalancer, $LBPort, $cycles, $sleepTime)
{
	$check = $true
	$counter = $cycles

	while ($check) {
		if (-not (Test-LmServerConnection -ComputerName $LoadBalancer -Port $LBPort)) {
			Start-Sleep -s $sleepTime
			$counter -= 1
			if ($counter -eq 0) {
				return $false
			}
		}
		else {
			return $true
		}
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Register-NetworkBondedInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$check = $true
	try {
		$response = SendCmdToLm -Command "createbond" -ParameterValuePair @{iface=$InterfaceID} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$check = reconnectToLm $LoadBalancer $LBPort 12 10
	}
	catch {
		$errMsg = $_.Exception.Message
		if ($errMsg.Contains("Unable to connect to the remote server")) {
			$check = reconnectToLm $LoadBalancer $LBPort 12 10
		}
		else {
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
	}
	if ($check -eq $true) {
		GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	}
	else {
		setKempAPIReturnObject 400 "Unable to connect to the LM" $null
	}
}
Export-ModuleMember -function Register-NetworkBondedInterface, Register-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Unregister-NetworkBondedInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$check = $true
	try {
		$response = SendCmdToLm -Command "unbond" -ParameterValuePair @{iface=$InterfaceID} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$check = reconnectToLm $LoadBalancer $LBPort 12 10
	}
	catch {
		$errMsg = $_.Exception.Message
		if ($errMsg.Contains("Unable to connect to the remote server")) {
			$check = reconnectToLm $LoadBalancer $LBPort 12 10
		}
		else {
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
	}
	if ($check -eq $true) {
		GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	}
	else {
		setKempAPIReturnObject 400 "Unable to connect to the LM" $null
	}
}
Export-ModuleMember -function Unregister-NetworkBondedInterface, Unregister-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-NetworkBondedInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "addbond" -ParameterValuePair @{iface=$InterfaceID; bond=$BondID} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
	GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function New-NetworkBondedInterface, Add-BondedInterface

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-NetworkBondedInterface
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "delbond" -ParameterValuePair @{iface=$InterfaceID; bond=$BondID} -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
	GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function Remove-NetworkBondedInterface, Remove-BondedInterface

# Internal use only
Function AddNetworkVlanVxLan($cmd2exec, $intfType, $cmdClass, $lanParams, $getParams, $ConnParams)
{
	try {
		$response = SendCmdToLm -Command $cmd2exec -ParameterValuePair $lanParams -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass $cmdClass -LMResponse $response -AdditionalData $lanParams.iface
		if ($lma.ReturnCode -eq 200) {
			$intfId = $lma.Data.$intfType
			$getParams.Add("InterfaceID", $intfId)
			Get-NetworkInterface @getParams
		}
		else {
			return $lma
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}

# Internal use only
Function RemoveNetworkVLanVxLan($cmd2exec, $InterfaceId, $ConnParams)
{
	try {
		$response = SendCmdToLm -Command $cmd2exec -ParameterValuePair @{iface=$InterfaceID} -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-NetworkVLAN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		$intfDetails
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$getParams = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$lanParams = [ordered]@{iface = $InterfaceID; vlanid = $VLanId;}

	AddNetworkVlanVxLan "addvlan" "VLanInterfaceId" "AddNetworkVLAN" $lanParams $getParams $ConnParams
}
Export-ModuleMember -function New-NetworkVLAN, Add-VLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-NetworkVLAN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		$intfDetails
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	RemoveNetworkVLanVxLan "delvlan" $InterfaceID $ConnParams
}
Export-ModuleMember -function Remove-NetworkVLAN, Remove-VLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-NetworkVxLAN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ((($Addr -As [IPAddress]) -As [Bool])) {

		$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($intfDetails.ReturnCode -ne 200) {
			return $intfDetails
		}

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$getParams = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$sep = "."
		$parts = [System.StringSplitOptions]::RemoveEmptyEntries
		$AddrParts = $Addr.Split($sep, 4, $parts)
		[int]$parti = [convert]::ToInt32($AddrParts[0], 10)

		$lanParams = [ordered]@{iface = $InterfaceID; vni = $VNI;}
		if ($parti -gt 223 -and $parti -lt 240) {
			$lanParams.Add("group", $Addr)
		}
		else {
			$lanParams.Add("remote", $Addr)
		}

		AddNetworkVlanVxLan "addvxlan" "VxLanInterfaceId" "AddNetworkVxLAN" $lanParams $getParams $ConnParams
	}
	else {
		$errMsg = "No valid group or remote IP address given"
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function New-NetworkVxLAN, Add-VxLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-NetworkVxLAN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intfDetails = GetLmNetworkInterface $InterfaceID $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($intfDetails.ReturnCode -ne 200) {
		return $intfDetails
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	RemoveNetworkVLanVxLan "delvxlan" $InterfaceID $ConnParams
}
Export-ModuleMember -function Remove-NetworkVxLAN, Remove-VxLan

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-HostsEntry
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "gethosts" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetHosts" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Get-HostsEntry

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-HostsEntry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$HostIP,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$HostFQDN,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "addhostsentry" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function New-HostsEntry

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-HostsEntry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$HostIP,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "delhostsentry" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}
Export-ModuleMember -function Remove-HostsEntry

# ==================================================
# endregion NETWORKING
# ==================================================


# ==================================================
# region ADC
# ==================================================

# Internal use only
Function SetAdcVirtualserviceCheckUserParam($params, $CheckUse1_1)
{
	if ($CheckUse1_1 -ne -1) {
		$params.Remove("CheckUse1_1")

		if ($CheckUse1_1 -eq 1) {
			$params.Add("CheckUse1.1", 1)
		}
		else {
			$params.Add("CheckUse1.1", 0)
		}
	}
}

# Internal use only
Function checkAdcVSInputParams($VirtualService, $VSPort, $VSProtocol, $VSIndex, $case)
{
	if ($VSIndex -ge 0) {
		if ($VirtualService) {
			Throw "The VSIndex and VirtualService parameters are mutually exclusive."
		}
		if ($VSPort) {
			Throw "The VSIndex and Port parameters are mutually exclusive."
		}
		if ($VSProtocol) {
			Throw "The VSIndex and Protocol parameters are mutually exclusive."
		}
		$cmdCase = "Index"
	}
	elseif ($VirtualService) {
		if (!$VSPort -or !$VSProtocol) {
			Throw "The VirtualService, Port and Protocol parameters are mandatory."
		}
		$cmdCase = "IPAddress"
	}
	else {
		if ($case -eq 0) {
			if ($VSPort -or $VSProtocol) {
				Throw "The VirtualService, Port and Protocol parameters must be used together."
			}
		}
		else {
			Throw "Either the VirtualService or VSIndex parameter is required."
		}
	}
	$cmdCase
}

# Internal use only
Function GeAdcVirtualService($VirtualService, $Port, $Protocol, $VSIndex, $LoadBalancer, $LBPort, $Credential, $SubjectCN, $CertSL)
{
	if ($VirtualService -and $Port -and $Protocol) {
		$params = @{VirtualService=$VirtualService; VSPort=$Port; VSProtocol=$Protocol}
	}
	elseif ($VSIndex) {
		$params = @{VSIndex=$VSIndex}
	}
	else {
		$params = @{}
	}

	$params.Add("LoadBalancer", $LoadBalancer)
	if ($LBPort) {
		$params.Add("LBPort", $LBPort)
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$params.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertSL))) {
			$params.Add("CertificateStoreLocation", $CertSL)
		}
	}
	else {
		$params.Add("Credential", $Credential)
	}
	Get-AdcVirtualService @params
}

# Internal use only
Function checkAdcRSInputParams($RealServer, $RealServerPort, $RSIndex, $nocheck)
{
	if ($RSIndex -ge 0) {
		if ($RealServer) {
			Throw "The RSIndex and RealServer parameters are mutually exclusive."
		}
		if ($RealServerPort) {
			Throw "The RSIndex and RealServerPort parameters are mutually exclusive."
		}
		$cmdCase = "Index"
	}
	elseif ($RealServer) {
		if (!$RealServerPort) {
			Throw "The RealServer and RealServerPort parameters must be used together."
		}
		$cmdCase = "IPAddress"
	}
	else {
		if ($nocheck -eq 1) {
			$cmdCase = "All"
		}
		else {
			Throw "Either the RealServer or RSIndex parameter is required."
		}
	}
	$cmdCase
}

# Internal use only
Function GetAdcRealServerStat($RealServer, $LoadBalancer, $LBPort, $Credential, $SubjectCN, $CertSL)
{
	$params = @{LoadBalancer=$LoadBalancer}

	if ($LBPort) {
		$params.Add("LBPort", $LBPort)
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$params.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertSL))) {
			$params.Add("CertificateStoreLocation", $CertSL)
		}
	}
	else {
		$params.Add("Credential", $Credential)
	}
	$tmpObject = Get-LogStatistics @params -RealServer

	if ($tmpObject.ReturnCode -eq 200 ) {
		if (([String]::IsNullOrEmpty($RealServer))) {
			$rs = [ordered]@{}
			$rs.PSTypeName = "RealServer"
			$rs.Add("RealServer", $tmpObject.Data.Rs)
			$rsObject = New-Object -TypeName PSObject -Property $rs
			setKempAPIReturnObject 200 "Command successfully executed." $rsObject
		}
		else {
			$rsA = @()
			foreach($server in $tmpObject.Data.Rs) {
				if ($server.Addr -eq $RealServer) {
					$rsA += $server
				}
			}
			if ($rsA.Length -gt 0) {
				$rs = [ordered]@{}
				$rs.PSTypeName = "RealServer"
				$rs.Add("Realserver", $rsA)

				$rsObject = New-Object -TypeName PSObject -Property $rs
				setKempAPIReturnObject 200 "Command successfully executed." $rsObject
			}
			else {
				setKempAPIReturnObject 400 "Rs `"$RealServer`" not found." $null
			}
		}
	}
	else {
		return $tmpObject
	}
}

# Internal use only
Function EnableDisableAdcRealServer($cmd2exec, $params, $ConnParams)
{
	try {
		$response = SendCmdToLm -Command "$cmd2exec" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}
}

#
# Internal use only
#
# NOTE: The function handles the cmd to set cache and compression
#       exceptions.
#
Function AddRemoveAdcHttpCacheCompressionException($Extension, $Cmd, $ConnParams)
{
	foreach ($ext in $Extension) {
		try {
			$response = SendCmdToLm -Command "$Cmd" -ParameterValuePair @{param=$ext} -ConnParams $ConnParams
			$adcServiceHealthConfiguration = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
			if ($adcServiceHealthConfiguration.ReturnCode -ne 200) {
				return $adcServiceHealthConfiguration
			}
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
	}
	setKempAPIReturnObject 200 "Command successfully executed." $null
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcVirtualService
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

		[string[]]$CertFile,

		[string[]]$IntermediateCerts,

		[bool]$UserPwdExpiryWarn,

		[ValidateRange(1, 30)]
		[Int16]$UserPwdExpiryWarnDays,

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

		[Int32]$ChkInterval,

		[Int32]$ChkTimeout,

		[Int32]$ChkRetryCount,

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

		[bool]$PassCipher,

		[bool]$PassSni,

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

		[ValidateSet("0", "1", "2", "4", "8", "16")]
		[string]$QoS,

		[int32]$CheckUseGet,

		[ValidateRange(0, 7)]
		[Int16]$Verify,

		[string]$ExtraHdrKey,

		[string]$ExtraHdrValue,

		[string]$AllowedHosts,

		[string]$AllowedDirectories,

		[string]$ExcludedDirectories,

		[string]$AllowedGroups,

		[string]$GroupSIDs,

		[string]$SteeringGroups,

		[bool]$IncludeNestedGroups,

		[bool]$MultiDomainPermittedGroups,

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

		[ValidateRange(0, 2)]
		[Int16]$SecurityHeaderOptions,

		[ValidateRange(0, 8)]
		[Int16]$InputAuthMode,

		[ValidateNotNullOrEmpty()]
		[string]$OutConf,

		[ValidateRange(0, 4)]
		[Int16]$OutputAuthMode,

		[ValidateRange(0, 1)]
		[Int16]$StartTLSMode,

		[string]$ExtraPorts,

		[string]$AltAddress,

		[bool]$MultiConnect,

		[string]$SingleSignOnDir,

		[string]$OCSPVerify,

		[Int32]$FollowVSID,

		[ValidateRange(0, 30)]
		[int]$TlsType = 0,

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

		[string]$MatchBodyPrecedence,

		[Int16]$MatchBodyPrecedencePos,

		[bool]$NeedHostName,

		[string]$CopyHdrFrom = "",

		[string]$CopyHdrTo = "",

		[string]$SingleSignOnMessage,

		[bool]$VerifyBearer,
 
		[string]$BearerCertificateName,

		[string]$BearerText,
		
		[int]$BandWidth,

		[bool]$RefreshPersist,

		[int]$ConnsPerSecLimit,

		[int]$RequestsPerSecLimit,

		[int]$MaxConnsLimit,

		[int]$InterceptMode,

		[string]$OWASPOpts,

		[int]$BlockingParanoia,

		[int]$ExecutingParanoia,

		[int]$AnomalyScoringThreshold,

		[int]$PCRELimit,

		[bool]$IPReputationBlocking,

		[string]$RuleSets,

		[string]$CustomRules,

		[string]$ExcludedWorkLoads,

		[string]$DisabledRules,

		[string]$BlockedCountries,

		[string]$AuditParts,

		[string]$PostOtherContentTypes,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -DontEncode @("BlockedCountries", "CustomRules", "DisabledRules", "PostOtherContentTypes" )

	SetAdcVirtualserviceCheckUserParam $params $CheckUse1_1

	try {
		$response = SendCmdToLm -Command "addvs" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewAdcVS" -LMResponse $response -AdditionalData $true
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcVirtualService, New-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcVirtualService
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 0

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($VirtualService -or $VSIndex -ge 0) {
			$CmdClass = "GetAdcVS_Single"
			$response = SendCmdToLm -Command "showvs" -ParameterValuePair $params -ConnParams $ConnParams
			$adata = $true
		}
		else {
			$CmdClass = "GetAdcVS_List"
			$response = SendCmdToLm -Command "listvs" -ParameterValuePair $params -ConnParams $ConnParams
			$adata = $false
		}
		HandleLmAnswer -Command2ExecClass $CmdClass -LMResponse $response -AdditionalData $adata
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcVirtualService, Get-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcVirtualService
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

		[string[]]$CertFile,

		[string[]]$IntermediateCerts,

		[bool]$UserPwdExpiryWarn,

		[ValidateRange(1, 30)]
		[Int16]$UserPwdExpiryWarnDays,

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

		[Int32]$ChkInterval,

		[Int32]$ChkTimeout,

		[Int32]$ChkRetryCount,

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

		[bool]$PassCipher,

		[bool]$PassSni,

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

		[ValidateSet("0", "1", "2", "4", "8", "16")]
		[string]$QoS,

		[int32]$CheckUseGet,

		[ValidateRange(0, 7)]
		[Int16]$Verify,

		[string]$ExtraHdrKey,

		[string]$ExtraHdrValue,

		[string]$AllowedHosts,

		[string]$AllowedDirectories,

		[string]$ExcludedDirectories,

		[string]$AllowedGroups,

		[string]$GroupSIDs,

		[string]$SteeringGroups,

		[bool]$IncludeNestedGroups,

		[bool]$MultiDomainPermittedGroups,

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

		[ValidateRange(0, 2)]
		[Int16]$SecurityHeaderOptions,

		[ValidateRange(0, 8)]
		[Int16]$InputAuthMode,

		[ValidateNotNullOrEmpty()]
		[string]$OutConf,

		[ValidateRange(0, 4)]
		[Int16]$OutputAuthMode,

		[ValidateRange(0, 1)]
		[Int16]$StartTLSMode,

		[string]$ExtraPorts,

		[string]$AltAddress,

		[bool]$MultiConnect,

		[string]$SingleSignOnDir,

		[string]$OCSPVerify,

		[Int32]$FollowVSID,

		[ValidateRange(0, 30)]
		[int]$TlsType = 0,

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

		[string]$MatchBodyPrecedence,

		[Int16]$MatchBodyPrecedencePos,

		[bool]$NeedHostName,

		[string]$CopyHdrFrom,

		[string]$CopyHdrTo,

		[string]$ServerFbaPath,

		[string]$ServerFbaPost,

		[string]$AddAuthHeader,

		[bool]$VerifyBearer,

		[string]$BearerCertificateName,

		[string]$BearerText,

		[string]$SingleSignOnMessage,

		[bool]$Intercept,

		[bool]$AllowHTTP2,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptOpts,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptRules,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptPostOtherContentTypes,

		[ValidateRange(0, 100000)]
		[int32]$AlertThreshold,

		[bool]$Captcha,

		[bool]$NonLocalSorryServer,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaPublicKey,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaPrivateKey,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaAccessUrl,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaVerifyUrl,

		[ValidateSet("yes", "no")]
		[String]$ServerFbaUsernameOnly,

		[string]$VSNewAddress,

		[int]$BandWidth,

		[bool]$RefreshPersist,

		[ValidateRange(3, 65530)]
		[Int32]$VSNewPort,

		[int]$ConnsPerSecLimit,

		[int]$RequestsPerSecLimit,

		[int]$MaxConnsLimit,

		[int]$InterceptMode,

		[string]$OWASPOpts,

		[int]$BlockingParanoia,

		[int]$ExecutingParanoia,

		[int]$AnomalyScoringThreshold,

		[int]$PCRELimit,

		[bool]$IPReputationBlocking,

		[string]$RuleSets,

		[string]$CustomRules,

		[string]$ExcludedWorkLoads,

		[string]$DisabledRules,

		[string]$BlockedCountries,

		[string]$AuditParts,

		[string]$PostOtherContentTypes,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	if ($ServerFbaPost -and -not ($ServerFbaPath) ) {
		setKempAPIReturnObject 400 "ERROR: ServerFbaPath must be set in order to use ServerFbaPost parameter" $null
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -DontEncode @("BlockedCountries", "CustomRules", "DisabledRules", "PostOtherContentTypes" )

	if ($VSNewAddress) {
		$params.Remove("VSNewAddress")
		$params.Add("vsaddress", $VSNewAddress)
	}

	if ($VSNewPort) {
		$params.Remove("VSNewPort")
		$params.Add("vsport", $VSNewPort)
	}

	SetAdcVirtualserviceCheckUserParam $params $CheckUse1_1

	if ($NonLocalSorryServer -eq $true) {
		$params.Remove("NonLocalSorryServer")
		$params.Add("non_local", 1)
	}
	else {
		$params.Remove("NonLocalSorryServer")
	}

	try {
		$response = SendCmdToLm -Command "modvs" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "SetAdcVS" -LMResponse $response -AdditionalData $true
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcVirtualService, Set-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcVirtualService
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

		$virtServ = GeAdcVirtualService $VirtualService $VSPort $VSProtocol $VSIndex $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($virtServ.ReturnCode -ne 200) {
			if ($virtServ.Response -and $virtServ.Response.Contains("Unknown VS")) {
				$virtServ.Response += ". Has it already been deleted?"
			}
			return $virtServ
		}

		switch ($cmdCase)
		{
			"IPAddress" {
				$params = @{vs=$VirtualService; port=$VSPort; prot=$VSProtocol}
			}

			"Index" {
				# NOTE: for SubVs we need to use the index only
				if ($virtServ.Data.VS.VSAddress) {
					$VirtualService = $virtServ.Data.VS.VSAddress
					$Port = $virtServ.Data.VS.VSPort
					$Protocol = $virtServ.Data.VS.Protocol
				
					$params = @{vs=$VirtualService; port=$Port; prot=$Protocol}
				}
				else {
					$params = @{vs=$VSIndex}
				}
			}

			default {
				Throw "Unknown error."
			}
		}

		if (($Force) -or ($PsCmdlet.ShouldProcess("$($VirtualService)/$($VSPort)/$($VSProtocol)", "Remove Virtual Service"))) {
			$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
			try {
				$response = SendCmdToLm -Command "delvs" -ParameterValuePair $params -ConnParams $ConnParams
				HandleLmAnswer -Command2ExecClass "RemoveAdcVS" -LMResponse $response
			}
			catch {
				$errMsg = $_.Exception.Message
				setKempAPIReturnObject 400 "$errMsg" $null
			}
		}
	}
}
Export-ModuleMember -function Remove-AdcVirtualService, Remove-VirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcSubVirtualService
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[ValidateRange(3, 65530)]
		[Int32]$VSPort,

		[ValidateNotNullOrEmpty()]
		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{}
	if ($cmdCase -eq "IPAddress") {
		$params.Add("vs", $VirtualService)
		$params.Add("port", $VSPort)
		$params.Add("prot", $VSProtocol)
	}
	else {
		$params.Add("vs", $VSIndex)
	}
	$params.Add("createsubvs", "")

	try {
		$response = SendCmdToLm -Command "modvs" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewAdcVS" -LMResponse $response -AdditionalData $true
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcSubVirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcSubVirtualService
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$SubVSIndex,

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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ([String]::IsNullOrEmpty($SubVSIndex) -or $SubVSIndex -le 0) {
			Throw "ERROR: VSIndex is a required parameter"
		}

		$params = [ordered]@{VSIndex=$SubVSIndex}
		$params.Add("Force", $Force)

		$params.Add("LoadBalancer", $LoadBalancer)
		if ($LBPort) {
			$params.Add("LBPort", $LBPort)
		}

		if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
			if (-not ([String]::IsNullOrEmpty($CertSL))) {
				$params.Add("SubjectCN", $SubjectCN)
				$params.Add("CertificateStoreLocation", $CertSL)
			}
			else {
				$params.Add("SubjectCN", $SubjectCN)
			}
		}
		else {
			$params.Add("Credential", $Credential)
		}
		Remove-AdcVirtualService @params
	}
}
Export-ModuleMember -function Remove-AdcSubVirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcSubVirtualService
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$SubVSIndex,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ([String]::IsNullOrEmpty($SubVSIndex) -or $SubVSIndex -le 0) {
		Throw "ERROR: VSIndex is a required parameter"
	}

	$params = [ordered]@{VSIndex=$SubVSIndex}

	$params.Add("LoadBalancer", $LoadBalancer)
	if ($LBPort) {
		$params.Add("LBPort", $LBPort)
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		if (-not ([String]::IsNullOrEmpty($CertSL))) {
			$params.Add("SubjectCN", $SubjectCN)
			$params.Add("CertificateStoreLocation", $CertSL)
		}
		else {
			$params.Add("SubjectCN", $SubjectCN)
		}
	}
	else {
		$params.Add("Credential", $Credential)
	}
	Get-AdcVirtualService @params
}
Export-ModuleMember -function Get-AdcSubVirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcSubVirtualService
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int32]$SubVSIndex,

		[Int16]$AddVia,

		[bool]$UserPwdExpiryWarn,

		[ValidateRange(1, 30)]
		[Int16]$UserPwdExpiryWarnDays,

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

		[Int32]$ChkInterval,

		[Int32]$ChkTimeout,

		[Int32]$ChkRetryCount,

		[Int32]$CheckPort,

		[bool]$EnhancedHealthChecks,

		[Int32]$RsMinimum,

		[string]$Cookie,

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

		[ValidateSet("rr", "wrr", "lc", "wlc", "fixed", "adaptive", "sh")]
		[string]$Schedule,

		[ValidateRange(0, 5)]
		[Int16]$ServerInit,

		[string]$StandByAddr,

		[string]$StandByPort,

		[Int32]$TransactionLimit,

		[bool]$Transparent,

		[bool]$SubnetOriginating,

		[ValidateSet("0", "1", "2", "4", "8", "16")]
		[string]$QoS,

		[int32]$CheckUseGet,

		[ValidateRange(0, 7)]
		[Int16]$Verify,

		[string]$ExtraHdrKey,

		[string]$ExtraHdrValue,

		[string]$AllowedHosts,

		[string]$AllowedDirectories,

		[string]$ExcludedDirectories,

		[string]$AllowedGroups,

		[string]$GroupSIDs,

		[string]$SteeringGroups,

		[bool]$IncludeNestedGroups,

		[bool]$MultiDomainPermittedGroups,

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

		[ValidateRange(0, 2)]
		[Int16]$SecurityHeaderOptions,

		[ValidateRange(0, 8)]
		[Int16]$InputAuthMode,

		[ValidateNotNullOrEmpty()]
		[string]$OutConf,

		[ValidateRange(0, 4)]
		[Int16]$OutputAuthMode,

		[ValidateRange(0, 1)]
		[Int16]$StartTLSMode,

		[bool]$MultiConnect,

		[string]$SingleSignOnDir,

		[string]$OCSPVerify,

		[Int32]$FollowVSID,

		[ValidateRange(0, 30)]
		[int]$TlsType = 0,

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

		[string]$MatchBodyPrecedence,

		[Int16]$MatchBodyPrecedencePos,

		[bool]$NeedHostName,

		[string]$CopyHdrFrom,

		[string]$CopyHdrTo,

		[string]$ServerFbaPath,

		[string]$ServerFbaPost,

		[string]$AddAuthHeader,

		[bool]$VerifyBearer,

		[string]$BearerCertificateName,

		[string]$BearerText,

		[string]$SingleSignOnMessage,

		[bool]$Intercept,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptOpts,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptRules,

		[ValidateNotNullOrEmpty()]
		[string]$InterceptPostOtherContentTypes,

		[ValidateRange(0, 100000)]
		[int32]$AlertThreshold,

		[bool]$Captcha,

		[bool]$NonLocalSorryServer,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaPublicKey,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaPrivateKey,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaAccessUrl,

		[ValidateNotNullOrEmpty()]
		[string]$CaptchaVerifyUrl,

		[ValidateRange(1, 65530)]
		[Int32]$Weight,

		[ValidateRange(0, 100000)]
		[Int64]$Limit = 0,

		[bool]$Critical,

		[int]$BandWidth,

		[bool]$RefreshPersist,

		[ValidateSet("yes", "no")]
		[String]$ServerFbaUsernameOnly,

		[int]$ConnsPerSecLimit,

		[int]$RequestsPerSecLimit,

		[int]$MaxConnsLimit,

		[int]$InterceptMode,

		[string]$OWASPOpts,

		[int]$BlockingParanoia,

		[int]$ExecutingParanoia,

		[int]$AnomalyScoringThreshold,

		[int]$PCRELimit,

		[bool]$IPReputationBlocking,

		[string]$RuleSets,

		[string]$CustomRules,

		[string]$ExcludedWorkLoads,

		[string]$DisabledRules,

		[string]$BlockedCountries,

		[string]$AuditParts,

		[string]$PostOtherContentTypes,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ([String]::IsNullOrEmpty($SubVSIndex) -or $SubVSIndex -le 0) {
		Throw "ERROR: VSIndex is a required parameter"
	}

	if ($ServerFbaPost -and -not ($ServerFbaPath) ) {
		setKempAPIReturnObject 400 "ERROR: ServerFbaPath must be set in order to use ServerFbaPost parameter" $null
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters -DontEncode @("BlockedCountries", "CustomRules", "DisabledRules", "PostOtherContentTypes" )
	$params.Remove("SubVSIndex")
	$params.Add("vs", $SubVSIndex)

	SetAdcVirtualserviceCheckUserParam $params $CheckUse1_1

	if ($NonLocalSorryServer -eq $true) {
		$params.Remove("NonLocalSorryServer")
		$params.Add("non_local", 1)
	}
	else {
		$params.Remove("NonLocalSorryServer")
	}

	try {
		$response = SendCmdToLm -Command "modvs" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "SetAdcVS" -LMResponse $response -AdditionalData $true
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcSubVirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcRealServer
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

		[ValidateRange(0, 100000)]
		[Int64]$RateLimit = 0,

		[bool]$Critical,

		[bool]$AddToAllSubvs,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addrs" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewAdcRS" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcRealServer, New-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcRealServer
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1
		checkAdcRSInputParams $RealServer $RealServerPort $RSIndex | Out-Null

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = ConvertBoundParameters -hashtable $psboundparameters

		if (($Force) -or ($PsCmdlet.ShouldProcess($RealServer, "Remove Real Server"))) {

			try {
				$response = SendCmdToLm -Command "delrs" -ParameterValuePair $params -ConnParams $ConnParams
				HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
			}
			catch {
				$errMsg = $_.Exception.Message
				setKempAPIReturnObject 400 "$errMsg" $null
			}
		}
	}
}
Export-ModuleMember -function Remove-AdcRealServer, Remove-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcRealServer
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

		[ValidateRange(0, 100000)]
		[Int64]$RateLimit = 0,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1
	checkAdcRSInputParams $RealServer $RealServerPort $RSIndex | Out-Null

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modrs" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcRealServer, Set-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcRealServer
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$vsParamsCheck = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1
	$rsParamsCheck = checkAdcRSInputParams $RealServer $RSPort $RSIndex 1

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{}

	# default values
	$cmd2exec = "showrs"
	$Command2ExecClass = "GetAdcRealServer"

	if ($vsParamsCheck -eq "IPAddress") {
		$params.Add("vs", $VirtualService)
		$params.Add("port", $VSPort)
		$params.Add("prot", $VSProtocol)
	}
	else {
		$params.Add("vs", $VSIndex)
	}

	if ($rsParamsCheck -eq "IPAddress") {
		$params.Add("rs", $RealServer)
		$params.Add("rsport", $RSPort)
	}
	elseif ($rsParamsCheck -eq "Index") {
		$params.Add("rs", "!$RSIndex")
	}
	else {
		# to get all the RS that belong to the specified VS
		$cmd2exec = "showvs"
		$Command2ExecClass = "GetAdcVS_Single"
	}

	try {
		$response = SendCmdToLm -Command $cmd2exec -ParameterValuePair $params -ConnParams $ConnParams

		$handleLmAnswerParams = [ordered]@{}
		$handleLmAnswerParams.Add("Command2ExecClass", $Command2ExecClass)
		$handleLmAnswerParams.Add("LMResponse", $response)

		if ($rsParamsCheck -eq "All") {
			$handleLmAnswerParams.Add("AdditionalData", $true)
		}

		$lma = HandleLmAnswer @handleLmAnswerParams

		if ($rsParamsCheck -ne "All") {
			return $lma
		}
		else {
			$rsData = $lma.Data.VS.Rs

			$rsConf = [ordered]@{}
			$rsConf.PSTypeName = "Rs"
			$rsConf.Add("Rs", $rsData) | Out-null
			$rsObj = New-Object -TypeName PSObject -Property $rsConf

			setKempAPIReturnObject 200 "Command successfully executed." $rsObj
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcRealServer, Get-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Enable-AdcRealServer
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ([String]::IsNullOrEmpty($RSIpaddress)) {
		Throw "ERROR: RSIpAddress is a mandatory parameter. Please check your input"
	}

	$params = @{rs=$RSIpaddress}

	if ($RSPort) {
		$params.Add("port", $RSPort) | Out-null
	}

	if ($RSFqdn) {
		$params.Add("dnsname", $RSFqdn) | Out-null
	}
	EnableDisableAdcRealServer "enablers" $params $ConnParams
}
Export-ModuleMember -function Enable-AdcRealServer, Enable-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Disable-AdcRealServer
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ([String]::IsNullOrEmpty($RSIpaddress)) {
		Throw "ERROR: RSIpAddress is a mandatory parameter. Please check your input"
	}

	$params = @{rs=$RSIpaddress}

	if ($RSPort) {
		$params.Add("port", $RSPort) | Out-null
	}

	if ($RSFqdn) {
		$params.Add("dnsname", $RSFqdn) | Out-null
	}
	EnableDisableAdcRealServer "disablers" $params $ConnParams
}
Export-ModuleMember -function Disable-AdcRealServer, Disable-RealServer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcVirtualServiceRule
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
			[String]$SubjectCN = $script:SubjectCN
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$Command = ""
	switch ($RuleType)
	{
		"pre" {$Command = "addprerule"}
		"response" {$Command = "addresponserule"}
		"request" {$Command = "addrequestrule"}
	}

	try {
		$response = SendCmdToLm -Command $Command -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcVirtualServiceRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcVirtualServiceRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$Command = ""
	switch ($RuleType)
	{
		"pre" {$Command = "delprerule"}
		"response" {$Command = "delresponserule"}
		"request" {$Command = "delrequestrule"}
	}

	if (($Force) -or ($PsCmdlet.ShouldProcess($RuleName, "Remove Virtual Server Rule"))) {
		try {
			$response = SendCmdToLm -Command $Command -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-AdcVirtualServiceRule, Remove-VirtualServerRule, Remove-AdcVirtualServerRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcVirtualServiceResponseBodyRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int32]$VSIndex,

		[Parameter(Mandatory=$true)]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ($VSIndex -le 0) {
		Throw "ERROR: VSIndex must be greater than 0."
		return
	}

	if ([String]::IsNullOrEmpty($RuleName)) {
		Throw "ERROR: Rule name is a mandatory parameter. Please check your input"
		return
	}

	try {
		$response = SendCmdToLm -Command "addresponsebodyrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcVirtualServiceResponseBodyRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcVirtualServiceResponseBodyRule
{
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[Int32]$VSIndex,

		[Parameter(Mandatory=$true)]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ($VSIndex -le 0) {
		Throw "ERROR: VSIndex must be greater than 0."
		return
	}

	if ([String]::IsNullOrEmpty($RuleName)) {
		Throw "ERROR: Rule name is a mandatory parameter. Please check your input"
		return
	}

	if (($Force) -or ($PsCmdlet.ShouldProcess($RuleName, "Remove Response Body Rule"))) {
		try {
			$response = SendCmdToLm -Command "delresponsebodyrule" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-AdcVirtualServiceResponseBodyRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcRealServerRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1
	checkAdcRSInputParams $RealServer $RSPort $RSIndex | Out-Null

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "addrsrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcRealServerRule, New-RealServerRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcRealServerRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1
	checkAdcRSInputParams $RealServer $RSPort $RSIndex | Out-Null

	$params = ConvertBoundParameters -hashtable $psboundparameters

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (($Force) -or ($PsCmdlet.ShouldProcess($RuleName, "Remove Real Server Rule"))) {
		try {
			$response = SendCmdToLm -Command "delrsrule" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-AdcRealServerRule, Remove-RealServerRule

Function New-AdcContentRule
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

		[ValidateRange(0, 1)]
		[int]$MustFail,

		[ValidateRange(0, 9)]
		[int]$OnlyOnFlag,

		[ValidateRange(0, 9)]
		[int]$OnlyOnNoFlag,

		[ValidateRange(0, 9)]
		[int]$SetFlagOnMatch,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($params.ContainsKey("rule")) {
		$params.Remove("rule")
		$params.Add("Name", $RuleName)
	}
	elseif ($params.ContainsKey("RuleName")) {
		$params.Remove("RuleName")
		$params.Add("Name", $RuleName)
	}
	else {
		Throw "[New-AdcContentRule] ERROR: The parameter RuleName is mandatory."
	}

	if ($params.ContainsKey("MustFail")) {
		$params.Remove("MustFail")
		$params.Add("mustfail", $MustFail)
	}
	if ($params.ContainsKey("OnlyOnFlag")) {
		$params.Remove("OnlyOnFlag")
		$params.Add("onlyonflag", $OnlyOnFlag)
	}
	if ($params.ContainsKey("SetFlagOnMatch")) {
		$params.Remove("SetFlagOnMatch")
		$params.Add("setonmatch", $SetFlagOnMatch)
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "addrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "AddAdcContentRule" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcContentRule, New-Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcContentRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove Content Rule"))) {
		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		try {
			$response = SendCmdToLm -Command "delrule" -ParameterValuePair @{name=$RuleName} -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-AdcContentRule, Remove-Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcContentRule
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

		[ValidateRange(0, 1)]
		[int]$MustFail,

		[ValidateRange(0, 9)]
		[int]$OnlyOnFlag,

		[ValidateRange(0, 9)]
		[int]$OnlyOnNoFlag,

		[ValidateRange(0, 9)]
		[int]$SetFlagOnMatch,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($params.ContainsKey("rule")) {
		$params.Remove("rule")
		$params.Add("Name", $RuleName)
	}
	elseif ($params.ContainsKey("RuleName")) {
		$params.Remove("RuleName")
		$params.Add("Name", $RuleName)
	}
	else {
		Throw "[Set-AdcContentRule] ERROR: The parameter RuleName is mandatory."
	}

	if ($params.ContainsKey("MustFail")) {
		$params.Remove("MustFail")
		$params.Add("mustfail", $MustFail)
	}
	if ($params.ContainsKey("OnlyOnFlag")) {
		$params.Remove("OnlyOnFlag")
		$params.Add("onlyonflag", $OnlyOnFlag)
	}
	if ($params.ContainsKey("SetFlagOnMatch")) {
		$params.Remove("SetFlagOnMatch")
		$params.Add("setonmatch", $SetFlagOnMatch)
	}

	#
	# TODO: Investigate if it should be better to retrieve the rule type
	#       to check the rule type against the pattern parameter.
	#       From the Official REST-apis documentation:
	#       Unless modifying/adding an AddHeaderRule, the pattern parameter must be supplied.
	#
	#       PRO
	#        1) checking if the rule exists before performing the set
	#        2) checking if the pattern parameter is required or not.
	#
	#       CON
	#        1) the command requires 2 REST api calls on success.
	#

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "modrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "SetAdcContentRule" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcContentRule, Set-Rule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcContentRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = @{}
	if ($All) {
		if (([String]::IsNullOrEmpty($RuleName)) -and ([String]::IsNullOrEmpty($RuleType))) {
			Write-Verbose "ALL case"
		}
		else {
			Throw "[Get-AdcContentRule] ERROR: only one option can be set."
		}
	}
	else {
		if (-not ([String]::IsNullOrEmpty($RuleName)) -and ([String]::IsNullOrEmpty($RuleType))) {
			Write-Verbose "Name case"
			$params.Add("name", $RuleName)
		}
		elseif (-not ([String]::IsNullOrEmpty($RuleType)) -and ([String]::IsNullOrEmpty($RuleName))) {
			Write-Verbose "Type case"
			$TypeNumber = $SystemRuleType[$RuleType]
			$params.Add("type", $TypeNumber)
		}
		else {
			Throw "[Get-AdcContentRule] ERROR: only one option can be set."
		}
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "showrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcContentRule" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcContentRule, Get-Rule

# Internal use only
Function mapInternalL7NamesToExt($L7ConfHt, $paramName, $paramValue)
{
	$alwaysCheckPersistHtValues = [ordered]@{"0" = "No"; "1" = "Yes"; "2" = "Yes - Accept Changes"}
	$additionalL7HeaderHtValues = [ordered]@{"0" = "X-ClientSide"; "1" = "X-Forwarded-For"; "2" = "None"}
	$100ContinueHandlingHtValues = [ordered]@{"0" = "RFC-2616 Compliant"; "1" = "Require 100-Continue"; "2" = "RFC-7231 Compliant"}

	switch ($paramName)
	{
		"localbind" { $L7ConfHt.Add("ScalingOver64KConnections", $paramValue); break }

		"alwayspersist" {
			$persistValue = $alwaysCheckPersistHtValues[$paramValue]
			$L7ConfHt.Add("AlwaysCheckPersist", $persistValue)
			break
		}

		"addcookieport" { $L7ConfHt.Add("AddPortToActiveCookie", $paramValue); break }

		"rfcconform" { $L7ConfHt.Add("RFCConform", $paramValue); break }

		"closeonerror" { $L7ConfHt.Add("CloseOnError", $paramValue); break }

		"addvia" { $L7ConfHt.Add("AddViaHeaderInCacheResponses", $paramValue); break }

		"rsarelocal" { $L7ConfHt.Add("RSAreLocal", $paramValue); break }

		"droponfail" { $L7ConfHt.Add("DropOnRSFail", $paramValue); break }

		"dropatdrainend" { $L7ConfHt.Add("DropAtDrainEnd", $paramValue); break }

		"transparent" { $L7ConfHt.Add("Transparent", $paramValue); break }

		"authtimeout" { $L7ConfHt.Add("L7AuthTimeoutSecs", $paramValue); break }

		"clienttokentimeout" { $L7ConfHt.Add("L7ClientTokenTimeoutSecs", $paramValue); break }

		"finalpersist" { $L7ConfHt.Add("L7ConnectionDrainTimeoutSecs", $paramValue); break }

		"addforwardheader" {
			$addForwardHeaderValue = $additionalL7HeaderHtValues[$paramValue]
			$L7ConfHt.Add("AdditionalL7Header", $addForwardHeaderValue);
			break
		}

		"expect100" {
			$Expect100Value = $100ContinueHandlingHtValues[$paramValue]
			$L7ConfHt.Add("OneHundredContinueHandling", $Expect100Value);
			break
		}

		"allowemptyposts" { $L7ConfHt.Add("AllowEmptyPosts", $paramValue); break }

		"AllowEmptyHttpHeaders" { $L7ConfHt.Add("AllowEmptyHttpHeaders", $paramValue); break }

		"ForceFullRSMatch" { $L7ConfHt.Add("ForceCompleteRSMatch", $paramValue); break }

		"slowstart" { $L7ConfHt.Add("SlowStart", $paramValue); break }

		"ShareSubVSPersist" { $L7ConfHt.Add("ShareSubVSPersistance", $paramValue); break }

		"CEFmsgFormat" { $L7ConfHt.Add("CEFmsgFormat", $paramValue); break }
	}
}

# Internal use only
Function mapL7ConfigName($paramsHT, $psName, $psValue)
{
	$alwaysCheckPersistHtValues = [ordered]@{"No" = 0; "Yes" = 1; "Yes - Accept Changes" = 2}
	$additionalL7HeaderHtValues = [ordered]@{"X-ClientSide" = 0; "X-Forwarded-For" = 1; "None" = 2}
	$100ContinueHandlingHtValues = [ordered]@{"RFC-2616 Compliant" = 0; "Require 100-Continue" = 1; "RFC-7231 Compliant" = 2}

	switch ($psName)
	{
		"AlwaysCheckPersist" {
			$persistValue = $alwaysCheckPersistHtValues[$psValue]
			$paramsHT.Remove("AlwaysCheckPersist")
			$paramsHT.Add("alwayspersist", $persistValue)
			break
		}

		"AdditionalL7Header" {
			$addForwardHeaderValue = $additionalL7HeaderHtValues[$psValue]
			$paramsHT.Remove("AdditionalL7Header")
			$paramsHT.Add("addforwardheader", $addForwardHeaderValue)
			break
		}

		"OneHundredContinueHandling" {
			$Expect100Value = $100ContinueHandlingHtValues[$psValue]
			$paramsHT.Remove("OneHundredContinueHandling")
			$paramsHT.Add("expect100", $Expect100Value)
			break
		}
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcL7Configuration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	# NOTE: add new parameters in the WUI same order
	$l7ConfParameters = @("localbind", "alwayspersist", "addcookieport", "rfcconform",
	                      "closeonerror", "addvia", "rsarelocal", "droponfail",
	                      "dropatdrainend", "transparent", "authtimeout", "clienttokentimeout", "finalpersist",
	                      "addforwardheader", "expect100", "allowemptyposts", "AllowEmptyHttpHeaders",
	                      "ForceFullRSMatch", "slowstart", "ShareSubVSPersist", "CEFmsgFormat")

	$l7ConfSettings = [ordered]@{}
	$l7ConfSettings.PSTypeName = "AdcL7Settings"
	foreach ($param in $l7ConfParameters) {
		$lma = GetLmParameter "$param" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$paramValue = $lma.Data.$param
		mapInternalL7NamesToExt $l7ConfSettings $param $paramValue

		Start-Sleep -m 150
	}
	$data = New-Object -TypeName PSObject -Property $l7ConfSettings

	$l7ConfConf = [ordered]@{}
	$l7ConfConf.PSTypeName = "AdcL7Configuration"
	$l7ConfConf.add("AdcL7Configuration", $data)
	$l7ConfObject = New-Object -TypeName PSObject -Property $l7ConfConf

	setKempAPIReturnObject 200 "Command successfully executed" $l7ConfObject
}
Export-ModuleMember -function Get-AdcL7Configuration, Get-L7Configuration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcL7Configuration
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

		[bool]$Transparent,

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

		[bool]$CEFmsgFormat,

		[ValidateRange(0, 600)]
		[Int16]$SlowStart,

		[bool]$ShareSubVSPersistance,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if ($AlwaysCheckPersist) {
		mapL7ConfigName $params "AlwaysCheckPersist" $AlwaysCheckPersist
	}

	if ($AdditionalL7Header) {
		mapL7ConfigName $params "AdditionalL7Header" $AdditionalL7Header
	}

	if ($OneHundredContinueHandling) {
		mapL7ConfigName $params "OneHundredContinueHandling" $OneHundredContinueHandling
	}

	foreach ($entry in $params.Keys) {
		$lma = SetLmParameter $entry $params[$entry] $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		Start-Sleep -m 150
	}

	$getParams = [ordered]@{LoadBalancer=$LoadBalancer; LBPort=$LBPort}
	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$getParams.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertificateStoreLocation))) {
			$getParams.Add("CertificateStoreLocation", $CertificateStoreLocation)
		}
	}
	else {
		$getParams.Add("Credential", $Credential)
	}
	Get-AdcL7Configuration @getParams
}
Export-ModuleMember -function Set-AdcL7Configuration, Set-L7Configuration

Function Get-AdcL7LogInsightSplitConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$paramName = "logsplitinterval"
	$lma = GetLmParameter "$paramName" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		$rc = $lma.ReturnCode
		$rs = $lma.Response
		setKempAPIReturnObject $rc $rs $null
		return
	}

	$AdcL7LogInsightSplitSettings = [ordered]@{}
	$AdcL7LogInsightSplitSettings.PSTypeName = "Adc L7 LogInsightSplit Configuration"

	$paramValue = $lma.Data.$paramName
	$AdcL7LogInsightSplitSettings.add($paramName, $paramValue)

	$data = New-Object -TypeName PSObject -Property $AdcL7LogInsightSplitSettings
	setKempAPIReturnObject 200 "Command successfully executed" $data
}
Export-ModuleMember -function Get-AdcL7LogInsightSplitConfiguration, Get-LogSplitInterval

Function Set-AdcL7LogInsightSplitConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters

	foreach ($entry in $params.Keys) {
		$lma = SetLmParameter $entry $params[$entry] $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($lma.ReturnCode -ne 200) {
			$rc = $lma.ReturnCode
			$rs = $lma.Response
			setKempAPIReturnObject $rc $rs $null
			return
		}
		Start-Sleep -m 150
	}

	$getParams = [ordered]@{LoadBalancer=$LoadBalancer; LBPort=$LBPort}
	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		$getParams.Add("SubjectCN", $SubjectCN)
		if (-not ([String]::IsNullOrEmpty($CertificateStoreLocation))) {
			$getParams.Add("CertificateStoreLocation", $CertificateStoreLocation)
		}
	}
	else {
		$getParams.Add("Credential", $Credential)
	}
	Get-AdcL7LogInsightSplitConfiguration @getParams
}
Export-ModuleMember -function Set-AdcL7LogInsightSplitConfiguration, Set-LogSplitInterval

Function Get-AdcServiceHealth
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "showhealth" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcServiceHealth" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcServiceHealth, Get-ServiceHealth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcServiceHealth
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($CheckInterval) {
		# not possible use the ParamReplacement array to replace CheckInterval with
		# RetryInterval because CheckInterval is used also by Misc (see GEO).
		$params.Remove("CheckInterval")
		$params.Add("RetryInterval", $CheckInterval)
	}
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "modhealth" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcServiceHealth" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcServiceHealth, Set-ServiceHealth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcHttpCompressionException
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		AddRemoveAdcHttpCacheCompressionException $Extension "addnocompress" $ConnParams
	}
}
Export-ModuleMember -function New-AdcHttpCompressionException, Add-NoCompressExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcHttpCompressionException
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		AddRemoveAdcHttpCacheCompressionException $Extension "delnocompress" $ConnParams
	}
}
Export-ModuleMember -function Remove-AdcHttpCompressionException, Remove-NoCompressExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcHttpCacheException
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		AddRemoveAdcHttpCacheCompressionException $Extension "addnocache" $ConnParams
	}
}
Export-ModuleMember -function New-AdcHttpCacheException, Add-NoCacheExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcHttpCacheException
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		AddRemoveAdcHttpCacheCompressionException $Extension "delnocache" $ConnParams
	}
}
Export-ModuleMember -function Remove-AdcHttpCacheException, Remove-NoCacheExtension

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcAdaptiveHealthCheck
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "showadaptive" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "AdcAdaptiveHealthCheck" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcAdaptiveHealthCheck, Get-AdaptiveCheck

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcAdaptiveHealthCheck
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modadaptive" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "AdcAdaptiveHealthCheck" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcAdaptiveHealthCheck, Set-AdaptiveCheck

Function New-AdcVsWafRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "vsaddwafrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcVsWafRule, VSAddWafRule

Function Remove-AdcVsWafRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "vsremovewafrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-AdcVsWafRule, VSRemoveWafRule

Function Get-AdcVsWafRule
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	# NOTE: The Rule parameter string should have the following syntax:
	#       C/string for Custom rule
	#       Z/string for Application Generic rule
	#       A/string for Application Specific rule
	#       G/string for Generic rule
	#
	#       Example: G/ip_reputation
	#
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "vslistwafruleids" -ParameterValuePair $params -ConnParams $ConnParams
		$ruleName = $Rule.Split("/")[1]
		HandleLmAnswer -Command2ExecClass "AdcWafVSRules" -LMResponse $response -AdditionalData $ruleName
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcVsWafRule, VSListWafRuleIds

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcTotalVirtualService
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "vstotals" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVSTotals" -LMResponse $response -AdditionalData $true
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcTotalVirtualService

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Install-VSErrorFile
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path
	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "uploadvserrfile" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "InstallLmAddon" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-VSErrorFile

# ==================================================
# endregion ADC
# ==================================================


# ==================================================
# region SECURITY
# ==================================================

Function Enable-SecAPIAccess
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65535)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params.Add("param", "enableapi")
	$params.Add("value", "yes")

	$response = Set-LmParameter @params

	if ($response.ReturnCode -eq 200) {
		setKempAPIReturnObject 200 "The API is enabled" $null
	}
	else {
		$errCode = $response.ReturnCode
		$errMsg = $response.Response
		setKempAPIReturnObject $errCode "$errMsg" $null
	}
}
Export-ModuleMember -function Enable-SecAPIAccess

Function Disable-SecAPIAccess
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65535)]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params.Add("param", "enableapi")
	$params.Add("value", "no")

	$response = Set-LmParameter @params

	if ($response.ReturnCode -eq 200) {
		setKempAPIReturnObject 200 "The API is disabled" $null
	}
	else {
		if ($response.Response.Contains("(404) Not Found.")) {
			setKempAPIReturnObject 400 "The API is already disabled" $null
		}
		else {
			return $response
		}
	}
}
Export-ModuleMember -function Disable-SecAPIAccess

Function Test-SecAPIAccess
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65535)]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params.Add("param", "version")

	$response = Get-LmParameter @params
	if ($response.ReturnCode -eq 200) {
		setKempAPIReturnObject 200 "The API is enabled" $response.Data
	}
	else {
		if ($response.Response.Contains("(404) Not Found.")) {
			setKempAPIReturnObject 400 "The API is NOT enabled" $null
		}
		else {
			return $response
		}
	}
}
Export-ModuleMember -function Test-SecAPIAccess

Function New-SecUser
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,

		[String]$Password,

		[bool]$Radius,

		[switch]$NoPassword,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ($Password -and ($NoPassword -eq $true) ) {
		Throw "ERROR: Password and No Password are mutually exclusive"
		return
	}

	if ($NoPassword -eq $false -and ([String]::IsNullOrEmpty($Password)) ) {
		Throw "ERROR: Password can't be null"
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($NoPassword -eq $true) {
		$params.Remove("NoPassword")
		$params.Add("nopass", "yes")
	}

	try {
		$response = SendCmdToLm -Command "useraddlocal" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-SecUser

Function Remove-SecUser
{	
	[cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$User,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove the user $User?"))) {
		try {
			$response = SendCmdToLm -Command "userdellocal" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-SecUser

Function Get-SecUser
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$User,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	try {
		if ( ([String]::IsNullOrEmpty($User)) ) {
			$response = SendCmdToLm -Command "userlist" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GetAllSecUser" -LMResponse $response
		}
		else {
			$response = SendCmdToLm -Command "usershow" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GetSingleSecUser" -LMResponse $response
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-SecUser

# Internal use only
Function mapSecRemoteAccessParamsName($params)
{
	foreach ($key in Get-Member -InputObject $params -MemberType NoteProperty) {
		switch ($key.Name)
		{
			"SSHPreAuth" {
				renameCustomObjectProperty $params "SSHPreAuth" "SSHPreAuthBanner"
				break
			}

			"multihomedwui" {
				renameCustomObjectProperty $params "multihomedwui" "MultiHomedWui"
				break
			}

			"tethering" {
				renameCustomObjectProperty $params "tethering" "AllowUpdateChecks"
				break
			}

			<#
			"geo_ssh_iface" {
				renameCustomObjectProperty $params "geo_ssh_iface" "GeoInterfaceId"
				break
			}
			#>
		}
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-SecRemoteAccess
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$parameters = @("sshaccess", "sshiface", "sshport", "sshpreauth"
	                "wuiaccess", "multihomedwui", "enableapi",
	                "tethering", "geoclients", "geopartners", "geosshport", "geo_ssh_iface")

	$lma = GetLmParameterSet $parameters "SecRemoteAccessSettings" $params

	if ($lma.Data.SecRemoteAccessSettings) {
		mapSecRemoteAccessParamsName $lma.Data.SecRemoteAccessSettings
	}

	$lma
}
Export-ModuleMember -function Get-SecRemoteAccess

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-SecRemoteAccess
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$SSHAccess,

		[string]$SSHIface,

		[ValidateRange(3, 65530)]
		[Int]$SSHPort,

		[string]$SSHPreAuthBanner,

		[bool]$WUIAccess,

		[bool]$MultiHomedWui,

		[bool]$EnableAPI,

		[bool]$AllowUpdateChecks,

		[String]$GeoClients,

		[String]$GeoPartners,

		[ValidateRange(3, 65530)]
		[Int]$GeoSSHPort,

		#[int32]$GeoInterfaceId,
		[int32]$geo_ssh_iface,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if ($parameters2set.ContainsKey("EnableAPI")) {
		$errMsg = "EnableAPI parameter is deprecated. Please use Enable/Disable-SecAPIAccess cmdlets"
		setKempAPIReturnObject 400 $errMsg $null
		return
	}

	if ($parameters2set.ContainsKey("GeoClients")) {
		$parameters2set["GeoClients"] = $GeoClients.replace(" ", "")
	}

	if ($parameters2set.ContainsKey("GeoPartners")) {
		$parameters2set["GeoPartners"] = $GeoPartners.replace(" ", "")
	}

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	$lma = GetLmParameterSet $params2Get "Parameters" $params

	if ($lma.Data.Parameters) {
		mapSecRemoteAccessParamsName $lma.Data.Parameters
	}

	$lma
}
Export-ModuleMember -function Set-SecRemoteAccess

# Internal use only
Function mapSecAdminAccessParamsName($params)
{
	foreach ($key in Get-Member -InputObject $params -MemberType NoteProperty) {
		switch ($key.Name)
		{
			"wuiiface" {
				renameCustomObjectProperty $params "wuiiface" "WuiNetworkInterfaceId"
				break
			}

			"wuiport" {
				renameCustomObjectProperty $params "wuiport" "WuiPort"
				break
			}

			"admingw" {
				renameCustomObjectProperty $params "admingw" "WuiDefaultGateway"
				break
			}
		}
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-SecAdminAccess
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$secRemAccParams = @("wuiiface", "wuiport", "admingw")
	$lma = GetLmParameterSet $secRemAccParams "SecAdminAccessConfiguration" $params
	if ($lma.Data.SecAdminAccessConfiguration) {
		mapSecAdminAccessParamsName $lma.Data.SecAdminAccessConfiguration
	}
	$lma
}
Export-ModuleMember -function Get-SecAdminAccess

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-SecAdminAccess
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ($WuiNetworkInterfaceId -lt 0) {
		Throw "ERROR: the WuiNetworkInterfaceId parameter is mandatory"
		return
	}

	if ($WuiPort -lt 0) {
		Throw "ERROR: the WuiPort parameter is mandatory"
		return
	}

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$response = Get-NetworkInterface @params
	if ($response.ReturnCode -ne 200) {
		return $response
	}

	$interfaceDetails = $response.Data.Interface
	$intfCheck = checkInterface $interfaceDetails $WuiNetworkInterfaceId
	if ($intfCheck -eq $false) {
		setKempAPIReturnObject 401 "The interface id [$WuiNetworkInterfaceId] is out of range." $null
		return
	}
	Write-Verbose "(new) interface id [$WuiNetworkInterfaceId]"
	$currIntfId = getCurrentIntfId $interfaceDetails $LoadBalancer
	Write-Verbose "current interface id [$currIntfId]"

	try {
		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$CmdParams = [ordered]@{
			wuiiface = $WuiNetworkInterfaceId
			wuiport  = $WuiPort
		}

		if ($WuiDefaultGateway) {
			$CmdParams.Add("wuidefaultgateway", $WuiDefaultGateway)
		}

		$response = SendCmdToLm -Command "setadminaccess" -ParameterValuePair $CmdParams -ConnParams $ConnParams
		$tmp = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($tmp.ReturnCode -ne 200) {
			return $tmp
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}

	if ($currIntfId -eq $WuiNetworkInterfaceId) {
		$reconnectIP  = $LoadBalancer
		$newIntfIdx   = $currIntfId
		Write-Verbose "Interface id has not changed: connect with the same IP [$reconnectIP]"
	}
	else {
		$reconnectIP  = getIpFromCidrNotation $interfaceDetails[$WuiNetworkInterfaceId].IPAddress
		$newIntfIdx   = $WuiNetworkInterfaceId
		$params.Remove("LoadBalancer")
		$params.Add("LoadBalancer", $reconnectIP)
		Write-Verbose "Interface id has changed: connect with the new IP [$reconnectIP]"
	}

	if ($LBPort -eq $WuiPort) {
		$reconnectPort = $LBPort
		Write-Verbose "The LM https port has not changed: [$reconnectPort]"
	}
	else {
		$reconnectPort = $WuiPort
		$params.Remove("LBPort")
		$params.Add("LBPort", $reconnectPort)
		Write-Verbose "The LM https port has changed: [$reconnectPort]"
	}

	$wait = $true
	$counter = 1
	$maxStep = 10
	$sleepTime = 10
	while ($wait -eq $true) {
		Write-Verbose "reconnecting to the LM . . . (step $counter, max step $maxStep)"
		if (-not (Test-LmServerConnection -ComputerName $reconnectIP -Port $reconnectPort)) {
			$counter += 1
			if ($counter -eq $maxStep) {
				setKempAPIReturnObject 401 "ERROR: Unable to re-connect to the LM. Reboot the LM." $null
				return
			}
			Start-Sleep -s $sleepTime
		}
		else {
			$wait = $false
		}
	}

	$secRemAccParams = @("wuiiface", "wuiport", "admingw")
	$lma = GetLmParameterSet $secRemAccParams "SecAdminAccessConfiguration" $params
	if ($lma.Data.SecAdminAccessConfiguration) {
		mapSecAdminAccessParamsName $lma.Data.SecAdminAccessConfiguration
	}
	$lma
}
Export-ModuleMember -function Set-SecAdminAccess, Set-AdminAccess

# Internal use only
Function mapOutLoginMethodName($loginMethodData)
{
	if ($loginMethodData) {
		renameCustomObjectProperty $loginMethodData "adminclientaccess" "LoginMethod"
		$numericLoginMethodValue = $loginMethodData.LoginMethod

		$item = $loginMethodHT.GetEnumerator() | ? {$_.Value -eq $numericLoginMethodValue}
		$loginMethodName = $item.Name

		$loginMethodData.LoginMethod = $loginMethodName
	}
}

Function Get-SecRemoteAccessLoginMethod
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$lma = GetLmParameter "adminclientaccess" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	mapOutLoginMethodName $lma.Data
	$lma
}
Export-ModuleMember -function Get-SecRemoteAccessLoginMethod

Function Set-SecRemoteAccessLoginMethod
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("PasswordOnly", "PasswordorClientCertificate", "ClientCertificateRequired", "ClientCertificateRequiredOCSP")]
		[string]$LoginMethod,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	SetLmParameter "adminclientaccess" $loginMethodHT[$loginMethod] $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function Set-SecRemoteAccessLoginMethod

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-SecWuiAuthentication
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$parameters = @("radiusserver", "radiusport", "radiussecret", "radiusrevalidateinterval",
	                "radiusbackupserver", "radiusbackupport", "radiusbackupsecret",
	                "wuildapep", "wuicertmapping", "wuiusergroups", "wuinestedgroups",
			"WuiDomain", "sessionlocalauth", "sessionauthmode")

	GetLmParameterSet $parameters "SecWuiAuthenticationConfiguration" $params
}
Export-ModuleMember -function Get-SecWuiAuthentication, Get-WUIAuth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-SecWuiAuthentication
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

		[ValidateSet("UserPrincipalName", "Subject", "IssuerandSubject", "IssuerandSerialNumber")]
		[string]$Wuicertmapping,

		[string]$Wuiusergroups,

		[ValidateSet("yes", "no")]
	 	[string]$Wuinestedgroups,

		[bool]$SessionLocalAuth,

		[ValidateSet(7, 22, 23, 262, 263, 278, 279, 772, 773, 774, 775, 788, 789, 790, 791)]
		[Int16]$SessionAuthMode,

		[string]$WuiDomain,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if ($Wuicertmapping) {
		$parameters2set.Remove("Wuicertmapping")
		$parameters2set.Add("wuicertmapping", $WuiCertMapHT[$Wuicertmapping]) 
	}

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	GetLmParameterSet $params2Get "Parameters" $params
}
Export-ModuleMember -function Set-SecWuiAuthentication, Set-WUIAuth

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-SecAdminWuiConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$parameters = @("WUITLSProtocols", "WUICipherset",
	                "sessioncontrol", "sessionbasicauth", "sessionmaxfailattempts",
	                "sessionidletime", "sessionconcurrent", "wuipreauth")

	GetLmParameterSet $parameters "SecAdminWuiConfiguration" $params
}
Export-ModuleMember -function Get-SecAdminWuiConfiguration, Get-WUISetting

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-SecAdminWuiConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateRange(0, 30)]
		[int]$WUITLSProtocols,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	GetLmParameterSet $params2Get "Parameters" $params
}
Export-ModuleMember -function Set-SecAdminWuiConfiguration, Set-WUISetting

Function New-SecUserCertificate
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$User,

		[ValidateNotNullOrEmpty()]
		[String]$Passphrase,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{
		user = $User
	}

	if ($Passphrase) {
		$params.Add("passphrase", [System.Web.HttpUtility]::UrlEncode($Passphrase))
	}

	try {
		$response = SendCmdToLm -Command "usernewcert" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-SecUserCertificate

Function Export-SecUserCertificate
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$User,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path,
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "userdownloadcert" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-SecUserCertificate

Function Remove-SecUserCertificate
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$User,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "userdelcert" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-SecUserCertificate

Function Set-SecSystemUserPassword
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "usersetsyspassword" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SecSystemUserPassword, UserSetSystemPassword

Function Set-SecUserPermission
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "usersetperms" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SecUserPermission, UserSetPermissions

Function Set-SecUserPassword
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "userchangelocpass" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SecUserPassword, UserChangeLocalPassword

Function New-SecRemoteUserGroup
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$Group,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "groupaddremote" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-SecRemoteUserGroup

Function Remove-SecRemoteUserGroup
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$Group,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "groupdelremote" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-SecRemoteUserGroup

Function Set-SecRemoteUserGroup
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[String]$Group,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "groupsetperms" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SecRemoteUserGroup

Function Get-SecRemoteUserGroup
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[String]$Group,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Group) {
		$cmd = "groupshow"
		$class = "GetRemoteGroup"
	}
	else {
		$cmd = "grouplist"
		$params.Remove("Group")
		$class = "GetAllRemoteGroups"
	}

	try {
		$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass $class -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-SecRemoteUserGroup

Function New-SecApiKey
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "addapikey" -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewApiSecurityKey" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-SecApiKey

Function Get-SecApiKey
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "listapikeys" -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetApiSecurityKeys" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-SecApiKey

Function Remove-SecApiKey
{	
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[String]$apikey,

		[String]$key,

		[String]$user,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delapikey" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "RemoveApiSecurityKeys" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-SecApiKey

# ==================================================
# endregion SECURITY
# ==================================================


# ==================================================
# region SYSTEM
# ==================================================

# Internal use only
Function SetScriptConnectionParams($Address, $LBPort)
{
	$cString = "Unless overridden using a local"
	$lmIpString = "$cString -LoadBalancer parameter, all commands will now be directed to"
	$lmPortString = "$cString -HTTPS  Port  parameter, all commands will now use HTTPS Port"

	$lmCurrentIp = ""
	if ($script:LoadBalancerAddress) {
		$lmCurrentIp = $script:LoadBalancerAddress
		$script:LoadBalancerAddress = $null
	}

	$lmCurrentHttpsPort = $null
	if ($script:LBAccessPort) {
		$lmCurrentHttpsPort = $script:LBAccessPort
		$script:LBAccessPort = $null
	}

	$connCheck = Test-LmServerConnection -ComputerName $Address -Port $LBPort
	if ($connCheck -eq $true) {
		$script:LoadBalancerAddress = $Address
		$script:LBAccessPort = $LBPort
	}
	else {
		if (-not ([String]::IsNullOrEmpty($lmCurrentIp))) {
			$script:LoadBalancerAddress = $lmCurrentIp
		}
		if ($lmCurrentHttpsPort) {
			$script:LBAccessPort = $lmCurrentHttpsPort
		}
		Throw "ERROR: Unable to resolve or connect to $Address`:$LBPort"
		return
	}
	Write-Verbose "$lmIpString $($script:LoadBalancerAddress)"
	Write-Verbose "$lmPortString $($script:LBAccessPort)."
}

# Internal use only
Function SetScriptLoginCertParams($SubjectCN, $CertificateStoreLocation, $currentCertStoreLoc, $cString)
{
	$lmLoginCertString = "$cString -SubjectCN parameter, all commands will now use"
	$lmLoginCertLocString = "$cString -CertificateStoreLocation parameter, all commands will now use"

	$temp_SubjectCN = $SubjectCN

	if (-not ([String]::IsNullOrEmpty($CertificateStoreLocation))) {
		$temp_CertificateStoreLocation = $CertificateStoreLocation
	}
	else {
		if (-not ([String]::IsNullOrEmpty($currentCertStoreLoc))) {
			$temp_CertificateStoreLocation = $currentCertStoreLoc
		}
		else {
			$temp_CertificateStoreLocation = "Cert:\CurrentUser\My"
		}
	}

	# test if the login certificate exists
	$LCert = Get-LoginCertificate $temp_CertificateStoreLocation $temp_SubjectCN
	if ($LCert -ne $null) {
		$script:SubjectCN = $temp_SubjectCN
		$script:CertificateStoreLocation = $temp_CertificateStoreLocation
	
		$script:cred = $null
	}
	else {
		Throw "ERROR: Can't find certificate `"$temp_SubjectCN`" in the `"$temp_CertificateStoreLocation`" store."
		return
	}
	Write-Verbose "$lmLoginCertString `"$($script:SubjectCN)`" as login certificate."
	Write-Verbose "$lmLoginCertLocString `"$($script:CertificateStoreLocation)`" as certificate location."
	Write-Verbose "Previous credential settings has been removed."
}

# Internal use only
Function SetScriptLoginCredParams($Credential, $cString)
{
	$lmCredString = "$cString -Credential parameter, all commands will now use"

	$script:SubjectCN = $null
	$script:CertificateStoreLocation = $null
	$script:cred = $Credential

	Write-Verbose "$lmCredString `"$($script:cred.Username)`" as user."
	Write-Verbose "Previous certificate settings have been removed."
}

# Internal use only
Function SetBackScriptLoginMethod($currentSubjectCN, $currentCertStoreLoc, $currentCred)
{
	if ($currentSubjectCN) {
		$script:SubjectCN = $currentSubjectCN

		if ($currentCertStoreLoc) {
			$script:CertStoreLoc = $currentCertStoreLoc
		}
		$loginMethod = "certificate"
	}

	if ($currentCred) {
		$script:cred = $currentCred
		$loginMethod = "credential"
	}
	return $loginMethod
}

# Internal use only
Function SetScriptLoginMethod($SubjectCN, $CertificateStoreLocation, $Credential)
{
	$cString = "Unless overridden using a local"

	$currentSubjectCN = ""
	if ($script:SubjectCN) {
		$currentSubjectCN = $script:SubjectCN
		$script:SubjectCN = $null
	}

	$currentCertStoreLoc = ""
	if ($script:CertStoreLoc) {
		$currentCertStoreLoc = $script:CertStoreLoc
		$script:CertStoreLoc = $null
	}

	$currentCred = ""
	if ($script:cred) {
		$currentCred = $script:cred
		$script:cred = $null
	}

	if (-not ([String]::IsNullOrEmpty($SubjectCN))) {
		SetScriptLoginCertParams $SubjectCN $CertificateStoreLocation $currentCertStoreLoc $cString
		return "certificate"
	}
	elseif ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
		SetScriptLoginCredParams $Credential $cString
		return "credential"
	}
	else {
		$loginMethod = SetBackScriptLoginMethod $currentSubjectCN $currentCertStoreLoc $currentCred
		return $loginMethod
	}
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Initialize-LmConnectionParameters
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

	if ( ([String]::IsNullOrEmpty($Address)) ) {
		Throw "ERROR: The parameter `"Address`" is mandatory"
		return
	}

	$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])
	if ($netAssembly) {
		$bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
		$settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

		$instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())
		if ($instance) {
			$bindingFlags = "NonPublic","Instance"
			$useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)
			if ($useUnsafeHeaderParsingField) {
				$useUnsafeHeaderParsingField.SetValue($instance, $true)
			}
		}
	}

	$connectionData = [ordered]@{}
	$connectionData.PSTypeName = "ConnectionData"

	SetScriptConnectionParams $Address $LBPort

	$connectionData.Add("LoadBalancer", $script:LoadBalancerAddress)
	$connectionData.Add("HttpsPort", $script:LBAccessPort)
	$connectionDataObject = New-Object -TypeName PSObject -Property $connectionData

	$loginData = [ordered]@{}
	$loginData.PSTypeName = "LoginData"

	$response = SetScriptLoginMethod $SubjectCN $CertificateStoreLocation $Credential
	if ($response -eq "certificate") {
		$loginData.Add("SubjectCN", $script:SubjectCN)
		$loginData.Add("CertificateStoreLocation", $script:CertificateStoreLocation)
	}
	elseif ($response -eq "credential") {
		$loginData.Add("Credential", $script:cred)
	}
	else {
		Write-Verbose "Login method not set or un-changed"
	}
	$loginDataObject = New-Object -TypeName PSObject -Property $loginData

	$connLoginData = [ordered]@{}
	$connLoginData.PSTypeName = "ConnectionLoginData"
	$connLoginData.Add("Connection", $connectionDataObject)
	$connLoginData.Add("Login", $loginDataObject)
	$connLoginDataObject = New-Object -TypeName PSObject -Property $connLoginData

	setKempAPIReturnObject 200 "Command successfully executed." $connLoginDataObject
}
Export-ModuleMember -function Initialize-LmConnectionParameters, Initialize-LoadBalancer

Function Test-LmServerConnection
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName,

		[ValidateRange(3, 65530)]
		[Int32]$Port
	)

	$params = [ordered]@{
		param = "version"
		LoadBalancer = $ComputerName
		LBPort = $Port
	}

	if (-not ([String]::IsNullOrEmpty($script:SubjectCN))) {
		$params["SubjectCN"] = $script:SubjectCN
		if (-not ([String]::IsNullOrEmpty($script:CertificateStoreLocationn))) {
			$params["CertificateStoreLocation"] = $script:CertificateStoreLocationn
		}
	}
	elseif ($script:cred -ne $null) {
		$params["Credential"] = $script:cred
	}
	else {
		$fpasswd = ConvertTo-SecureString "invalidpassword" -AsPlainText -Force
		$fcreds = New-Object System.Management.Automation.PSCredential("bal", $fpasswd)
		$params["Credential"] = $fcreds
	}

	try {
		$LmTestServerConnectionFlag = $true
		Write-Verbose -Message "Connecting to $ComputerName on $Port . . ."
		$LmResponse = Get-LmParameter @params
		$rc = $LmResponse.ReturnCode
		$rs = $LmResponse.Response
		Write-Verbose "ret code [$rc]"
		Write-Verbose "ret resp [$rs]"
		if ( ($rc -eq 200) -or
		     ($rc -eq 401 -and $rs.Contains("(401) Unauthorized")) -or
		     ($rc -eq 401 -and $rs.Contains("(401)")) -or
		     ($rc -eq 400 -and $rs.Contains("(401) Unauthorized")) -or
		     ($rc -eq 400 -and $rs.Contains("(401)")) -or
		     ($rc -eq 405 -and $rs.Contains("Unknown command")) -or
		     ($rc -eq 400 -and $rs.Contains("Not Found")) -or
		     ($rc -eq 405) ) {
			# the LM is up and running
			$LmTestServerConnectionFlag = $false
			Write-Verbose -Message "OK, the LM Server is up and running"
			return $true
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		$LmTestServerConnectionFlag = $false
		Write-Verbose -Message "ERROR: Exception caught [$errMsg]"
	}
	return $false
}
Export-ModuleMember -function Test-LmServerConnection, Test-ServerConnection

Function Get-LmRaidController
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "getraidinfo" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetRaidController" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmRaidController

Function Get-LmRaidControllerDisk
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "getraiddisksinfo" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetRaidControllerDisk" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmRaidControllerDisk

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-AdcLimitRules
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "listlimitrules" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcLimitRules" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-AdcLimitRules

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-AdcLimitRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Pattern,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$Limit,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet(0, 1, 2, 64, 65, 66)]
		[int]$Match,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "addlimitrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcLimitRules" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-AdcLimitRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-AdcLimitRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Pattern,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$Limit,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet(0, 1, 2, 64, 65, 66)]
		[int]$Match,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "modlimitrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcLimitRules" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-AdcLimitRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Move-AdcLimitRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$Position,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "movelimitrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcLimitRules" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Move-AdcLimitRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-AdcLimitRule
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
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
			[String]$SubjectCN = $script:SubjectCN
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "dellimitrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAdcLimitRules" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-AdcLimitRule

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-ClientCPSLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientcpslimitlist" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientCPSLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-ClientCPSLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-ClientCPSLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$L7Limit,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientcpslimitadd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientCPSLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-ClientCPSLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-ClientCPSLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientcpslimitdel" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientCPSLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-ClientCPSLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-ClientRPSLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientrpslimitlist" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientRPSLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-ClientRPSLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-ClientRPSLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$L7Limit,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientrpslimitadd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientRPSLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-ClientRPSLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-ClientRPSLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientrpslimitdel" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientRPSLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-ClientRPSLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-ClientMaxcLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientmaxclimitlist" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientMaxcLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-ClientMaxcLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-ClientMaxcLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$L7Limit,

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
	$params = ConvertBoundParameters -hashtable $psboundparameters
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientmaxclimitadd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientMaxcLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-ClientMaxcLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-ClientMaxcLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientmaxclimitdel" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientMaxcLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-ClientMaxcLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-ClientBandwidthLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientbandwidthlimitlist" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientBandwidthLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-ClientBandwidthLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-ClientBandwidthLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[int]$L7Limit,

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
	$params = ConvertBoundParameters -hashtable $psboundparameters
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientbandwidthlimitadd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientBandwidthLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-ClientBandwidthLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-ClientBandwidthLimit
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$L7Addr,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "clientbandwidthlimitdel" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClientBandwidthLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-ClientBandwidthLimit

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LMIngressMode
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

	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "getlmingressmode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetMode" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LMIngressMode

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LMIngressMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Mode,

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

	$params = ConvertBoundParameters -hashtable $psboundparameters
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "setlmingressmode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LMIngressMode

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LMIngressNamespace
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

	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "getlmingressnamespace" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetNamespace" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LMIngressNamespace

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LMIngressNamespace
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Namespace,

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

	$params = ConvertBoundParameters -hashtable $psboundparameters
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "setlmingressnamespace" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LMIngressNamespace

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LMIngressWatchTimeout
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

	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "getlmingresswatchtimeout" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetWatchTimeout" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LMIngressWatchTimeout

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LMIngressWatchTimeout
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$WatchTimeout,

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

	$params = ConvertBoundParameters -hashtable $psboundparameters
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "setlmingresswatchtimeout" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LMIngressWatchTimeout

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LMIngressK8sConf
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

	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "showlmingressk8sconf" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetContext" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LMIngressK8sConf

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Restart-LMIngress
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

	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "restartlmingress" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Restart-LMIngress

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Install-LMIngressK8sConf
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addlmingressk8sconf" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "InstallLmAddon" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-LMIngressK8sConf

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-LMIngressK8sConf
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

	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	try {
		$response = SendCmdToLm -Command "dellmingressk8sconf" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LMIngressK8sConf

# ==================================================
# endregion SYSTEM
# ==================================================


# ==================================================
# region GET-SET
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmAllParameters
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = @{}

	try {
		$response = SendCmdToLm -Command "getall" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAllParameters" -LMResponse $response -AdditionalData "AllParameters"
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmAllParameters, Get-AllParameters

Function Get-LmParameter
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "get" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAllParameters" -LMResponse $response -AdditionalData "Parameter"
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmParameter, Get-Parameter

Function Set-LmParameter
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "set" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmParameter, Set-Parameter

# ==================================================
# endregion GET-SET
# ==================================================


# ==================================================
# region TLS
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-TlsCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{cert=$name; replace="0"}
	if ($Replace) {
		$params["replace"]="1"
	}

	if ($Password) {
		$params.Add("password",[System.Web.HttpUtility]::UrlEncode($Password))
	}

	try {
		$response = SendCmdToLm -Command "addcert" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-TlsCertificate, New-Certificate

Function Get-TlsCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if (([String]::IsNullOrEmpty($CertName))) {
			$response = SendCmdToLm -Command "listcert" -ParameterValuePair $params -ConnParams $ConnParams
		}
		else {
			$params.Remove("CertName")
			$params.Add("cert", $CertName)
			$response = SendCmdToLm -Command "readcert" -ParameterValuePair $params -ConnParams $ConnParams
		}
		HandleLmAnswer -Command2ExecClass "GetTlsCertificate" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-TlsCertificate, ListCert

Function Remove-TlsCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove Certificate")))
	{
		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = @{cert=$Name}

		try {
			$response = SendCmdToLm -Command "delcert" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-TlsCertificate, Remove-Certificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
#
# NOTE: If the input parameter Path is not set,
#       the default  location where  the cmdlet
#       tries to save the TlsCertificate is:
#
#         $($Env:SystemRoot)\Temp
#
#       If the above folder does not exist or it is not
#       accessible (permissions) the cmdlet will fail.
#
Function Backup-TlsCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{}
	$params.Add("password", [System.Web.HttpUtility]::UrlEncode($Password))

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\CertificateBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	Write-Verbose "Path = $Path"

	try {
		$response = SendCmdToLm -Command "backupcert" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Backup-TlsCertificate, Backup-Certificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Restore-TlsCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{}
	$params.Add("password", [System.Web.HttpUtility]::UrlEncode($Password))
	$params.Add("Type", $Type.ToLower())

	try {
		$response = SendCmdToLm -Command "restorecert" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Restore-TlsCertificate, Restore-Certificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-TlsIntermediateCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	#
	# TODO: the structure of this command is the same of addcert (New-TlsCertificate).
	#       To avoid code duplication, set a common function accepting among the input
	#       parameters, the command to execute (addcert/addintermediate).
	#

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{cert=$name; replace="0"}
	if ($Replace) {
		$params["replace"]="1"
	}

	if ($Password) {
		$params.Add("password",[System.Web.HttpUtility]::UrlEncode($Password))
	}

	try {
		$response = SendCmdToLm -Command "addintermediate" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-TlsIntermediateCertificate, New-IntermediateCertificate

Function Get-TlsIntermediateCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if (([String]::IsNullOrEmpty($CertName))) {
			$response = SendCmdToLm -Command "listintermediate" -ParameterValuePair $params -ConnParams $ConnParams
		}
		else {
			$params.Remove("CertName")
			$params.Add("cert", $CertName)
			$response = SendCmdToLm -Command "readintermediate" -ParameterValuePair $params -ConnParams $ConnParams
		}
		HandleLmAnswer -Command2ExecClass "GetTlsCertificate" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-TlsIntermediateCertificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-TlsIntermediateCertificate
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (($Force) -or ($PsCmdlet.ShouldProcess($Name, "Remove Certificate")))
	{
		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = @{cert=$Name}

		try {
			$response = SendCmdToLm -Command "delintermediate" -ParameterValuePair $params -ConnParams $ConnParams
			HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
		}
	}
}
Export-ModuleMember -function Remove-TlsIntermediateCertificate, Remove-IntermediateCertificate

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-TlsCipherSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getcipherset" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetTlsCipherSet" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-TlsCipherSet, GetCipherset

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-TlsCipherSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modifycipherset" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-TlsCipherSet, ModifyCipherset

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-TlsCipherSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delcipherset" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-TlsCipherSet, DelCipherset

# ==================================================
# endregion TLS
# ==================================================


# ==================================================
# region WAF
# ==================================================

# Internal use only
Function validatePath($Path, $FileName)
{
	if ( ([String]::IsNullOrEmpty($Path)) ) {
		Throw "ERROR: Path is NULL"
		return
	}

	if ($Path -and ( ($Path[-1] -eq "/") -or ($Path[-1] -eq "\") ) ) {
		# Path is a folder
		if ($FileName) {
			$Path += $FileName
		}
		else {
			Throw "ERROR: $Path is not a valid path."
			return
		}
	}

	$folder = Split-Path -Path $Path
	if ($folder) {
		if ($folder -and (-not (Test-Path $folder))) {
			Throw "ERROR: $folder is not a valid path."
			return
		}
	}
	else {
		Throw "ERROR: $Path is not a valid path."
		return
	}

	if ((Test-Path $Path) -and (Test-Path $Path -PathType Container)) {
		Throw "ERROR: $Path is a folder."
		return
	}

	Write-Verbose "Path = $Path"
	return $Path
}

Function Get-WafRules
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "listwafrules" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetWafRules" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-WafRules, ListWafRules

Function New-WafCustomRuleData
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Path) {
		$params.Remove("Path")
		$Filename = Split-Path $Path -leaf
		if ($Filename) {
			$params.Add("filename", $Filename)
		}
		else {
			Throw "ERROR: Malformed file name"
			return
		}
	}
	else {
		Throw "ERROR: Path is a mandatory parameter"
		return
	}

	try {
		$response = SendCmdToLm -Command "addwafcustomdata" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-WafCustomRuleData, AddWafCustomData

Function Export-WafCustomRuleData
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\WafCustomRuleData_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	$Path = validatePath $Path $RuleDataName

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("Path")
	$params.Remove("RuleDataName")
	$params.Add("filename", $RuleDataName)

	try {
		$response = SendCmdToLm -Command "downloadwafcustomdata" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-WafCustomRuleData, DownloadWafCustomData

Function Uninstall-WafCustomRuleData
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delwafcustomdata" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Uninstall-WafCustomRuleData, DelWafCustomData

Function New-WafCustomRuleSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Path) {
		$params.Remove("Path")
		$Filename = Split-Path $Path -leaf
		if ($Filename) {
			$params.Add("filename", $Filename)
		}
		else {
			Throw "ERROR: Malformed file name"
			return
		}
	}
	else {
		Throw "ERROR: Path is a mandatory parameter"
		return
	}

	try {
		$response = SendCmdToLm -Command "addwafcustomrule" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-WafCustomRuleSet, AddWafCustomRule

Function Uninstall-WafCustomRuleSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delwafcustomrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Uninstall-WafCustomRuleSet, DelWafCustomRule

Function Export-WafCustomRuleSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\WafCustomRuleSet_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	$Path = validatePath $Path $RuleSetName

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("Path")
	$params.Remove("RuleSetName")
	$params.Add("filename", $RuleSetName)

	try {
		$response = SendCmdToLm -Command "downloadwafcustomrule" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-WafCustomRuleSet, DownloadWafCustomRule

Function Enable-WafRemoteLogging
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "enablewafremotelogging" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Enable-WafRemoteLogging, EnableWafRemoteLogging
	
Function Disable-WafRemoteLogging
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "disablewafremotelogging" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Disable-WafRemoteLogging, DisableWafRemoteLogging

Function Set-WafLogFormat
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("native", "json")]
		[string]$LogFormat,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setwaflogformat" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-WafLogFormat

Function Get-WafAuditFiles
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "listwafauditfiles" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetWafAuditFiles" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-WafAuditFiles, ListWafAuditFiles

Function Export-WafAuditLog
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Path) {
		$params.Remove("Path")
	}
	$params.Remove("AuditFile")
	$params.Add("File", $AuditFile)

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\wafaudit_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).log"
	}
	$Path = validatePath $Path $AuditFile

	try {
		$response = SendCmdToLm -Command "downloadwafauditlog" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-WafAuditLog, DownloadWafAuditLog

Function Export-WafChangeLog
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Path) {
		$params.Remove("Path")
	}

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\WAF_changes_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).log"
	}
	$Path = validatePath $Path

	try {
		$response = SendCmdToLm -Command "getwafchangelog" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-WafChangeLog, GetWafChangeLog

Function Install-WafRulesDatabase
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "maninstallwafrules" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-WafRulesDatabase, ManInstallWafRules

Function Update-WafRulesDatabase
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "downloadwafrules" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Update-WafRulesDatabase, DownloadWafRules

Function Get-WafRulesAutoUpdateConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getwafsettings" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetWafRulesAutoUpdateConfiguration" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-WafRulesAutoUpdateConfiguration, GetWafSettings

Function Set-WafRulesAutoUpdateConfiguration
{
	Param(
		[Parameter(ParameterSetName="AutoUpdate", Mandatory=$True)]
			[switch]$DatabaseAutoUpdate,

		[Parameter(ParameterSetName="AutoInstall")]
			[switch]$DatabaseAutoInstall,

		[Parameter(ParameterSetName="AutoInstall")]
			[ValidateRange(0, 23)]
			[ValidateNotNullOrEmpty()]
			[Int32]$DatabaseInstallTimeHour,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,

		[ValidateNotNullOrEmpty()]
		[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[ValidateNotNullOrEmpty()]
		[String]$SubjectCN = $script:SubjectCN
	)
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$tempPT = ConvertBoundParameters -hashtable $psboundparameters
	$params = $tempPT.GetEnumerator() | sort-object -Property Name

	try {
		ForEach ($h in $params) {
			switch($($h.Name))
			{
				"DatabaseAutoUpdate" {
					$cmd2do = "setwafautoupdate"
					if ($($h.Value) -eq $true) {
						$dbUpdateParam = @{"Enable" = 1}
					}
					else {
						$dbUpdateParam = @{"Enable" = 0}
					}
					break
				}
				"DatabaseAutoInstall" {
					$cmd2do = "enablewafautoinstall"
					if ($($h.Value) -eq $true) {
						$dbUpdateParam = @{"Enable" = 1}
					}
					else {
						$dbUpdateParam = @{"Enable" = 0}
					}
					break
				}
				"DatabaseInstallTimeHour" {
					$cmd2do = "setwafinstalltime"
					$dbUpdateParam = @{"Hour" = $($h.Value)}
					break
				}
			}

			if ($cmd2do -eq $null) {
				continue
			}

			$xmlAnswer = SendCmdToLm -Command $cmd2do -ParameterValuePair $dbUpdateParam -ConnParams $ConnParams
			$response = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $xmlAnswer
			if ($response.ReturnCode -ne 200) {
				return $response
			}
			$cmd2do = $null
		}
		setKempAPIReturnObject 200 "Command successfully executed" $null
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-WafRulesAutoUpdateConfiguration

Function New-OWASPCustomRuleData
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Path) {
		$params.Remove("Path")
		$Filename = Split-Path $Path -leaf
		if ($Filename) {
			$params.Add("filename", $Filename)
		}
		else {
			Throw "ERROR: Malformed file name"
			return
		}
	}
	else {
		Throw "ERROR: Path is a mandatory parameter"
		return
	}

	try {
		$response = SendCmdToLm -Command "addowaspcustomdata" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-OWASPCustomRuleData, AddOWASPCustomData

Function Export-OWASPCustomRuleData
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\OWASPCustomRuleData_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	$Path = validatePath $Path $RuleDataName

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("Path")
	$params.Remove("RuleDataName")
	$params.Add("filename", $RuleDataName)

	try {
		$response = SendCmdToLm -Command "downloadowaspcustomdata" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-OWASPCustomRuleData, DownloadOWASPCustomData

Function Uninstall-OWASPCustomRuleData
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delowaspcustomdata" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Uninstall-OWASPCustomRuleData, DelOWASPCustomData

Function New-OWASPCustomRuleSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($Path) {
		$params.Remove("Path")
		$Filename = Split-Path $Path -leaf
		if ($Filename) {
			$params.Add("filename", $Filename)
		}
		else {
			Throw "ERROR: Malformed file name"
			return
		}
	}
	else {
		Throw "ERROR: Path is a mandatory parameter"
		return
	}

	try {
		$response = SendCmdToLm -Command "addowaspcustomrule" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-OWASPCustomRuleSet, AddOWASPCustomRule

Function Uninstall-OWASPCustomRuleSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delowaspcustomrule" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Uninstall-OWASPCustomRuleSet, DelOWASPCustomRule

Function Export-OWASPCustomRuleSet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\OWASPCustomRuleSet_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	$Path = validatePath $Path $RuleSetName

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("Path")
	$params.Remove("RuleSetName")
	$params.Add("filename", $RuleSetName)

	try {
		$response = SendCmdToLm -Command "downloadowaspcustomrule" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-OWASPCustomRuleSet, DownloadOWASPCustomRule


# ==================================================
# endregion WAF
# ==================================================


# ==================================================
# region GEO
# ==================================================

# Internal use only
Function SetSelectionCriteria($params, $SelectionCriteria)
{
	switch ($SelectionCriteria)
	{
		"RoundRobin" {$ss = "rr"}
		"WeightedRoundRobin" {$ss = "wrr"}
		"FixedWeighting" {$ss = "fw"}
		"RealServerLoad" {$ss = "rsr"}
		"Proximity" {$ss = "prx"}
		"LocationBased" {$ss = "lb"}
		"AllAvailable" {$ss = "all"}
	}
	$params.Remove("SelectionCriteria")
	$params.Add("SelectionCriteria", $ss)
}

# Internal use only
Function getPublicPrivateRequestIdFromString($case, $ppReqString)
{
	$id = -1
	if ($case -eq "Public") {
		switch ($ppReqString)
		{
			"PublicSitesOnly" {$id = 0}
			"PreferPublicSites" {$id = 1}
			"PreferPrivateSites" {$id = 2}
			"AllSites" {$id = 3}
		}
	}
	elseif ($case -eq "Private") {
		switch ($ppReqString)
		{
			"PrivateSitesOnly" {$id = 0}
			"PreferPrivateSites" {$id = 1}
			"PreferPublicSites" {$id = 2}
			"AllSites" {$id = 3}
		}
	}
	else {
		Throw "ERROR: unknow request string"
		return
	}
	return $id
}

# Internal use only
Function getCheckerValueFromString($checkerString)
{
	switch ($checkerString)
	{
		"None" {
			$checker = "none"
			break
		}
		"Icmp Ping" {
			$checker = "icmp"
			break
		}
		"Tcp Connect" {
			$checker = "tcp"
			break
		}
		"Cluster Checks" {
			$checker = "clust"
			break
		}
		"HTTP" {
			$checker = "http"
			break
		}
		"HTTPS" {
			$checker = "https"
			break
		}
	}
	return $checker
}

Function New-GeoFQDN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "addfqdn" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Added FQDN $FQDN"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoFQDN, Add-GeoFQDN, AddFQDN

Function Remove-GeoFQDN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "delfqdn" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoFQDN, DeleteFQDN

Function Get-GeoFQDN
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($FQDN -eq "") {
			$cmd2exec = "listfqdns"
		}
		else {
			$cmd2exec = "showfqdn"
		}
		$response = SendCmdToLm -Command $cmd2exec -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoFQDN" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoFQDN, ListFQDNs

Function Set-GeoFQDN
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

		[bool]$Failover,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if ($PublicRequest) {
		$PublicRequestValue = getPublicPrivateRequestIdFromString "Public" $PublicRequest
		$params.Remove("PublicRequest")
		$params.Add("PublicRequestValue", $PublicRequestValue)
	}

	if ($PrivateRequest) {
		$PrivateRequestValue = getPublicPrivateRequestIdFromString "Private" $PrivateRequest
		$params.Remove("PrivateRequest")
		$params.Add("PrivateRequestValue", $PrivateRequestValue)
	}

	if ($SiteFailureDelay -ge 0) {
		$params.Remove("SiteFailureDelay")
		$params.Add("FailTime", $SiteFailureDelay)
	}

	if ($SelectionCriteria) {
		SetSelectionCriteria $params $SelectionCriteria
	}

	try {
		$response = SendCmdToLm -Command "modfqdn" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoFQDN" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoFQDN, ModifyFQDN

Function New-GeoCluster
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addcluster" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response -AdditionalData $ClusterName
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoCluster, AddCluster

Function Remove-GeoCluster
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delcluster" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoCluster, DeleteCluster

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($ClusterIp) {
			$cmd2exec = "showcluster"
		}
		else {
			$cmd2exec = "listclusters"
		}
		$response = SendCmdToLm -Command $cmd2exec -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoCluster" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoCluster, ShowCluster, ListClusters

Function Set-GeoCluster
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

		[ValidateRange(3, 65530)]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if ($Type -eq "remoteLM" -or $Type -eq "localLM") {
		$params.Remove("Checker")
	}

	try {
		$response = SendCmdToLm -Command "modcluster" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "SetGeoCluster" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoCluster, ModifyCluster

Function Set-GeoClusterCoordinates
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "clustchangeloc" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Cluster location updated"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoClusterCoordinates, ClusterChangeLocation

Function New-GeoFQDNSiteAddress
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addmap" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Added site $SiteAddress to FQDN $FQDN"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoFQDNSiteAddress, AddMap

Function Remove-GeoFQDNSiteAddress
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delmap" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Deleted site $SiteAddress from FQDN $FQDN"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoFQDNSiteAddress, DeleteMap

Function Set-GeoFQDNSiteAddress
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[ValidateSet("None", "Icmp Ping", "Tcp Connect", "Cluster Checks", "HTTP", "HTTPS")]
		[String]$Checker,

		[Int32]$Weight,

		[String]$Enable,

		[String]$Cluster,

		[String]$Mapaddress,

		[String]$Mapport,

		[String]$CheckerURL,

		[String]$CheckerCodes,

		[Int32]$CheckerHTTPMethod,

		[String]$CheckerHost,

		[String]$CheckerPostData,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($checker) {
		$siteChecker = getCheckerValueFromString $Checker
		$params.Remove("Checker")
		$params.Add("Checker", $siteChecker)
	}
	if ($Cluster) {
		$params.Remove("clust")
		$params.Add("Cluster", $Cluster)
	}

	try {
		$response = SendCmdToLm -Command "modmap" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "SetGeoFQDNSiteAddress" -LMResponse $response -AdditionalData $SiteAddress
		if ($lma.ReturnCode -eq 200) {
			if ($lma.Data.GeoFqdnMap.Checker) {
				$lma.Data.GeoFqdnMap.Checker = $Checker
			}
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoFQDNSiteAddress, ModifyMap

Function Set-GeoFQDNSiteCheckerAddress
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	# get fqdn to verify
	$getParams = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$getParams.Add("FQDN", $FQDN)
	$lma = Get-GeoFQDN @getParams
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	if ($lma.Data.GeoFqdn.Map) {
		# OK: at least one mapping has been defined
		$foundMapping = $null
		if ($lma.Data.GeoFqdn.Map -is [array]) {
			foreach($map in $lma.Data.GeoFqdn.Map) {
				if ($map.IPAddress -eq $SiteAddress) {
					$foundMapping = $map
					break
				}
			}
		}
		else {
			if ($lma.Data.GeoFqdn.Map.IPAddress -eq $SiteAddress) {
				$foundMapping = $lma.Data.GeoFqdn.Map
			}
		}

		if ($foundMapping) {
	
			$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
			$params = ConvertBoundParameters -hashtable $psboundparameters

			switch ($foundMapping.Checker)
			{
				"none" {
					$errMsg = "ERROR: checker type is set to None"
					setKempAPIReturnObject 400 "$errMsg" $null
					return
				}
				"icmp" {
					if ($CheckerPort) {
						$params.Remove("CheckerPort")
					}
					$params.Add("port", "")	#TODO: to investigate
					break
				}
				"tcp" {
					if ($CheckerPort) {
						$params.Remove("CheckerPort")
						$params.Add("port", $CheckerPort)
					}
					break
				}
				"http" {
					if ($CheckerPort) {
						$params.Remove("CheckerPort")
						$params.Add("port", $CheckerPort)
					}
					break
				}
				"https" {
					if ($CheckerPort) {
						$params.Remove("CheckerPort")
						$params.Add("port", $CheckerPort)
					}
					break
				}
				"clust" {
					$errMsg = "ERROR: checker type is set to `'Cluster Checks`'"
					setKempAPIReturnObject 400 "$errMsg" $null
					return
				}
			}
			try {
				$response = SendCmdToLm -Command "changecheckeraddr" -ParameterValuePair $params -ConnParams $ConnParams
				$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
				if ($lma.ReturnCode -eq 200) {
					Get-GeoFQDN @getParams
					return
				}
				return $lma
			}
			catch {
				$errMsg = $_.Exception.Message
				setKempAPIReturnObject 400 "$errMsg" $null
				return
			}
		}
		else {
			$errMsg = "ERROR: the site `'$siteAddress`' does not exist"
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
	}
	$errMsg = "ERROR: no mapping found"
	setKempAPIReturnObject 400 "$errMsg" $null
	return
}
Export-ModuleMember -function Set-GeoFQDNSiteCheckerAddress, ChangeCheckerAddr

Function Set-GeoFQDNSiteMapping
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[ValidateNotNullOrEmpty()]
		[String]$SiteAddress,

		[ValidateNotNullOrEmpty()]
		[int]$SiteAddressId,

		[ValidateNotNullOrEmpty()]
		[String]$MappingIp,

		[ValidateNotNullOrEmpty()]
		[string]$MappingPort,

		[ValidateNotNullOrEmpty()]
		[String]$MappingName,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if ($SiteAddress) {
		$params.Remove("IP")
		$params.Add("fqdnip", $SiteAddress)
	}

	if ($SiteAddressId) {
		$params.Remove("SiteAddressId")
		$params.Add("fqdnipid", $SiteAddressId)
	}

	if ($MappingIp) {
		$params.Remove("MappingIp")
		$params.Add("remvip", $MappingIp)
	}

	if ($MappingPort) {
		$params.Remove("MappingPort")

		if ($MappingPort -ne '*') {
			try {
				$i_mappingPort = [convert]::ToDecimal($MappingPort)
			}
			catch {
				$errMsg = [string]$_.Exception.InnerException
				if ($errMsg.Contains("was not in a correct format")) {
					setKempAPIReturnObject 400 "The MappingPort parameter must be a number (greater than 2) or the wildcard *" $null
				}
				else {
					setKempAPIReturnObject 400 "$errMsg" $null
				}
				return
			}
			$params.Add("remport", $MappingPort)
		}
		else {
			$params.Add("remport", "2")
		}
	}

	if ($MappingName) {
		$params.Remove("MappingName")
		$params.Add("remname", $MappingName)
	}

	try {
		$response = SendCmdToLm -Command "geochangecheckermapping" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoFQDNSiteMapping

# Internal use only
Function checkGeoFqdnCountryInput($CountryCode, $CustomLocation, $IsContinent)
{
	if (!$CountryCode -and !$CustomLocation) {
		Throw "A country code or custom location must be provided."
	}

	if ($CountryCode -and !$IsContinent) {
		Throw "Please indicate if country code refers to a continent."
	}

	if (!$CountryCode -and $IsContinent) {
		Throw "IsContinent parameter requires a country code."
	}
}

Function Set-GeoFQDNSiteCountry
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	checkGeoFqdnCountryInput $CountryCode $CustomLocation $IsContinent

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addcountry" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Country/Continent updated."
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoFQDNSiteCountry, AddCountry

Function Remove-GeoFQDNSiteCountry
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	checkGeoFqdnCountryInput $CountryCode $CustomLocation $IsContinent

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "removecountry" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Country/Continent updated."
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoFQDNSiteCountry, RemoveCountry

Function Set-GeoFQDNSiteCoordinates
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "changemaploc" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Map location updated."
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoFQDNSiteCoordinates, ChangeMapLocation

Function New-GeoCustomLocation
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addcustomlocation" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoCustomLocation, AddCustomLocation

Function Remove-GeoCustomLocation
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("location")
	$params.Add("clName", $Location)

	try {
		$response = SendCmdToLm -Command "deletecustomlocation" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoCustomLocation, DeleteCustomLocation

Function Get-GeoCustomLocation
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "listcustomlocation" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoCustomLocation" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoCustomLocation, ListCustomLocation

Function Set-GeoCustomLocation
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ( ([String]::IsNullOrEmpty($clOldName)) -or ([String]::IsNullOrEmpty($clNewName)) ) {
		Throw "ERROR: clOlName and clNewName are both mandatory"
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "editcustomlocation" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoCustomLocation, EditCustomLocation

Function New-GeoIpRange
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addip" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range added"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoIpRange, AddIP

Function Remove-GeoIpRange
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delip" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range deleted"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoIpRange, DeleteIP

Function Get-GeoIpRange
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($IP) {
			$cmd = "showip"
		}
		else {
			$cmd = "listips"
		}
		$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoIpRange" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoIpRange, ListIPs, ShowIP

Function Set-GeoIPRangeCoordinates
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modiploc" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range location updated"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoIPRangeCoordinates, ModifyIPLocation

Function Remove-GeoIPRangeCoordinates
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "deliploc" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range location updated"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoIPRangeCoordinates, DeleteIPLocation

Function Set-GeoIPRangeCountry
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addipcountry" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range country updated"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoIPRangeCountry, AddIPCountry

Function Remove-GeoIPRangeCountry
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "removeipcountry" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range country updated"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoIPRangeCountry, RemoveIPCountry, RemoveIPCountryCustom, Remove-GeoIPRangeCustomLocation 

Function Set-GeoIPRangeCustomLocation
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addipcountry" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " IP range country updated"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoIPRangeCustomLocation, AddIPCountryCustom

Function Get-GeoPartnerStatus
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getgeopartnerstatus" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoPartnerStatus" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoPartnerStatus

Function Get-GeoIPBlacklistDatabaseConfiguration
{
	Get-GeoIPBlocklistDatabaseConfiguration @args -LegacyCall $true
}
Export-ModuleMember -function Get-GeoIPBlacklistDatabaseConfiguration

Function Get-GeoIPBlocklistDatabaseConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$LegacyCall = $false,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	$legacy = $params["LegacyCall"]
	$params.Remove("LegacyCall")

	try {
		$response = SendCmdToLm -Command "geoacl/getsettings" -ParameterValuePair $params -ConnParams $ConnParams
		if($legacy){
			HandleLmAnswer -Command2ExecClass "GetGeoIPBlacklistDatabaseConfiguration" -LMResponse $response
		}
		else{
			HandleLmAnswer -Command2ExecClass "GetGeoIPBlocklistDatabaseConfiguration" -LMResponse $response
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoIPBlocklistDatabaseConfiguration

Function Set-GeoIPBlacklistDatabaseConfiguration
{
	Set-GeoIPBlocklistDatabaseConfiguration @args
}
Export-ModuleMember -function Set-GeoIPBlacklistDatabaseConfiguration

Function Set-GeoIPBlocklistDatabaseConfiguration
{
	Param(
		[Parameter(ParameterSetName="Update", Mandatory=$True)]
			[switch]$DatabaseAutoUpdate,

		[Parameter(ParameterSetName="Install")]
			[switch]$DatabaseAutoInstall,

		[Parameter(ParameterSetName="Install")]
		[ValidateRange(0, 23)]
		[ValidateNotNullOrEmpty()]
		[Int32]$DatabaseInstallTimeHour,

		[ValidateNotNullOrEmpty()]
		[string]$LoadBalancer = $LoadBalancerAddress,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(3, 65530)]
		[int]$LBPort = $LBAccessPort,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.Credential()]$Credential = $script:cred,

		[ValidateNotNullOrEmpty()]
		[String]$CertificateStoreLocation = $script:CertificateStoreLocation,

		[ValidateNotNullOrEmpty()]
		[String]$SubjectCN = $script:SubjectCN
	)
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$tempParamsHt = ConvertBoundParameters -hashtable $psboundparameters
	$paramsHt = $tempParamsHt.GetEnumerator() | sort-object -Property Name
	foreach ($param in $paramsHt)
	{
		switch ($($param.Name))
		{
			"DatabaseAutoUpdate" {
				$cmd2do = "geoacl/setautoupdate"
				if($($param.Value) -eq $true) {
					$dbUpdateParam = @{"enable" = 1}
				}
				else {
					$dbUpdateParam = @{"enable" = 0}
				}
				break
			}

			"DatabaseAutoInstall" {
				$cmd2do = "geoacl/setautoinstall"
				if($($param.Value) -eq $true) {
					$dbUpdateParam = @{"enable" = 1}
				}
				else {
					$dbUpdateParam = @{"enable" = 0}
				}
				break
			}

			"DatabaseInstallTimeHour" {
				$cmd2do = "geoacl/setinstalltime"
				$dbUpdateParam = @{"hour" = $($param.Value)}
				break
			}
		}

		if ($cmd2do -eq $null) {
			continue
		}

		try {
			$response = SendCmdToLm -Command $cmd2do -ParameterValuePair $dbUpdateParam -ConnParams $ConnParams
			$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
			if ($lma.ReturnCode -ne 200) {
				return $lma
			}
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}

		$cmd2do = $null
	}
	setKempAPIReturnObject 200 "Command successfully executed." $null
}
Export-ModuleMember -function Set-GeoIPBlocklistDatabaseConfiguration

Function Update-GeoIPBlacklistDatabase
{
	Update-GeoIPBlocklistDatabase @args -LegacyCall $true
}
Export-ModuleMember -function Update-GeoIPBlacklistDatabase

Function Update-GeoIPBlocklistDatabase
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$LegacyCall = $false,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	$legacy = $params["LegacyCall"]
	$params.Remove("LegacyCall")

	try {
		$response = SendCmdToLm -Command "geoacl/updatenow" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			if($legacy){
				$lma.Response += " Download of new GEO IP Blacklist data successfully completed."
			}
			else {
				$lma.Response += " Download of new GEO IP Blocklist data successfully completed."
			}
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Update-GeoIPBlocklistDatabase

Function Install-GeoIPBlacklistDatabase
{
	Install-GeoIPBlocklistDatabase @args
}
Export-ModuleMember -function Install-GeoIPBlacklistDatabase

Function Install-GeoIPBlocklistDatabase
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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "geoacl/installnow" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-GeoIPBlocklistDatabase

Function Export-GeoIPBlacklistDatabase
{
	Export-GeoIPBlocklistDatabase @args
}
Export-ModuleMember -function Export-GeoIPBlacklistDatabase

Function Export-GeoIPBlocklistDatabase
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$filename = validatePath $filename

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("filename")

	try {
		$response = SendCmdToLm -Command "geoacl/downloadlist" -ParameterValuePair $params -File $filename -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-GeoIPBlocklistDatabase

Function Export-GeoIPBlacklistDatabaseChanges
{
	Export-GeoIPBlocklistDatabaseChanges @args
}
Export-ModuleMember -function Export-GeoIPBlacklistDatabaseChanges

Function Export-GeoIPBlocklistDatabaseChanges
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$filename = validatePath $filename

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("filename")

	try {
		$response = SendCmdToLm -Command "geoacl/downloadchanges" -ParameterValuePair $params -File $filename -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-GeoIPBlocklistDatabaseChanges

Function New-GeoIPWhitelist
{
	New-GeoIPAllowlist @args -LegacyCall $true
}
Export-ModuleMember -function New-GeoIPWhitelist

Function New-GeoIPAllowlist
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$LegacyCall = $false,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	$legacy = $params["LegacyCall"]
	$params.Remove("LegacyCall")

	try {
		$response = SendCmdToLm -Command "geoacl/addcustom" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			if($legacy) {
				$lma.Response += " $Addr was successfully added to GEO ACL white list."
			}
			else {
				$lma.Response += " $Addr was successfully added to GEO ACL allow list."
			}
			
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoIPAllowlist

Function Get-GeoIPWhitelist
{
	Get-GeoIPAllowlist @args -LegacyCall $true
}
Export-ModuleMember -function Get-GeoIPWhitelist

Function Get-GeoIPAllowlist
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$LegacyCall = $false,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	$legacy = $params["LegacyCall"]
	$params.Remove("LegacyCall")

	try {
		$response = SendCmdToLm -Command "geoacl/listcustom" -ParameterValuePair $params -ConnParams $ConnParams
		if($legacy) {
			HandleLmAnswer -Command2ExecClass "GetGeoIPWhitelist" -LMResponse $response
		}
		else {
			HandleLmAnswer -Command2ExecClass "GetGeoIPAllowlist" -LMResponse $response
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoIPAllowlist

Function Remove-GeoIPWhitelist
{
	Remove-GeoIPAllowlist @args -LegacyCall $true
}
Export-ModuleMember -function Remove-GeoIPWhitelist

Function Remove-GeoIPAllowlist
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$LegacyCall = $false,

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

	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	$legacy = $params["LegacyCall"]
	$params.Remove("LegacyCall")

	try {
		$response = SendCmdToLm -Command "geoacl/removecustom" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response

		if ($lma.ReturnCode -eq 200) {
			if ($legacy){
				$lma.Response += " $Addr was successfully removed from GEO ACL white list."
			}
			else {
				$lma.Response += " $Addr was successfully removed from GEO ACL allow list."
			}
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoIPAllowlist

Function Export-GeoIPWhitelistDatabase
{
	Export-GeoIPAllowlistDatabase @args -LegacyCall $true
}
Export-ModuleMember -function Export-GeoIPWhitelistDatabase

Function Export-GeoIPAllowlistDatabase
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[bool]$LegacyCall = $false,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$filename = validatePath $filename

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("filename")
	$legacy = $params["LegacyCall"]
	$params.Remove("LegacyCall")

	try {
		$response = SendCmdToLm -Command "geoacl/listcustom" -ParameterValuePair $params -ConnParams $ConnParams
		$addDataHt = [ordered]@{"filename" = $filename; "force" = $Force}

		if($legacy) {
		HandleLmAnswer -Command2ExecClass "ExportGeoIPWhitelistDatabase" -LMResponse $response -AdditionalData $addDataHt
		}
		else {
			HandleLmAnswer -Command2ExecClass "ExportGeoIPAllowlistDatabase" -LMResponse $response -AdditionalData $addDataHt
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		if ($errMsg.Contains(" already exists.")) {
			$errMsg = "ERROR: The specified file already exists. To use the same filename, either delete the file or use the -Force switch"
		}
		Write-Verbose "errMsg: $errMsg"
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-GeoIPAllowlistDatabase

Function Set-GeoDNSSECStatus
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("enabled", "disabled")]
		[string]$status,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{}
	if ($status -eq "enabled") {
		$params.Add("Enable", 1)
	}
	elseif ($status -eq "disabled") {
		$params.Add("Enable", 0)
	}
	else {
		Throw "ERROR: not allowed value for parameter status"
	}

	try {
		$response = SendCmdToLm -Command "geosetdnssec" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoDNSSECStatus

Function New-GeoDNSSECKeySigningKey
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateSet("RSASHA256", "RSASHA512", "NSEC3RSASHA1")]
		[String]$SigningAlgorithm,

		[ValidateSet("1024", "2048", "4096")]
		[int]$SigningKeySize,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{}

	if ($SigningAlgorithm) {
		$params.Remove("SigningAlgorithm")
		$params.Add("algorithm", $SigningAlgorithm)
	}

	if ($SigningKeySize) {
		$params.Remove("SigningKeySize")
		$params.Add("keysize", $SigningKeySize)
	}

	try {
		$response = SendCmdToLm -Command "geogenerateksk" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoDNSSECKeySigningKey

Function Import-GeoDNSSECKeySigningKey
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$privateKeyFile,

		[Parameter(Mandatory=$true)]
		[string]$publicKeyFile,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	validateFile2Upload $privateKeyFile $null
	validateFile2Upload $publicKeyFile $null

	try {
		if ( ([String]::IsNullOrEmpty($LBPort)) ) {
			$LBPort = 443
		}
		$url = "https://$LoadBalancer`:$LBPort/access/geoimportksk"
		Write-Verbose "url: $url"
		$response = uploadGeoDnssecKeyFiles $url $privateKeyFile $publicKeyFile $Credential $SubjectCN $CertificateStoreLocation
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$rc = 400
		$errMsg = $_.Exception.Message
		if ($errMsg -and $errMsg.Contains("Unauthorized")) {
			$rc = 401
		}
		setKempAPIReturnObject $rc "$errMsg" $null
	}
}
Export-ModuleMember -function Import-GeoDNSSECKeySigningKey

Function Remove-GeoDNSSECKeySigningKey
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "geodeleteksk" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoDNSSECKeySigningKey

Function Get-GeoDNSSECConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "geoshowdnssec" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoDNSSECConfiguration" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoDNSSECConfiguration

Function Get-GeoMiscParameter
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "listparams" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoLmMiscParameter" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoMiscParameter, ListMiscParameters

Function Set-GeoMiscParameter
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[String]$SourceOfAuthority,

		[String]$NameSrv,

		[String]$SOAEmail,

		[bool]$PerZoneSOA,

		[bool]$DClustUnavail,

		[String]$GlueIP,

		[String]$TXT,

		[ValidateRange(1, 86400)]
		[int]$TTL,

		[ValidateRange(0, 86400)]
		[int]$Persist,

		[ValidateRange(9, 3600)]
		[int]$CheckInterval,

		[ValidateRange(4, 60)]
		[int]$ConnTimeout,

		[ValidateRange(2, 10)]
		[int]$RetryAttempts,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modparams" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoLmMiscParameter" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoMiscParameter, ModifyMiscParameters

Function Update-GeoDatabase
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "locdataupdate" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Update-GeoDatabase, LocationDataUpdate

Function Enable-LmGeoPack
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "enablegeo" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Enable-LmGeoPack, EnableGEO

Function Disable-LmGeoPack
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "disablegeo" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Disable-LmGeoPack, DisableGEO

Function Test-LmGeoEnabled
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "isgeoenabled" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "TestLmGeoEnabled" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Test-LmGeoEnabled, IsGEOEnabled

Function Get-GeoStatistics
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "geostats" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGeoStats" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GeoStatistics

Function New-GeoFQDNResourceRecord
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Type,

		[ValidateNotNullOrEmpty()]
		[String]$RData,

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


	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if($type -ieq "TXT" -Or $type -ieq "MX"){
		if(!$RData){
			$Rdata = Read-Host -Prompt "RData"
			$params.Add("RData", $RData)
		}
	}
	elseif($type -ieq "CNAME"){
		if(!$Name){
			$Name = Read-Host -Prompt "Name"
			$params.Add("Name", $Name)
		}
	}

	try {
		$response = SendCmdToLm -Command "addrr" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Added record FQDN $FQDN"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GeoFQDNResourceRecord

Function Set-GeoFQDNResourceRecord
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Type,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int]$ID,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Param,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modrr" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Updated record FQDN $FQDN $ID"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-GeoFQDNResourceRecord

Function Remove-GeoFQDNResourceRecord
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FQDN,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Int]$ID,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delrr" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			$lma.Response += " Deleted record FQDN $FQDN $ID"
		}
		$lma
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GeoFQDNResourceRecord

# ==================================================
# endregion GEO
# ==================================================


# ==================================================
# region LDAP
# ==================================================

Function Get-LdapEndpoint
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($Name) {
			$cmd = "showldapendpoint"
			$list = $false
		}
		else {
			$cmd = "showldaplist"
			$list = $true
		}
		$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLdapEndpoint" -LMResponse $response -AdditionalData $list
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LdapEndpoint

# Internal use only
Function mapLdapProtocol($ldapParams, $LdapProtocol)
{
	if ($LdapProtocol) {
		if ($ldapParams.ContainsKey("LdapProtocol")) {
			$ldapParams.Remove("LdapProtocol")
		}
		$value = 0
		switch ($LdapProtocol)
		{
			"Unencrypted" {
				$value = 0
				break
			}
			"StartTLS" {
				$value = 1
				break
			}
			"LDAPS" {
				$value = 2
				break
			}
		}
		$ldapParams.Add("ldaptype", $value)
	}
}

Function New-LdapEndpoint
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[String]$Server,

		[ValidateSet("Unencrypted", "StartTLS", "LDAPS")]
		[string]$LdapProtocol,

		[ValidateRange(10, 86400)]
		[Int16]$VInterval = 60,

		[ValidateRange(0, 10)]
		[Int16]$ReferralCount = 0,

		[Int16]$Timeout,

		[String]$AdminUser,

		[String]$AdminPass,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	mapLdapProtocol $params $LdapProtocol

	try {
		$response = SendCmdToLm -Command "addldapendpoint" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-LdapEndpoint

Function Set-LdapEndpoint
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[String]$Server,

		[ValidateSet("Unencrypted", "StartTLS", "LDAPS")]
		[string]$LdapProtocol,

		[ValidateRange(10, 86400)]
		[Int16]$VInterval = 60,

		[ValidateRange(0, 10)]
		[Int16]$ReferralCount = 0,

		[Int16]$Timeout,

		[String]$AdminUser,

		[String]$AdminPass,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	mapLdapProtocol $params $LdapProtocol

	try {
		$response = SendCmdToLm -Command "modifyldapendpoint" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LdapEndpoint

Function Remove-LdapEndpoint
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "deleteldapendpoint" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LdapEndpoint

# ==================================================
# endregion LDAP
# ==================================================


# ==================================================
# region BACKUP
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Backup-LmConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (-not ($Path)) {
		$Path = "$($Env:SystemRoot)\Temp\LMBackup_$(Get-Date -format yyyy-MM-dd_HH-mm-ss)"
	}
	Write-Verbose "Path = $Path"

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "backup" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Backup-LmConfiguration, Backup-LoadBalancer

# Internal use only
Function getRestoreBackupTypeInt($BackupStringType)
{
	switch ($BackupStringType) {
		"Base" { $type = 1 }
		"Base + VS" { $type = 3 }
		"Base + Geo" { $type = 5 }
		"VS" { $type = 2 }
		"VS + Geo" { $type = 6 }
		"Geo" { $type = 4 }
		"SSO/LDAP" { $type = 8 }
		"All" { $type = 7 }
	}
	return $type
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Restore-LmConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{}

	$TypeInt = getRestoreBackupTypeInt $Type

	$params.Add("Type", $TypeInt)

	try {
		$response = SendCmdToLm -Command "restore" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Restore-LmConfiguration, Restore-LoadBalancer

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmBackupConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$bckParams = @("backupenable", "backuphour", "backupminute", "backupday", "backupsecure",
	               "backupmethod", "backupuser", "backuppassword", "backuphost", "backuppath")

	$bckSettings = [ordered]@{}
	$bckSettings.PSTypeName = "BackupConfiguration"
	foreach ($param in $bckParams) {
		$lma = GetLmParameter "$param" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$paramValue = $lma.Data.$param
		if ($paramValue -eq "wput") {
			$paramValue = "ftp"
		}
		$bckSettings.Add($param, $paramValue)

		Start-Sleep -m 200
	}
	$data = New-Object -TypeName PSObject -Property $bckSettings

	$bckConfiguration = [ordered]@{}
	$bckConfiguration.PSTypeName = "BackupConfiguration"
	$bckConfiguration.add("BackupConfiguration", $data)
	$bckObject = New-Object -TypeName PSObject -Property $bckConfiguration

	setKempAPIReturnObject 200 "Command successfully executed" $bckObject
}
Export-ModuleMember -function Get-LmBackupConfiguration, Get-BackupOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LmBackupConfiguration
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

		[ValidateSet("ftp", "sftp", "scp")]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params.Add("param", "backupenable")
	$response = Get-LmParameter @params
	if ($response.ReturnCode -ne 200) {
		return $response
	}
	$params.Remove("param")

	if ($BackupMethod) {
		if ($BackupMethod -eq "ftp") {
			$BackupMethod_ = "wput"
		}
		else {
			$BackupMethod_ = $BackupMethod
		}
	}

	$params2Get = @("backupenable")
	if ($response.Data.backupenable -eq "yes") {
		if ($BackupEnable -and $BackupEnable -eq "no") {
			# OK: set only the backupenable
			$params.Add("param", "backupenable")
			$params.Add("value", $BackupEnable)
			$lma = Set-LmParameter @params
			if ($lma.ReturnCode -ne 200) {
				return $lma
			}
			$params.Remove("param")
			$params.Remove("value")
		}
		else {
			# OK: set all the parametes
			$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding
			$parameters2set.Remove("backupenable")
			if ($BackupMethod_) {
				$parameters2set.Remove("backupmethod")
				$parameters2set.Add("backupmethod", $BackupMethod_)
			}
			$lma = SetParameterSet $parameters2set $params ([ref]$params2Get)
			if ($lma.ReturnCode -ne 200) {
				return $lma
			}
		}
	}
	else {
		if ($BackupEnable -and $BackupEnable -eq "yes") {
			# OK: set all the parametes
			$params.Add("param", "backupenable")
			$params.Add("value", $BackupEnable)
			$response = Set-LmParameter @params
			if ($response.ReturnCode -ne 200) {
				return $response
			}
			$params.Remove("param")
			$params.Remove("value")

			$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding
			$parameters2set.Remove("backupenable")
			if ($BackupMethod_) {
				$parameters2set.Remove("backupmethod")
				$parameters2set.Add("backupmethod", $BackupMethod_)
			}
			$lma = SetParameterSet $parameters2set $params ([ref]$params2Get)
			if ($lma.ReturnCode -ne 200) {
				return $lma
			}
		}
		else {
			# ERROR: cannot set the parametes
			setKempAPIReturnObject 400 "ERROR: cannot set backup parameter(s) when backup is disabled" $null
			return
		}
	}
  $response = GetLmParameterSet $params2Get "Parameters" $params
  if ($response.ReturnCode -eq 200) {
    if ($response.Data.Parameters.backupmethod) {
      if ($response.Data.Parameters.backupmethod -eq "wput") {
        $response.Data.Parameters.backupmethod = "ftp"
      }
    }
  }
  $response
}
Export-ModuleMember -function Set-LmBackupConfiguration, Set-BackupOption

Function Set-LmBackupSecureIdentity
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = @{}

	$currFolder = Split-Path -Path $Path
	if (-not (Test-Path -Path $currFolder)) {
		Throw "ERROR: the folder $currFolder does not exist"
	}
	$currFolder = Convert-Path $currFolder

	$fileToUpload = $currFolder + "\IdentityFile.txt"
	$tmpFile = $currFolder + "\IdentityFile_temp.txt"

	if (Test-Path -Path $fileToUpload) {
		Remove-Item $fileToUpload
	}

	if (Test-Path -Path $tmpFile) {
		Remove-Item $tmpFile
	}

	try {
		$privKeyFileContent = Get-Content -Raw $Path
		$privKeyFileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($privKeyFileContent)
		$privKeyFileContentEncoded = [System.Convert]::ToBase64String($privKeyFileContentBytes)
		$secureString = "param=backupident&value=" + $privKeyFileContentEncoded
		Set-Content -Value $secureString -Path $tmpFile 
		$txt = (Get-Content -Raw $tmpFile) -replace "`r`n",""
		[io.file]::WriteAllText($fileToUpload, $txt)
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}

	try {
		$response = SendCmdToLm -Command "set" -ParameterValuePair $params -File $fileToUpload -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}

	if (-not ($PSBoundParameters['Debug'])) {
		Remove-Item $tmpFile
		Remove-Item $fileToUpload
	}

	$lma
}
Export-ModuleMember -function Set-LmBackupSecureIdentity

# ==================================================
# endregion BACKUP
# ==================================================


# ==================================================
# region VPN
# ==================================================

Function New-LmVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams2 = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "createvpncon" -ParameterValuePair $params -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "NewLmVpnConnection" -LMResponse $response
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$ConnParams2.Add("Name", $Name)
		Get-LmVpnConnection @ConnParams2
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-LmVpnConnection, CreateVpnConnection

Function Remove-LmVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "deletevpncon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LmVpnConnection, DeleteVpnConnection

Function Get-LmVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($Name) {
			$cmd = "getvpnstatus"
		}
		else {
			$cmd = "listvpns"
		}
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmVpnConnection, ListVpns

Function Set-LmVpnAddrs
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnaddr" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnAddrs, SetVpnAddrs

Function Set-LmVpnLocalIp
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnlocalip" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnLocalIp, SetVpnLocalIp

Function Set-LmVpnLocalSubnet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnlocalsubnets" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnLocalSubnet, SetVpnLocalSubnets

Function Set-LmVpnRemoteIp
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnremoteip" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnRemoteIp, SetVpnRemoteIp

Function Set-LmVpnRemoteSubnet
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnremotesubnets" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnRemoteSubnet, SetVpnRemoteSubnets

Function Set-LmVpnSecret
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnsecret" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnSecret, SetVpnSecret

Function Start-LmVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "startvpncon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Start-LmVpnConnection, StartVpnConnection

Function Stop-LmVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "stopvpncon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Stop-LmVpnConnection, StopVpnConnection

Function Start-LmVpnIkeDaemon
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "startikedaemon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Start-LmVpnIkeDaemon, StartIkeDaemon

Function Stop-LmVpnIkeDaemon
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "stopikedaemon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Stop-LmVpnIkeDaemon, StopIkeDaemon

Function Get-LmVpnIkeDaemonStatus
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "statusikedaemon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmVpnIkeDaemonStatus" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmVpnIkeDaemonStatus, StatusIkeDaemon

Function Set-LmVpnPfsEnable
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnpfsenable" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnPfsEnable, SetVpnPfsEnable

Function Set-LmVpnPfsDisable
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "setvpnpfsdisable" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmVpnPfsDisable, SetVpnPfsDisable

# ==================================================
# endregion VPN
# ==================================================


# ==================================================
# region SAML
# ==================================================

# Internal use only
Function checkOutputFile($strFileName = "strFileName is mandatory, please provide a value.")
{
	if (([String]::IsNullOrEmpty($strFileName))) {
		return $false
	}

	if ($strFileName -eq "strFileName is mandatory, please provide a value.") {
		return $false
	}

	$parent = Split-Path -Path $strFileName -Parent
	if (([String]::IsNullOrEmpty($parent))) {
		return $false
	}

	if (Test-Path $parent) {
		# File exists
		return $true
	}
	else {
		# File does not exist
		return $false
	}
}

# Internal use only
Function SetSAMLSPEntityParameter($params, $IdpEntityId, $IdpSsoUrl, $IdpLogoffUrl, $IdpCert, $SpEntityId, $SpCert, $idp_match_cert)
{
	$count = 0
	if (-not ([String]::IsNullOrEmpty($IdpEntityId))) {
		$params.Add("idp_entity_id", $IdpEntityId)
		$count += 1
	}
	if (-not ([String]::IsNullOrEmpty($IdpSsoUrl))) {
		$params.Add("idp_sso_url", $IdpSsoUrl)
		$count += 1
	}
	if (-not ([String]::IsNullOrEmpty($IdpLogoffUrl))) {
		$params.Add("idp_logoff_url", $IdpLogoffUrl)
		$count += 1
	}
	if (-not ([String]::IsNullOrEmpty($IdpCert))) {
		$params.Add("idp_cert", $IdpCert)
		$count += 1
	}
	if (-not ([String]::IsNullOrEmpty($SpEntityId))) {
		$params.Add("sp_entity_id", $SpEntityId)
		$count += 1
	}
	if (-not ([String]::IsNullOrEmpty($SpCert))) {
		$params.Add("sp_cert", $SpCert)
		$count += 1
	}
	if ($idp_match_cert -eq 0 -or $idp_match_cert -eq 1) {
		$count += 1
	}
	return $count
}

Function Install-SAMLIdpMetafile
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Domain,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$getParams = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$getParams.Add("domain", $Domain)
	$lma = Get-SSODomain @getParams
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	if ($lma.Data.Domain.auth_type -ne "SAML") {
		$errMsg = "The supplied Domain `"$Domain`" authentication protocol is not SAML: auth_type: $($lma.Data.Domain.auth_type)"
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "uploadsamlidpmd" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
		if ($lma.ReturnCode -eq 200) {
			# Get SAML domain
			Get-SSODomain @getParams
		}
		else {
			return $lma
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-SAMLIdpMetafile

Function Set-SAMLSPEntity
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Domain,

		[ValidateNotNullOrEmpty()]
		[string]$IdpEntityId,

		[ValidateNotNullOrEmpty()]
		[string]$IdpSsoUrl,

		[ValidateNotNullOrEmpty()]
		[string]$IdpLogoffUrl,

		[ValidateNotNullOrEmpty()]
		[string]$IdpCert,

		[ValidateNotNullOrEmpty()]
		[string]$SpEntityId,

		[ValidateNotNullOrEmpty()]
		[string]$SpCert,

		[ValidateRange(0, 1)]
		[int]$idp_match_cert,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$getParams = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$getParams.Add("domain", $Domain)
	$lma = Get-SSODomain @getParams
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	if ($lma.Data.Domain.auth_type -ne "SAML") {
		$errMsg = "The supplied Domain `"$Domain`" authentication protocol is not SAML: auth_type: $($lma.Data.Domain.auth_type)"
		setKempAPIReturnObject 400 "$errMsg" $null
		return
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	$count = SetSAMLSPEntityParameter $params $IdpEntityId $IdpSsoUrl $IdpLogoffUrl $IdpCert $SpEntityId $SpCert $idp_match_cert
	if ($count -eq 0) {
		setKempAPIReturnObject 401 "ERROR: you need to set at least one parameter other than Domain" $null
	}

	try {
		$response = SendCmdToLm -Command "moddomain" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetSSOSamlDomain" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SAMLSPEntity

Function Get-SAMLDomain
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[string]$Domain,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "showdomain" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
		if ($Domain) {
			$lma = HandleLmAnswer -Command2ExecClass "GetSSOSamlDomain" -LMResponse $response

			if ($lma.ReturnCode -ne 200) {
				return $lma
			}

			if ($lma.Data.Domain.auth_type -ne "SAML") {
				$errMsg = "The supplied Domain `"$Domain`" authentication protocol is not SAML: auth_type: $($lma.Data.SamlDomain.auth_type)"
				setKempAPIReturnObject 400 $errMsg $null
				return
			}
			return $lma
		}
		else {
			$lma = HandleLmAnswer -Command2ExecClass "GetSSODomain" -LMResponse $response
			$domains = $lma.Data.Domain
			if ($domains) {
				$samlDomains = @()
				foreach ($singleDomain in $domains) {
					if ($singleDomain.auth_type -eq "SAML") {
						$samlDomains += $singleDomain
					}
				}
				$ht = [ordered]@{}
				$ht.PSTypeName = "SSODomain"
				$ht.add("Domain", $samlDomains)
				$samlDomainsObject = New-Object -TypeName PSObject -Property $ht
				setKempAPIReturnObject 200 "Command successfully executed." $samlDomainsObject
			}
		}
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-SAMLDomain

Function Export-SAMLSPCert
{
	[cmdletbinding(SupportsShouldProcess=$true, DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$Domain,

		[Parameter(Mandatory=$true)]
		[string]$CertificateFilePath,

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

	PROCESS
 	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$getParams = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$getParams.Add("domain", $Domain)
		$lma = Get-SSODomain @getParams
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}

		if ($lma.Data.Domain.auth_type -ne "SAML") {
			$errMsg = "The supplied Domain `"$Domain`" authentication protocol is not SAML: auth_type: $($lma.Data.Domain.auth_type)"
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}

		$fileCheck = checkOutputFile $CertificateFilePath
		if ($fileCheck -eq $false) {
			setKempAPIReturnObject 401 "The destination folder does not exist." $null
			return
		}

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = ConvertBoundParameters -hashtable $psboundparameters

		if (($Force) -or $PsCmdlet.ShouldProcess($CertificateFilePath, "Overwrite")) {

			try {
				$response = SendCmdToLm -Command "downloadsamlspcert" -ParameterValuePair $params -File $CertificateFilePath -Output -ConnParams $ConnParams
				HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
			}
			catch {
				$errMsg = $_.Exception.Message
				setKempAPIReturnObject 400 "$errMsg" $null
			}

		}
	}
}
Export-ModuleMember -function Export-SAMLSPCert

# ==================================================
# endregion SAML
# ==================================================


# ==================================================
# region ADDON
# ==================================================

Function Install-LmAddon
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addaddon" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "InstallLmAddon" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-LmAddon, UploadAddon

Function Remove-LmAddon
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "deladdon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LmAddon, DeleteAddon

Function Get-LmAddOn
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "listaddon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmAddOn" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmAddOn, ListAddons

# ==================================================
# endregion ADDON
# ==================================================


# ==================================================
# region PATCH
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Install-LmPatch
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "installpatch" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "InstallLmPatch" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Install-LmPatch, Install-Patch

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Uninstall-LmPatch
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "restorepatch" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "UninstallLmPatch" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Uninstall-LmPatch, Restore-Patch

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Restart-Lm
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

	PROCESS
 	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$params = ConvertBoundParameters -hashtable $psboundparameters

		$cmd = $null
		if ($Shutdown) {
			$cmd = "shutdown"
		}
		else {
			$cmd = "reboot"
		}

		if (($Force) -or ($PsCmdlet.ShouldProcess($cmd, "$cmd on $LoadBalancer"))) {

			try {
				$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
				$lma = HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
				if ($lma.ReturnCode -ne 200) {
					return $lma
				}
				if ($cmd -eq "reboot") {
					if ( ([String]::IsNullOrEmpty($SleepTime)) ) {
						$SleepTime = 12
					}
					if ( ([String]::IsNullOrEmpty($Cycles)) ) {
						$Cycles = 8
					}
					Start-Sleep -s 10
					$check = reconnectToLm $LoadBalancer $LBPort $Cycles $SleepTime
					if ($check) {
						# the LM is back
						return $lma
					}
					else {
						# the LM is not back in time
						setKempAPIReturnObject 400 "the LM is not back yet" $null
						return
					}
				}
				else {
					# SHUTDOWN case
					return $lma
				}
			}
			catch {
				$errMsg = $_.Exception.Message
				setKempAPIReturnObject 400 "$errMsg" $null
			}
		}
	}
}
Export-ModuleMember -function Restart-Lm, Restart-LoadBalancer

Function Get-LmPreviousFirmwareVersion
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getpreviousversion" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmPreviousFirmwareVersion" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmPreviousFirmwareVersion

# ==================================================
# endregion PATCH
# ==================================================


# ==================================================
# region DATE-TIME
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmDateTimeConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	# Don't get NTPKeySecret - no valid data is returned
	$params2get = @("NTPHost", "NTPKeyType", "NTPKeyId", "Time", "ActiveTime", "BootTime", "TimeZone")

	$ht = [ordered]@{}
	$ht.PSTypeName = "DateTimeConfiguration"
	foreach($param in $params2get) {
		$params.Add("param", $param)

		$lma = Get-LmParameter @params
		if ($lma.ReturnCode -eq 200) {
			$paramValue = $lma.Data.$param
			if ($param -eq "NTPKeyType" -and $paramValue -eq "M") {
				$paramValue = "MD5"
			}
			if ($param -eq "NTPKeyType" -and $paramValue -eq "SHA") {
				$paramValue = "SHA-1"
			}
			$ht.Add($param, $paramValue)
		}
		else {
			return $lma
		}
		$params.Remove("param")
		Start-Sleep -m 200
	}
	$tmpObj = New-Object -TypeName PSObject -Property $ht

	$emConf = [ordered]@{}
	$emConf.PSTypeName = "DateTimeConfiguration"
	$emConf.Add("DateTimeConfiguration", $tmpObj)
	$emConfObject = New-Object -TypeName PSObject -Property $emConf

	setKempAPIReturnObject 200 "Command successfully executed" $emConfObject
}
Export-ModuleMember -function Get-LmDateTimeConfiguration, Get-DateTimeOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LmDateTimeConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if ($NTPKeyType -and $NTPKeyType -eq "MD5") {
		$parameters2set["NTPKeyType"] = "M"
	}

	if ($NTPKeyType -and $NTPKeyType -eq "SHA-1") {
		$parameters2set["NTPKeyType"] = "SHA"
	}

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	$lma = GetLmParameterSet $params2Get "Parameters" $params
	if ($lma.ReturnCode -eq 200) {
		if ($lma.Data.Parameters.NTPKeyType) {
			if ($lma.Data.Parameters.NTPKeyType -eq "M") {
				$lma.Data.Parameters.NTPKeyType = "MD5"
			}
			else {
				$lma.Data.Parameters.NTPKeyType = "SHA-1"
			}
		}
	}
	$lma
}
Export-ModuleMember -function Set-LmDateTimeConfiguration, Set-DateTimeOption

Function Get-LmWuiSetting
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$parameters = @("hoverhelp", "motd", "wuidisplaylines")
 	<#
	NOTE: missing parameters
	 - eula
	 - EnableHistoricalGraphs
	 - Collect All Statistics
	#>

	GetLmParameterSet $parameters "WuiSetting" $params
}
Export-ModuleMember -function Get-LmWuiSetting

Function Set-LmWuiSetting
{
  [cmdletbinding(DefaultParameterSetName='Credential')]
  Param(
		[bool]$hoverhelp,

    [string]$motd,

    [ValidateRange(10, 100)]
    [int]$wuidisplaylines,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	GetLmParameterSet $params2Get "Parameters" $params
}
Export-ModuleMember -function Set-LmWuiSetting

# ==================================================
# endregion DATE-TIME
# ==================================================


# ==================================================
# region SDN
# ==================================================

Function New-SdnController
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "addsdncontroller" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "AddSdnController" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-SdnController, AddSDNController

Function Remove-SdnController
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "delsdncontroller" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "RemoveSdnController" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-SdnController, DeleteSDNController

Function Set-SdnController
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "modsdncontroller" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "SetSdnController" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-SdnController, ModifySDNController

Function Get-SdnController
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getsdncontroller" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetSdnController" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-SdnController, GetSDNController

# ==================================================
# endregion SDN
# ==================================================

# ==================================================
# region Exporter
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-Telemetry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Alias("Interface")]
		[ValidateNotNullOrEmpty()]
		[int]$Iface,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "showtelemetry" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetNetworkInterface" -LMResponse $response -AdditionalData $Type
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-Telemetry

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Enable-Telemetry
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Alias("Interface")]
		[ValidateNotNullOrEmpty()]
		[int]$Iface,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[bool]$Enable,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	try {
		$response = SendCmdToLm -Command "enabletelemetry" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetNetworkInterface" -LMResponse $response -AdditionalData $Type
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Enable-Telemetry

# ==================================================
# endregion Exporter
# ==================================================

# ==================================================
# region FILTER
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-VSPacketFilterACL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$VirtualService,

		[string]$VSPort,

		[ValidateSet("tcp", "udp")]
		[string]$VSProtocol,

		[Int32]$VSIndex = -1,

		[Parameter(Mandatory=$true)]
		[ValidateSet("black", "white", "allow", "block")]
		[String]$Type,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{
		"listvs" = $Type
	}

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	if ($cmdCase -eq "IPAddress") {
		$params.Add("vs", $VirtualService)
		$params.Add("port", $VSPort)
		$params.Add("prot", $VSProtocol)
	}
	else {
		$params.Add("vs", $VSIndex)
	}

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVSPacketFilterACL" -LMResponse $response -AdditionalData $Type
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-VSPacketFilterACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-VSPacketFilterACL
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
		[ValidateSet("black", "white", "allow", "block")]
		[String]$Type,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$AclAddress,

		[String]$AclComment,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{
		"addvs" = $Type
		"addr" = $AclAddress
	}

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	if ($cmdCase -eq "IPAddress") {
		$params.Add("vs", $VirtualService)
		$params.Add("port", $VSPort)
		$params.Add("prot", $VSProtocol)
	}
	else {
		$params.Add("vs", $VSIndex)
	}

	if ($AclComment) {
		$params.Add("comment", [System.Uri]::EscapeDataString($AclComment))
	}

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewVSPacketFilterACL" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-VSPacketFilterACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-VSPacketFilterACL
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
		[ValidateSet("black", "white", "allow", "block")]
		[String]$Type,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$AclAddress,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = [ordered]@{
		"delvs" = $Type
		"addr" = $AclAddress
	}

	$cmdCase = checkAdcVSInputParams $VirtualService $VSPort $VSProtocol $VSIndex 1

	if ($cmdCase -eq "IPAddress") {
		$params.Add("vs", $VirtualService)
		$params.Add("port", $VSPort)
		$params.Add("prot", $VSProtocol)
	}
	else {
		$params.Add("vs", $VSIndex)
	}

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "RemoveVSPacketFilterACL" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-VSPacketFilterACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-PacketFilterOptionACL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
			<#
		[Parameter(Mandatory=$true)]
		[ValidateSet("enable", "drop", "ifblock")]
		[String]$Option,
			#>

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$parameters = @("isenabled", "isdrop", "isifblock", "iswuiblock", "wuiaddr")

	$ht = [ordered]@{}
	$ht.PSTypeName = "PacketFilterOption"
	$skip_wuiaddr = $false
	foreach ($param in $parameters)
	{
		if ($param -eq "wuiaddr" -AND $skip_wuiaddr -eq $true) {
			continue
		}
		try {
			$response = SendCmdToLm -Command "aclcontrol/$param" -ParameterName $null -ConnParams $ConnParams
			$lma = HandleLmAnswer -Command2ExecClass "GetPacketFilterOption" -LMResponse $response -AdditionalData $param
			if ($lma.ReturnCode -eq 200) {
				$ht.add($lma.Data.PSObject.Properties.Name, $lma.Data.PSObject.Properties.Value)
				if ($lma.Data.PSObject.Properties.Name -eq "aclwuiblock" -AND $lma.Data.PSObject.Properties.Value -eq "no") {
					$skip_wuiaddr = $true
				}
			}
			else {
				return $lma
			}
		}
		catch {
			$errMsg = $_.Exception.Message
			setKempAPIReturnObject 400 "$errMsg" $null
			return
		}
	}
	$pfoObject = New-Object -TypeName PSObject -Property $ht

	$pfHt = [ordered]@{}
	$pfHt.PSTypeName = "PacketFilterConfiguration"
	$pfHt.Add("PacketFilterConfiguration", $pfoObject)
	$pfcObject = New-Object -TypeName PSObject -Property $pfHt

	setKempAPIReturnObject $lma.ReturnCode $lma.Response $pfcObject
}
Export-ModuleMember -function Get-PacketFilterOptionACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-PacketFilterOptionACL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("enable", "drop", "ifblock", "wuiblock")]
		[String]$Option,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[bool]$Value,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$param = [ordered]@{}
	$param.Add($Option, $Value -as [int])

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $param -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-PacketFilterOptionACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-GlobalPacketFilterACL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("black", "white", "allow", "block")]
		[String]$Type,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$param = [ordered]@{"list" = $Type}

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $param -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetGlobalPacketFilterACL" -LMResponse $response -AdditionalData $Type
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-GlobalPacketFilterACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-GlobalPacketFilterACL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("black", "white", "allow", "block")]
		[String]$Type,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,

		[String]$Comment,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{
		"add" = $Type
		"addr" = $Address
	}
	if ($Comment) {
		$params.Add("comment", [System.Uri]::EscapeDataString($Comment))
	}

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewGlobalPacketFilterACL" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-GlobalPacketFilterACL

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-GlobalPacketFilterACL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("black", "white", "allow", "block")]
		[String]$Type,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = [ordered]@{
		"del" = $Type
		"addr" = $Address
	}

	try {
		$response = SendCmdToLm -Command "aclcontrol" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-GlobalPacketFilterACL

# ==================================================
# endregion FILTER
# ==================================================


# ==================================================
# region AFE
# ==================================================

# Internal use only
Function getIntrusionDetectionLevelString($paranoiaLevel)
{
	switch ($paranoiaLevel)
	{
		0 {
			$plString = "Low"
			break
		}

		1 {
			$plString = "Default"
			break
		}

		2 {
			$plString = "High"
			break
		}

		3 {
			$plString = "Paranoid"
			break
		}
	}
	return $plString
}

# Internal use only
Function getIntrusionDetectionLevel($IDLString)
{
	switch ($IDLString)
	{
		"Low" {
			$level = 0
			break
		}

		"Default" {
			$level = 1
			break
		}

		"High" {
			$level = 2
			break
		}

		"Paranoid" {
			$level = 3
			break
		}
	}
	return $level
}

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmAFEConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	# NOTE Missing params:
	#      extensions not cached
	#      extensions not compressed
	$parameters = @("Cachesize", "HostCache", "Paranoia", "LimitInput")

	$lma = GetLmParameterSet $parameters "LmAFEConfiguration" $params
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	$lma.Data.LmAFEConfiguration.Paranoia = getIntrusionDetectionLevelString $lma.Data.LmAFEConfiguration.Paranoia
	renameCustomObjectProperty $lma.Data.LmAFEConfiguration "Paranoia" "DetectionLevel"
	$lma
}
Export-ModuleMember -function Get-LmAFEConfiguration, Get-AFEConfiguration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LmAFEConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateRange(1, 409)]
		[Int]$CacheSize,

		[bool]$HostCache,

		[ValidateSet("Low", "Default", "High", "Paranoid")]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding
	if ($DetectionLevel) {
		$paranoiaLevel = getIntrusionDetectionLevel $DetectionLevel
		$parameters2set.Remove("DetectionLevel")
		$parameters2set.Add("paranoia", $paranoiaLevel)
	}

	if ($parameters2set.Count -eq 0) {
		setKempAPIReturnObject 200 "Command successfully executed." $null
		return
	}

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	$lma = GetLmParameterSet $params2Get "Parameters" $params
	if ($lma.Data.Parameters.Paranoia) {
		$lma.Data.Parameters.Paranoia = getIntrusionDetectionLevelString $lma.Data.Parameters.Paranoia
		renameCustomObjectProperty $lma.Data.Parameters "Paranoia" "DetectionLevel"
	}
	$lma
}
Export-ModuleMember -function Set-LmAFEConfiguration, Set-AFEConfiguration

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Update-AFEIDSRules
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "updatedetect" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Update-AFEIDSRules, Update-IDSRules

# ==================================================
# endregion AFE
# ==================================================


# ==================================================
# region CONNLIMIT
# ==================================================

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmIPConnectionLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "afeclientlimitlist" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmIPConnectionLimit" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmIPConnectionLimit, AfeClientLimitList

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function New-LmIPConnectionLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "afeclientlimitadd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-LmIPConnectionLimit, AfeClientLimitAdd

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Remove-LmIPConnectionLimit
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "afeclientlimitdel" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LmIPConnectionLimit, AfeClientLimitDelete

# ==================================================
# endregion CONNLIMIT
# ==================================================


# ==================================================
# region HA
# ==================================================

# Internal use only
Function GetHaModeString($HaMode)
{
	switch ($HaMode)
	{
		0 { $HaModeStringValue = "No HA mode" }
		1 { $HaModeStringValue = "HA First" }
		2 { $HaModeStringValue = "HA Second" }
		3 { $HaModeStringValue = "Cloud HA" }
		4 { $HaModeStringValue = "N+M Cluster" }

		default { $HaModeStringValue = "HA mode UNKNOWN" }
	}
	return $HaModeStringValue
}

# Internal use only
Function ConvertHaModeStringToInt($HaMode)
{
	switch ($HaMode)
	{
		"SingleMode" {
			$HaModeIntValue = 0
			break
		}

		"HA First" {
			$HaModeIntValue = 1
			break
		}

		"HA Second" {
			$HaModeIntValue = 2
			break
		}

		default {
			$HaModeIntValue = -1
			break
		}
	}
	return $HaModeIntValue
}

# Internal use only
Function GetPreferredServerString($prefServer)
{
	switch ($prefServer)
	{
		0 { $prefServerString = "No Preferred Host" }
		1 { $prefServerString = "Prefer First HA" }
		2 { $prefServerString = "Prefer Second HA" }

		default { $prefServerString = "Prefer UNKNOWN" }
	}
	return $prefServerString
}

Function Get-LmHAMode
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$lma = GetLmParameter "Hamode" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	$HaModeValue = $lma.Data.hamode
	if ($HaModeValue -ge 0 -and $HaModeValue -le 4) {
		$HaModeDescription = GetHaModeString $HaModeValue
		$tmp = [ordered]@{}
		$tmp.Add("HaMode", $HaModeValue)
		$tmp.Add("HaDescription", $HaModeDescription)
		$dataObj = New-Object -TypeName PSObject -Prop $tmp

		$haConf = [ordered]@{}
		$haConf.Add("HAConf", $dataObj)
		$haObj = New-Object -TypeName PSObject -Prop $haConf

		setKempAPIReturnObject 200 "Command successfully executed" $haObj
	}
	else {
		Write-Verbose "ERROR: invalid HA mode value [$HaModeValue]"
		setKempAPIReturnObject 401 "ERROR: invalid HA mode value" $null
	}
}
Export-ModuleMember -function Get-LmHAMode

Function Set-LmHAMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("SingleMode", "HA First", "HA Second")]
		[string]$HaMode,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$intHaMode = ConvertHaModeStringToInt $HaMode
	if ($intHaMode -lt 0) {
		setKempAPIReturnObject 401 "System error: not allowed HA mode value [$intHaMode]" $null
		return
	}

	SetLmParameter "hamode" $intHaMode $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function Set-LmHAMode

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmHAConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$lma = Get-LmHAMode @params
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}

	if ($lma.Data.HAConf.HaMode -le 0 -or $lma.Data.HAConf.HaMode -ge 3) {
		setKempAPIReturnObject 401 "ERROR: The LoadMaster is not in HA mode." $null
		return
	}

	$params2get = @("hamode", "hatimeout", "hawait", "havhid", "haprefered", "haif", "hal4update", "hal7update", "MCast", "Vmac")

	$ht = [ordered]@{}
	$ht.PSTypeName = "HAConfiguration"
	foreach($param in $params2get) {
		$params.Add("param", $param)

		$lma = Get-LmParameter @params
		if ($lma.ReturnCode -eq 200) {
			$paramValue = $lma.Data.$param
			if ($param -eq "hamode") {
				$ht.Add($param, (GetHaModeString $paramValue))
			}
			elseif ($param -eq "haprefered") {
				$ht.Add($param, (GetPreferredServerString $paramValue))
			}
			elseif ($param -eq "hatimeout") {
				$ht.Add($param, (($paramValue -as [int])*3))
			}
			else {
				$ht.Add($param, $paramValue)
			}
		}
		else {
			return $lma
		}
		$params.Remove("param")
		Start-Sleep -m 200
	}
	$tmpObj = New-Object -TypeName PSObject -Property $ht

	$haConf = [ordered]@{}
	$haConf.PSTypeName = "HAConfiguration"
	$haConf.Add("HAConfiguration", $tmpObj)
	$emConfObject = New-Object -TypeName PSObject -Property $haConf

	setKempAPIReturnObject 200 "Command successfully executed" $emConfObject
}
Export-ModuleMember -function Get-LmHAConfiguration, Get-HAOption

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Set-LmHAConfiguration
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

		[Int16]$MCast,

		[bool]$Vmac,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	if ($hatimeout) {
		$parameters2set["hatimeout"] = $hatimeout/3
	}
	if ($haprefered) {
		$parameters2set["haprefered"] = $preferredServerHT[$haprefered]
	}

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	$lma = GetLmParameterSet $params2Get "Parameters" $params
	if ($lma.ReturnCode -eq 200) {
		if ($lma.Data.Parameters.hatimeout) {
			$lma.Data.Parameters.hatimeout = ($lma.Data.Parameters.hatimeout -as [int])*3
		}
		if ($lma.Data.Parameters.haprefered -ge 0) {
			$lma.Data.Parameters.haprefered = GetPreferredServerString $lma.Data.Parameters.haprefered
		}
	}
	$lma
}
Export-ModuleMember -function Set-LmHAConfiguration, Set-HAOption

Function Set-LmAzureHAMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("master", "slave", "single", "first", "second")]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "azurehamode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmAzureHAMode, Set-AzureHAMode

Function Get-LmAzureHAConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getazurehaparams" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAzureHAConfiguration" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmAzureHAConfiguration, Get-AzureHAOption

Function Set-LmAzureHAConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$Partner,

		[ValidateNotNullOrEmpty()]
		[string]$HealthCheckPort,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, 1)]
		[int]$Hapreferred,

		[ValidateNotNullOrEmpty()]
		[ValidateSet("no", "yes")]
		[string]$HealthCheckAllInterfaces = "no",

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (!$Partner -and !$HealthCheckPort) {
		Throw "ERROR: Partner and/or Hcp must be provided."
	}

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($HealthCheckPort) {
		$params.Remove("HealthCheckPort")
		$params.Add("Hcp", $HealthCheckPort)
	}
	if ($Hapreferred -eq 0 -or $Hapreferred -eq 1) {
		$params.Remove("Hapreferred")
		$params.Add("Haprefered", $Hapreferred)
	}
	else {
		Throw "ERROR: Value for Hapreferred ($Hapreferred) out of range."
		return
	}
	if ($HealthCheckAllInterfaces) {
		$params.Remove("HealthCheckAllInterfaces")
		if ($HealthCheckAllInterfaces -eq "yes") {
			$params.Add("hcai", 1)
		}
		else {
			$params.Add("hcai", 0)
		}
	}

	try {
		$response = SendCmdToLm -Command "azurehaparam" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmAzureHAConfiguration, Set-AzureHAOption

Function Set-LmAwsHAMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("master", "slave", "single", "first", "second")]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "awshamode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmAwsHAMode, Set-AwsHAMode

Function Get-LmAwsHAConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "getawshaparams" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetAwsHaConfiguration" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmAwsHAConfiguration, Get-AwsHAOption

Function Set-LmAwsHAConfiguration
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
		[ValidateSet("no", "yes")]
		[string]$HealthCheckAllInterfaces = "no",

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (!$Partner -and !$HealthCheckPort) {
		Throw "ERROR: Partner and/or HealthCheckPort must be provided."
	}

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($HealthCheckPort) {
		$params.Remove("HealthCheckPort")
		$params.Add("Hcp", $HealthCheckPort)
	}

	if ($HealthCheckAllInterfaces) {
		$params.Remove("HealthCheckAllInterfaces")
		if ($HealthCheckAllInterfaces -eq "yes") {
			$params.Add("hcai", 1)
		}
		else {
			$params.Add("hcai", 0)
		}
	}

	try {
		$response = SendCmdToLm -Command "awshaparam" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmAwsHAConfiguration, Set-AwsHAOption

Function Set-LmCloudHAMode
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("master", "slave", "single", "first", "second")]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "setcloudhamode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmCloudHAMode

Function Get-LmCloudHaConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "getcloudhaparams" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmCloudHaConfiguration" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmCloudHaConfiguration

Function Set-LmCloudHaConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[string]$Partner,

		[ValidateNotNullOrEmpty()]
		[string]$HealthCheckPort,

		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, 1)]
		[int]$Hapreferred,

		[ValidateNotNullOrEmpty()]
		[ValidateSet("no", "yes")]
		[string]$HealthCheckAllInterfaces = "no",

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if (!$Partner -and !$HealthCheckPort) {
		Throw "ERROR: Partner and/or Hcp must be provided."
	}

	$params = ConvertBoundParameters -hashtable $psboundparameters
	if ($HealthCheckPort) {
		$params.Remove("HealthCheckPort")
		$params.Add("Hcp", $HealthCheckPort)
	}
	if ($Hapreferred -eq 0 -or $Hapreferred -eq 1) {
		$params.Remove("Hapreferred")
		$params.Add("Haprefered", $Hapreferred)
	}
	else {
		Throw "ERROR: Value for Hapreferred ($Hapreferred) out of range."
		return
	}
	if ($HealthCheckAllInterfaces) {
		$params.Remove("HealthCheckAllInterfaces")
		if ($HealthCheckAllInterfaces -eq "yes") {
			$params.Add("hcai", 1)
		}
		else {
			$params.Add("hcai", 0)
		}
	}

	try {
		$response = SendCmdToLm -Command "setcloudhaparam" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmCloudHaConfiguration

# ==================================================
# endregion HA
# ==================================================


# ==================================================
# region DIAGNOSTIC
# ==================================================

Function Get-LmDebugInformation
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateSet("ps", "meminfo", "ifconfig", "netstat", "interrupts", "partitions", "cpuinfo", "df", "lspci", "lsmod", "slabinfo")]
		[string]$Param,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$cmd = "logging/$Param"
	
	try {
		$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmDebugInformation" -LMResponse $response -AdditionalData $Param
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmDebugInformation

#.ExternalHelp Kemp.LoadBalancer.Powershell-Help.xml
Function Get-LmDebugConfiguration
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	# NOTE: to verify
	#        - Enable L7 Debug Traces
	#        - Perform an l7adm
	#        - Enable WAF Debug Logging
	#        - Enable TSO
	#        - Enable Bind Debug Traces
	#        - Include Netstat in Backups
	#        - Reset Statistic Counters
	#        - Flush OCSPD Cache
	#        - SSO LDAP server timeout
	#        - Stop IPsec IKE Daemon
	#        - Perform an IPsec Status
	#        - Enable IKE Debug Level Logs
	$parameters = @("irqbalance", "linearesplogs", "netconsole", "netconsoleinterface")

	GetLmParameterSet $parameters "LmDebugConfiguration" $params
}
Export-ModuleMember -function Get-LmDebugConfiguration, Get-DebugOption

Function Set-LmDebugConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$parameters2set = ConvertBoundParameters -hashtable $psboundparameters -SkipEncoding

	$params2Get = @()
	foreach ($param in $parameters2set.Keys) {

		$params.Add("param", $param)
		$params.Add("value", $parameters2set[$param])
		$params2Get += $param

		$response = Set-LmParameter @params
		if ($response.ReturnCode -ne 200) {
			return $response
		}

		$params.Remove("param")
		$params.Remove("value")

		Start-Sleep -m 200
	}
	GetLmParameterSet $params2Get "Parameters" $params
}
Export-ModuleMember -function Set-LmDebugConfiguration, Set-DebugOption

# Internal use only
Function CheckPingInputParameters($Address2Ping, $PingClass, $Interface, $params)
{
	if (([String]::IsNullOrEmpty($Address2Ping))) {
		Throw "ERROR: Address to ping is NULL"
	}
	$params.Remove("Address")
	$params.Add("addr", $Address)

	if (([String]::IsNullOrEmpty($PingClass))) {
		Throw "ERROR: Ping class is NULL"
	}

	if ($PingClass -ne "ping" -and $PingClass -ne "ping6") {
		Throw "ERROR: Not allowed Ping Class ($PingClass)"
	}
	if ($PingClass -ne "") {
		$params.Remove("PingClass")
	}

	if ($Interface) {
		$params.Remove("Interface")
		$params.Add("intf", $Interface)
	}
}

Function Ping-Host
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Address,

		[ValidateSet("ping", "ping6")]
		[string]$PingClass = "ping",

		[string]$Interface = $null,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	if ($Interface) {
		$ConnParams2 = getConnParameters_2 $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$lma = Get-LmNetworkInterface @ConnParams2
		if ($lma.ReturnCode -ne 200) {
			return $lma
		}
		$check = $false
		$intfs = $lma.Data.Interface.name
		foreach($item in $intfs) {
			if ($item -eq $Interface) {
				$check = $true
				break
			}
		}
		if ($check -eq $false) {
			setKempAPIReturnObject 400 "Invalid interface ($Interface)" $null
			return
		}
	}

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	CheckPingInputParameters $Address $PingClass $Interface $params
	
	$cmd = "logging/$PingClass"
	try {
		$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "PingHost" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Ping-Host

Function Trace-TcpTraffic
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

	PROCESS
	{
		validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
		$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

		$params = [ordered]@{}
		if($MaxPackets){
			$params.Add("maxpackets", $MaxPackets)
		}
		if($MaxTime){
			$params.Add("maxtime", $MaxTime)
		}
		if($Interface){
			$params.Add("interface", $Interface)
		}
		if($Port){
			$params.Add("port", $Port)
		}
		if($Address){
			$params.Add("address", $Address)
		}
		if($TcpOptions){
			$params.Add("tcpoptions", $TcpOptions)
		}

		if (-not ($Path))
		{
			$defaultFolder = "$($Env:SystemRoot)\Temp"
			if (Test-Path -Path $defaultFolder) {
				$Path = "$defaultFolder\tcpdump_$(Get-Date -format yyyy-MM-dd_HH-mm-ss).pcap"
			}
			else {
				Throw "ERROR: the default folder $($Env:SystemRoot)\Temp does not exist"
			}
		}
		else {
			$folder = Split-Path -Path $path
			if (-not (Test-Path -Path $folder)) {
				Throw "ERROR: the folder $folder does not exist"
			}
		}
		Write-Verbose "output file: $Path"

		if (($Force) -or ($PsCmdlet.ShouldProcess($Path, "Output File Overwrite"))) {

			try {
				$response = SendCmdToLm -Command "tcpdump" -ParameterValuePair $params -File $Path -Output -ConnParams $ConnParams
				HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
			}
			catch {
				$errMsg = $_.Exception.Message
				setKempAPIReturnObject 400 "$errMsg" $null
			}
		}
	}
}
Export-ModuleMember -function Trace-TcpTraffic, DoTcpDump

Function Get-LmProcessesInfo
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateRange(1, 30)]
		[int]$iterations,

		[ValidateRange(1, 30)]
		[int]$interval,

		[switch]$mem,

		[switch]$threads,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	$cmd = "logging/top"

	if ($mem) {
		$params.Remove("mem")
		$params.Add("mem", 1)
	}

	if ($threads) {
		$params.Remove("threads")
		$params.Add("threads", 1)
	}

	try {
		$response = SendCmdToLm -Command $cmd -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLmDebugInformation" -LMResponse $response -AdditionalData "top"
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmProcessesInfo

# ==================================================
# endregion DIAGNOSTIC
# ==================================================


# ==================================================
# region N+M
# ==================================================

Function Get-ClusterStatus
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/status" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetClusterStatus" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-ClusterStatus, NMClusterStatus

Function New-Cluster
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/create" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "NewCluster" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-Cluster, NMClusterCreate

Function New-ClusterNode
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/addnode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-ClusterNode, NMAddNode

Function Join-Cluster
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/joincluster" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Join-Cluster, NMJoinCluster

Function Enable-ClusterNode
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/enablenode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Enable-ClusterNode, NMEnableNode

Function Disable-ClusterNode
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/disablenode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Disable-ClusterNode, NMDisableNode

Function Remove-ClusterNode
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$params = ConvertBoundParameters -hashtable $psboundparameters
	
	try {
		$response = SendCmdToLm -Command "cluster/deletenode" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-ClusterNode, NMDeleteNode

# ==================================================
# endregion N+M
# ==================================================


# ==================================================
# region HSM
# ==================================================
$hsm_warning = "WARNING: This function is not available. The HSM feature has been removed from the LoadMaster."

Function Get-TlsHSM
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
	Write-Output "$hsm_warning"
}
Export-ModuleMember -function Get-TlsHSM, HSMShow
 
Function Set-TlsHSM
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
	Write-Output "$hsm_warning"
}
Export-ModuleMember -function Set-TlsHSM, HSMConfigure
 
Function New-TlsHSMClientCert
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
	Write-Output "$hsm_warning"
}
Export-ModuleMember -function New-TlsHSMClientCert, HSMGenerateClientCert
 
Function Import-TlsHSMCACert
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
	Write-Output "$hsm_warning"
}
Export-ModuleMember -function Import-TlsHSMCACert, HSMUploadCACert
# ==================================================
# endregion HSM
# ==================================================

# ==================================================
# region Strongswan VPN
# ==================================================

Function New-LmRouteVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/createvpnconn" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function New-LmRouteVpnConnection

Function Remove-LmRouteVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/deletevpnconn" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LmRouteVpnConnection

Function Get-LmRouteVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($Name) {
			$cmd = "routevpn/getvpnconn"
		}
		else {
			$cmd = "routevpn/listvpns"
		}
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LmRouteVpnConnection

Function Set-LmRouteVpnConfiguration
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/setipsecconf" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmRouteVpnConfiguration

Function Set-LmRouteVpnSecrets
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/setsecretsconf" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmRouteVpnSecrets

Function Set-LmRouteVpnRoutes
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation $Path

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/setrouteconf" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Set-LmRouteVpnRoutes

Function Start-LmRouteVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/startvpnconn" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Start-LmRouteVpnConnection

Function Stop-LmRouteVpnConnection
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/stopvpnconn" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetVpnConnection" -LMResponse $response -AdditionalData $Name
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Stop-LmRouteVpnConnection

Function Start-LmRouteVpnDaemon
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/startdaemon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Start-LmRouteVpnDaemon

Function Stop-LmRouteVpnDaemon
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "routevpn/stopdaemon" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Stop-LmRouteVpnDaemon

Function Export-LmRouteVpnLogs
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$filename = validatePath $filename

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("filename")

	try {
		$response = SendCmdToLm -Command "routevpn/viewlogs" -ParameterValuePair $params -File $filename -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-LmRouteVpnLogs

Function Export-LmRouteVpnStatus
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$filename = validatePath $filename

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("filename")

	try {
		$response = SendCmdToLm -Command "routevpn/getvpnstatus" -ParameterValuePair $params -File $filename -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-LmRouteVpnStatus

Function Export-LmRouteVpnRoutes
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$filename,

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
	<#
	$ErrorActionPreference = "Stop"
	#>
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$filename = validatePath $filename

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters
	$params.Remove("filename")

	try {
		$response = SendCmdToLm -Command "routevpn/viewroutes" -ParameterValuePair $params -File $filename -Output -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Export-LmRouteVpnRoutes

# ==================================================
# endregion Strongswan VPN
# ==================================================

# ==================================================
# region Let's Encrypt
# ==================================================

Function Register-LEAccount
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$Email,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "registerleaccount" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Register-LEAccount

Function Get-LEAccount
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path $_})]
		[string]$Path,

		[ValidateNotNullOrEmpty()]
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "fetchleaccount" -ParameterValuePair $params -File $Path -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LEAccount

Function Request-NewLECertificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Cert,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$CommonName,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$VID,

		[ValidateNotNullOrEmpty()]
		[String]$Country,

		[ValidateNotNullOrEmpty()]
		[String]$State,

		[ValidateNotNullOrEmpty()]
		[String]$City,

		[ValidateNotNullOrEmpty()]
		[String]$Company,

		[ValidateNotNullOrEmpty()]
		[String]$Organization,

		[ValidateNotNullOrEmpty()]
		[String]$Email,

		[ValidateSet("2048", "4096")]
		[String]$KeySize,

		[ValidateSet("yes", "no")]
		[String]$EllipticCurve,

		[ValidateNotNullOrEmpty()]
		[String]$SAN1,
		[ValidateNotNullOrEmpty()]
		[String]$SAN2,
		[ValidateNotNullOrEmpty()]
		[String]$SAN3,
		[ValidateNotNullOrEmpty()]
		[String]$SAN4,
		[ValidateNotNullOrEmpty()]
		[String]$SAN5,
		[ValidateNotNullOrEmpty()]
		[String]$SAN6,
		[ValidateNotNullOrEmpty()]
		[String]$SAN7,
		[ValidateNotNullOrEmpty()]
		[String]$SAN8,
		[ValidateNotNullOrEmpty()]
		[String]$SAN9,
		[ValidateNotNullOrEmpty()]
		[String]$SAN10,

		[ValidateNotNullOrEmpty()]
		[String]$VID1,
		[ValidateNotNullOrEmpty()]
		[String]$VID2,
		[ValidateNotNullOrEmpty()]
		[String]$VID3,
		[ValidateNotNullOrEmpty()]
		[String]$VID4,
		[ValidateNotNullOrEmpty()]
		[String]$VID5,
		[ValidateNotNullOrEmpty()]
		[String]$VID6,
		[ValidateNotNullOrEmpty()]
		[String]$VID7,
		[ValidateNotNullOrEmpty()]
		[String]$VID8,
		[ValidateNotNullOrEmpty()]
		[String]$VID9,
		[ValidateNotNullOrEmpty()]
		[String]$VID10,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	if ($CommonName) {
		$params.Remove("CommonName")
		$params.Add("cn", $CommonName)
	}
	if ($KeySize) {
		$params.Remove("KeySize")
		$params.Add("key_size", $KeySize)
	}
	if ($EllipticCurve) {
		$params.Remove("EllipticCurve")
		$params.Add("ec", $EllipticCurve)
	}

	try {
		$response = SendCmdToLm -Command "addlecert" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Request-NewLECertificate

Function Remove-LECertificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Cert,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "dellecert" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Remove-LECertificate

Function Request-RenewLECertificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Cert,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "renewlecert" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GeneralCase" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Request-RenewLECertificate

Function Get-LECertificate
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[ValidateNotNullOrEmpty()]
		[String]$Cert,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		if ($Cert) {
			$cmd = "getlecert"
		}
		else {
			$cmd = "listlecert"
		}
		$response = SendCmdToLm -Command "$cmd" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLECertificate" -LMResponse $response -AdditionalData $Cert
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}
}
Export-ModuleMember -function Get-LECertificate

Function Get-LERenewPeriod
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$lma = GetLmParameter "renewperiod" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	# Convert it in PS object
	$tmp = [ordered]@{}
	$tmp.Add("RenewPeriod", $lma.Data.renewperiod)
	$dataObj = New-Object -TypeName PSObject -Prop $tmp
	setKempAPIReturnObject 200 "Command successfully executed" $dataObj
}
Export-ModuleMember -function Get-LERenewPeriod

Function Set-LERenewPeriod
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[int]$RenewPeriod,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	SetLmParameter "renewperiod" $RenewPeriod $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function Set-LERenewPeriod

Function Get-LEDirectoryURL
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$lma = GetLmParameter "directoryurl" $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	if ($lma.ReturnCode -ne 200) {
		return $lma
	}
	# Convert it in PS object
	$tmp = [ordered]@{}
	$tmp.Add("DirectoryURL", $lma.Data.directoryurl)
	$dataObj = New-Object -TypeName PSObject -Prop $tmp
	setKempAPIReturnObject 200 "Command successfully executed" $dataObj
}
Export-ModuleMember -function Get-LEDirectoryURL

Function Set-LEDirectoryURL
{
	[cmdletbinding(DefaultParameterSetName='Credential')]
	Param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$DirectoryURL,

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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	SetLmParameter "directoryurl" $DirectoryURL $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
}
Export-ModuleMember -function Set-LEDirectoryURL

Function Get-LEAccountInfo
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
	validateCommonInputParams $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation

	$ConnParams = getConnParameters $LoadBalancer $LBPort $Credential $SubjectCN $CertificateStoreLocation
	$params = ConvertBoundParameters -hashtable $psboundparameters

	try {
		$response = SendCmdToLm -Command "leaccountinfo" -ParameterValuePair $params -ConnParams $ConnParams
		HandleLmAnswer -Command2ExecClass "GetLEAccountInfo" -LMResponse $response
	}
	catch {
		$errMsg = $_.Exception.Message
		setKempAPIReturnObject 400 "$errMsg" $null
	}

}
Export-ModuleMember -function Get-LEAccountInfo

# ==================================================
# endregion Let's Encrypt 
# ==================================================

