##########
# This example assumes a KEMP LoadMaster with an IP Address has been deployed and is ready for setup. 
# A valid KEMP ID and password exist to get the license from the KEMP Licensing Server
##########

# (1) CREATE THE CREDENTIALS
$LMPASSWD = ConvertTo-SecureString "<<your password>>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("bal", $LMPASSWD)
$LMIP = <<LoadMaster IP address>>
$KEMPID = <<Customer KEMP ID>>
$KEMPPASSWD = <<Customer KEMP PASSWORD>>
# (2) Virtual Service and Real Server details (for mode details about the configuration parameters see the official KEMP documentation: https://kemptechnologies.com/loadmaster-documentation/)
$VSIP = <<Virtual Service IP>>
$VSPORT = <<Virtual Service Port>>
$VSPROTOCOL = <<Virtual Service Protocol (tcp/udp)>>
$RSIP = <<Real Server IP>>
$RSPORT = <<Real Server Port>>
# (3) GET the EULA
$reula = Read-LicenseEULA -LoadBalancer $LMIP -Credential $creds
if ($reula.ReturnCode -ne 200) {
    # ERROR: exit
    return $reula
}
# (4) CONFIRM the EULA (mandatory)
$ceula = Confirm-LicenseEULA -Magic $reula.Data.Eula.MagicString `
                            -LoadBalancer $LMIP -Credential $creds
if ($ceula.ReturnCode -ne 200) {
    # ERROR: exit
    return $ceula
}
# (5) CONFIRM/NOT CONFIRM the EULA2 (your choice)
#$accept = “yes”
$accept = “no”
$ceula2 = Confirm-LicenseEULA2 -Magic $ceula.Data.Eula2.MagicString `
              -Accept $accept -LoadBalancer $LMIP -Credential $creds
if ($ceula2.ReturnCode -ne 200) {
    # ERROR: exit
    return $ceula2
}
# (6) LICENSE the machine
$lic = Request-LicenseOnline -LoadBalancer $LMIP -Credential $creds `
                                -KempId $KEMPID -Password $KEMPPASSWD
if ($lic.ReturnCode -ne 200) {
    # ERROR: exit
    return $lic
}
# (7) SET the Initial Password
$setp = Set-LicenseInitialPassword -Passwd $LMPASSWD -LoadBalancer $LMIP `
                                                      -Credential $creds
if ($setp .ReturnCode -ne 200) {
    # ERROR: exit
    return $setp
}
# (8) CREATE a Virtual Service
$vs = New-AdcVirtualService -VirtualService $VSIP -VSPort $VSPORT `
     -VSProtocol $VSPROTOCOL -LoadBalancer $LMIP -Credential $creds
if ($vs.ReturnCode -ne 200) {
    # ERROR: exit
    return $vs
}
# (9) CREATE a Real Server
$rs = New-AdcRealServer -VirtualService $VSIP -VSPort $VSPORT `
-VSProtocol $VSPROTOCOL -RealServer $RSIP -RealServerPort $RSPORT `
                         -LoadBalancer $LMIP -Credential $creds
if ($rs.ReturnCode -ne 200) {
    # ERROR: exit
    return $rs
}
