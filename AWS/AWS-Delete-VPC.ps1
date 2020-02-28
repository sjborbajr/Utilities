if (1 -eq 1) {#Using if statement to shirink view in ISE
 if ($Host.Version.Major -ge 6) {$requiredModules = @('PAN-Power','AWSPowerShell.NetCore')} else {$requiredModules = @('PAN-Power','AWSPowerShell')}
 foreach ( $module in $requiredModules )  {
  if ( -not (Get-Module -ListAvailable $Module )) { 
    Install-Module -Name $Module -Scope CurrentUser
    Write-Progress -Activity "Installing module dependancies." -CurrentOperation "Install module $module."
  }
  Import-Module $module
 }
 #Find and Load Custom Options
 if (1 -eq 1) {#Using if statement to shirink view in ISE
   if ($PSScriptRoot){ $ScriptRoot = "$PSScriptRoot" } else { $ScriptRoot = "." }
   $Temp = Get-Item "$ScriptRoot\configs\*.xml"
   if ($Temp.Count -gt 1) {
     $Temp = $Temp | select Name,LastAccessTime,FullName | Sort-Object -Property LastAccessTime | Out-GridView -Title "Which Config?" -OutputMode Single
   } elseif ($Temp.Count -eq 0) {
     Write-Error "Could not find custom option Specifications" -ErrorAction Stop
   }
   $Temp = Import-Clixml ($Temp.FullName)
     $CommonOptions = $Temp.CommonOptions
   $Router_Location = $Temp.Router_Location
     $vsys_Location = $Temp.vsys_Location
     $Zone_Location = $Temp.Zone_Location
       $vsys_Import = $Temp.vsys_Location
  $vm_info_Location = $Temp.vm_info_Location
     $Location_Name = $Temp.Location_Name
}
 #Test AWS connection and update if needed
 if (-not (Get-AWSCredential -ProfileName $CommonOptions.ProfileName)) {
   $Temp = Get-Credential -Message "Enter API key for: $CommonOptions.Profile"
   Set-AWSCredential -AccessKey $Temp.UserName -SecretKey $Temp.GetNetworkCredential().Password -StoreAs $CommonOptions.ProfileName
 } elseif (-not (Get-EC2CustomerGateway @CommonOptions)) {
   $Temp = Get-Credential -Message "Enter API key for: $CommonOptions.Profile"
   Set-AWSCredential -AccessKey $Temp.UserName -SecretKey $Temp.GetNetworkCredential().Password -StoreAs $CommonOptions.ProfileName
 }
 if (-not $PANs ) {
  Write-Host "Loading PAN info from Cloud..."
  $PANs = (Get-EC2CustomerGateway @CommonOptions | % { @{
         "Name"       = ($_.Tags | ?{ $_.Key -eq 'Name' } | select -ExpandProperty Value)
         "Management" = ($_.Tags | ?{ $_.Key -eq 'Management' } | select -ExpandProperty Value)
         "objId"      = $_.CustomerGatewayId
         "IP"         = $_.IpAddress
         "ASN"        = $_.BgpAsn
        }}) | ? { $_.Name -match ("^"+$Location_Name+'-TRANS-01-VM300-') -and $_.name -match '-1$' }
 }
 #Test PAN Connection and update if needed
 if (-not (Import-Clixml "$env:USERPROFILE\panrc.xml").Tags.($CommonOptions.ProfileName)) {
   $Temp = Invoke-PANKeyGen -Addresses $PANs[0].Management -Tag $CommonOptions.ProfileName -SkipCertificateCheck
 } elseif ( -not (Invoke-PANOperation -Tag $CommonOptions.ProfileName -Addresses $PANs[0].Management -Command '<show><system><info/></system></show>' -SkipCertificateCheck)) {
   $Temp = Invoke-PANKeyGen -Addresses $PANs[0].Management -Tag $CommonOptions.ProfileName -SkipCertificateCheck
 }
}

if ((Read-Host "Type 'delete' to continue VPC delete" ) -eq 'delete') {#Using if statement to shirink sections in ISE
 $Logging = (Get-date -Format 'u')+": Starting delete script, run by $env:username`n"
 $existingvpcs = Get-EC2Vpc @CommonOptions | %{ [PSCustomObject]@{ 'Name' = ($_.Tags | ?{ $_.Key -eq 'Name' } | select -ExpandProperty Value); 'CIDR' = $_.CidrBlock; 'objId' = $_.VpcId }}
 $VPC = $existingvpcs | Out-GridView -OutputMode Single  -Title "Which VPC?"
 If ($VPC) {
  $Logging+= (Get-date -Format 'u')+": Chose $VPC.Name`n"
  $VPC =@{'Name'         = $VPC.Name
          'ShortName'    = $VPC.Name.Substring($Location_Name.Length + 5)
          'CIDR'         = $VPC.CIDR
          'objId'        = $VPC.objId
          'PaddedNumber' = $VPC.Name.Substring($Location_Name.Length+1,3)
          'Number'       = 0 + $VPC.Name.Substring($Location_Name.Length+1,3)
         }
  $instances = Get-EC2Instance -Filter @( @{Name="vpc-id";Values=$VPC.objId} ) @CommonOptions
  $instances_Network = Get-EC2Instance -Filter @( @{Name="vpc-id";Values=$VPC.objId},@{Name="tag:Owner";Values='Network'} ) @CommonOptions
  #$VPR_Peering = Get-EC2VpcPeeringConnection -Filter @{ Name="vpc-id";Values=$VPC.objId} @CommonOptions
  if (($instances.count - $instances_Network.Count ) -gt 0 -or $VPR_Peering.count  -gt 0 ) {
    "There are running instances in that VPC, cannot remove"
     $Logging+= (Get-date -Format 'u')+": Aborting because there are instances`n"
  } else {
    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Gathering Data") -PercentComplete 5
    $vgw_obj = Get-EC2VpnGateway -Filter @{ Name="attachment.vpc-id";Values=$VPC.objId} @CommonOptions
    $vpn_obj = Get-EC2VpnConnection @CommonOptions -filter @{ Name="vpn-gateway-id";Values=$vgw_obj.VpnGatewayId}
    $VPC+=@{'VPN'=@{'Name'=($vgw_obj.Tags | ?{ $_.Key -eq 'Name' } | select -ExpandProperty Value)
                    'ASN' = $vgw_obj.AmazonSideAsn
                   'objId'= $vgw_obj.VpnGatewayId
                 "Primary"=@{"Name"= ($PANs | ? { $_.objId -eq $vpn_obj[0].CustomerGatewayId }).Name
                              'CGW'=  $vpn_obj[0].CustomerGatewayId
                            'objId'=  $vpn_obj[0].VpnConnectionId
                          "VPN_IPA"= ([xml]$vpn_obj[0].CustomerGatewayConfiguration).vpn_connection.ipsec_tunnel[0].vpn_gateway.tunnel_inside_address.ip_address
                          "VPN_IPB"= ([xml]$vpn_obj[0].CustomerGatewayConfiguration).vpn_connection.ipsec_tunnel[1].vpn_gateway.tunnel_inside_address.ip_address
                           "PAN_IP"= ($PANs | ? { $_.objId -eq $vpn_obj[0].CustomerGatewayId }).Management
                            }
               "Secondary"=@{"Name"= ($PANs | ? { $_.objId -eq $vpn_obj[1].CustomerGatewayId }).Name
                              'CGW'=  $vpn_obj[1].CustomerGatewayId
                            'objId'=  $vpn_obj[1].VpnConnectionId
                          "VPN_IPA"= ([xml]$vpn_obj[1].CustomerGatewayConfiguration).vpn_connection.ipsec_tunnel[0].vpn_gateway.tunnel_inside_address.ip_address
                          "VPN_IPB"= ([xml]$vpn_obj[1].CustomerGatewayConfiguration).vpn_connection.ipsec_tunnel[1].vpn_gateway.tunnel_inside_address.ip_address
                           "PAN_IP"= ($PANs | ? { $_.objId -eq $vpn_obj[1].CustomerGatewayId }).Management
                            }
                   }
           }
    if ($instances_Network) {
      $VPC+=@{"NETUTIL_A"=@{'Name'=($instances_Network[0].Instances[0].Tags | ?{ $_.Key -eq 'Name' } | select -ExpandProperty Value)
                           'objId'= $instances_Network[0].Instances[0].InstanceId
                              'IP'= $instances_Network[0].Instances[0].PrivateIpAddress
                             'AMI'= $instances_Network[0].Instances[0].ImageId
                            }
              "NETUTIL_B"=@{'Name'=($instances_Network[1].Instances[0].Tags | ?{ $_.Key -eq 'Name' } | select -ExpandProperty Value)
                           'objId'= $instances_Network[1].Instances[0].InstanceId
                              'IP'= $instances_Network[1].Instances[0].PrivateIpAddress
                             'AMI'= $instances_Network[1].Instances[0].ImageId
                           }
             }
    }

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing VPN") -PercentComplete 15
    $vpn_obj | % { Remove-EC2VpnConnection -VpnConnectionId $_.VpnConnectionId @CommonOptions -Force }
    Dismount-EC2VpnGateway -VpcId $VPC.objId -VpnGatewayId $vgw_obj.VpnGatewayId @CommonOptions -Force
    Remove-EC2VpnGateway -VpnGatewayId $vgw_obj.VpnGatewayId @CommonOptions -Force
    $Logging+= (Get-date -Format 'u')+": Deleted VPN Objects`n"

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Shutting Down NETUTIL") -PercentComplete 20
    if ($instances_Network) {
      $Logging+= (Get-date -Format 'u')+": Removing NETUTIL instances`n"
      $rc = $instances_Network | remove-ec2instance -Force @CommonOptions
      $i = 0
      Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Shutting Down NETUTIL") -PercentComplete 25
      Write-Progress -ParentId 1 -id 2 -Activity ("Waiting") -Status ("Waiting for shut Down") -PercentComplete 0
      while (Get-EC2Instance -Filter @( @{Name="vpc-id";Values=$VPC.objId} ) @CommonOptions) { sleep 5 ; Write-Progress -ParentId 1 -id 2 -Activity "Waiting for shut Down" -PercentComplete ($i+=5) }
      sleep 10
      Write-Progress -ParentId 1 -id 2 -Completed -Activity "Completed"
      $Logging+= (Get-date -Format 'u')+": Done Shutting down`n"
    }

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing Network Interfaces") -PercentComplete 50
    $NetInt_Obj = Get-EC2NetworkInterface @CommonOptions -Filter @{ Name="vpc-id";Values=$VPC.objId}
    if ($NetInt_Obj) {
      $VPC+=@{'ENIs'=$NetInt_Obj}
      $NetInt_Obj | % { Remove-EC2NetworkInterface -NetworkInterfaceId $_.NetworkInterfaceId @CommonOptions -Force }
    }

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing Subnets") -PercentComplete 55
    $Subnets_obj = Get-EC2Subnet -Filter @{ Name="vpc-id";Values=$VPC.objId} @CommonOptions
    if ($Subnets_obj) {
      $VPC+=@{'Subnets'=$Subnets_obj}
      $Subnets_obj | % { Remove-EC2Subnet -SubnetId $_.SubnetId @CommonOptions -Force }
    }
    $Logging+= (Get-date -Format 'u')+": Removed Subnet Objects`n"

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing ACLs") -PercentComplete 65
    $acls = Get-EC2NetworkAcl -Filter @{ Name="vpc-id";Values=$VPC.objId} @CommonOptions | ? { $_.IsDefault -eq $false }
    if ($acls) {
      $VPC+=@{'acls'=$acls}
      $acls | % { Remove-EC2NetworkAcl -NetworkAclId $_.NetworkAclId @CommonOptions -Force }
    }
    $Logging+= (Get-date -Format 'u')+": Removed ACL Objects`n"

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing Security Groups") -PercentComplete 70
    $SGs = Get-EC2SecurityGroup -Filter @{ Name="vpc-id";Values=$VPC.objId} @CommonOptions | ? { $_.GroupName -ne 'default' } | Sort-Object -Property GroupName -Descending
    if ($SGs) {
      $VPC+=@{'SGs'=$SGs}
      $SGs | % { Remove-EC2SecurityGroup -GroupId $_.GroupId @CommonOptions -Force }
    }
    $Logging+= (Get-date -Format 'u')+": Removed Security Group Objects`n"

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing PAN Configs") -PercentComplete 75
    if (1 -eq 1) {
      #Remove VPN Configs
      $XPaths = @(($Router_Location+'/protocol/bgp/peer-group/entry[@name="SubscriberVPCs"]/peer/entry[@name="'+$VPC.Name+'-1"]'),
                ($Router_Location+'/protocol/bgp/peer-group/entry[@name="SubscriberVPCs"]/peer/entry[@name="'+$VPC.Name+'-2"]'),
                ($vm_info_Location+'/entry[@name="'+$VPC.Name+'"]'),
                ('/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec/entry[@name="'+$VPC.Name+'-1"]'),
                ('/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec/entry[@name="'+$VPC.Name+'-2"]'),
                ('/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="'+$VPC.Name+'-1"]'),
                ('/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway/entry[@name="'+$VPC.Name+'-2"]'))
      ForEach ($XPath in $XPaths) {
       $rc = Remove-PANConfig -Tag $CommonOptions.ProfileName -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -XPath ($XPath) -SkipCertificateCheck
      }

      #Remove Interface from 
      $Interface_A = 'tunnel.1'+$VPC.PaddedNumber
      $Interface_B = 'tunnel.2'+$VPC.PaddedNumber
      ForEach ($Location in (($Router_Location+'/interface'),($Zone_Location+'/entry[@name="'+$VPC.ShortName+'"]/network/layer3'),$vsys_Import)) {
       ForEach ($Interface in ($Interface_A,$Interface_B)) {
          $rc = Remove-PANConfig -Tag $CommonOptions.ProfileName -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -XPath ($Location+"/member[text()='"+$Interface+"']") -SkipCertificateCheck
       }
      }
      $rc = Remove-PANConfig -Tag $CommonOptions.ProfileName -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -XPath ('/config/devices/entry[@name="localhost.localdomain"]/network/interface/tunnel/units/entry[@name="'+$Interface_A+'"]') -SkipCertificateCheck
      $rc = Remove-PANConfig -Tag $CommonOptions.ProfileName -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -XPath ('/config/devices/entry[@name="localhost.localdomain"]/network/interface/tunnel/units/entry[@name="'+$Interface_B+'"]') -SkipCertificateCheck

      #Delete Zone if Empty
      ForEach ($PAN in ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP)) {
        $rc = Get-PANConfig -Tag $CommonOptions.ProfileName -Addresses $PAN -SkipCertificateCheck -XPath ($Zone_Location+'/entry[@name="'+$VPC.ShortName+'"]')
        if ($rc.result.entry.network.layer3.member.Count -eq 0) {
          $rc = Remove-PANConfig -Tag $CommonOptions.ProfileName -Addresses $PAN -XPath ($Zone_Location+'/entry[@name="'+$VPC.ShortName+'"]') -SkipCertificateCheck
        }
      }

      #Commit
      $rc = Invoke-PANCommit -Tag $CommonOptions.ProfileName -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -SkipCertificateCheck
      $Logging+= (Get-date -Format 'u')+": Removed PAN Configs`n"
    }

    Write-Progress -id 1 -Activity ("Deleting VPC - "+$VPC.Name) -Status ("Removing VPC") -PercentComplete 95
    Remove-EC2Vpc -VpcId $VPC.objId @CommonOptions -Force
    $Logging+= (Get-date -Format 'u')+": Removed VPC`n"
    $VPC+=@{'Log'=$Logging}
    $VPC |  Export-Clixml ("$PSScriptRoot\Built\"+$(Get-Date -Format 'yyyyMMdd_HHmmss')+"_Delete_"+$env:UserName+"_"+$VPC.Name+".xml")
  }
 }
}
