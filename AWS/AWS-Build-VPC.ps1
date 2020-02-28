If (1 -eq 1) {#Using if statement to shirink view in ISE
 if ($Host.Version.Major -ge 6) {$requiredModules = @('PAN-Power','AWSPowerShell.NetCore')} else {$requiredModules = @('PAN-Power','AWSPowerShell')}
 foreach ( $module in $requiredModules )  {
  if ( -not (Get-Module -ListAvailable $Module )) { 
    Write-Progress -Activity "Installing module dependancies." -CurrentOperation "Install module $module."
    Install-Module -Name $Module -Scope CurrentUser
  }
  Import-Module $module
 }
 #Find and Load Custom Options
 if (1 -eq 1) {#Using if statement to shirink view in ISE
   if ($PSScriptRoot){ $ScriptRoot = "$PSScriptRoot" } else { $ScriptRoot = "." }
   $Temp = Get-Item "$ScriptRoot\configs\*.xml"
   if ($Temp.Count -gt 1) {
     $Temp = $Temp | select Name,LastAccessTime,FullName | Sort-Object -Property LastAccessTime | Out-GridView -Title "Which Custom Options?" -OutputMode Single
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
       $IKE_Common = $Temp.IKE_Common
 $Interface_Common = $Temp.Interface_Common
       $BGP_Common = $Temp.BGP_Common
          $KeyName = $Temp.KeyName
     $DefaultRules = $Temp.DefaultRules
     $RO_AccessKey = $Temp.RO_AccessKey
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
 Write-Output 'Querying AWS for AMI...'
 $AMI = (Get-EC2Image @CommonOptions -Owner 513442679011 -Filter @(@{Name= 'sriov-net-support';Values='simple'},@{Name= 'virtualization-type';Values='hvm'}) | ? {
            $_.Description -match 'Canonical, Ubuntu, ' -and $_.Description -match ' LTS, amd64 ' -and
            -not ($_.Name -match 'ubuntu-minimal') -and
            $_.RootDeviceType -match 'ebs' # 'instance-store'
          } | Sort-Object -Descending -Property 'Description' )[0]
}

#Gather Data
if (1 -eq 1) {#Using if statement to shirink sections in ISE
 $Logging = (Get-date -Format 'u')+": Starting build script, run by $env:username`n"
 #Figure Out all the information needed
 if (1 -eq 1) {#Using if statement to shirink sections in ISE
  #Process to get VPC Name
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    #PAN Tunnel name limited is 31
    $Temp = 32 - ("$Location_Name-###-"+"-A").Length
    $VPC_Name = @()
    [ValidatePattern('^[A-Z0-9][A-Z0-9\-]*[A-Z0-9]$')]$VPC_Name = Read-Host -Prompt "VPC Name (alpha/numeric/hyphen, less than $temp)"
    While ($VPC_Name.Length -ge $temp) {
      $Logging+= (Get-date -Format 'u')+": Name $VPC_Name exceeds limit`n"
      [ValidatePattern('^[A-Z0-9][A-Z0-9\-]*[A-Z0-9]$')]$VPC_Name = Read-Host -Prompt ("Invalid name, VPC Name (alpha/numeric/hyphen, less than $Temp)")
    }
    if (-not $VPC_Name) {write-error "Did not get valid VPC Name" -ErrorAction Stop}
    $VPC_Name = $VPC_Name.ToUpper()
    $Logging+= (Get-date -Format 'u')+": Chose Name: $VPC_Name`n"
  }

  #Process to get VPC Size
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $message  = 'VPC Sizing';$choices  = '&Yes', '&No'
    $question = 'Will any Tier need more than 50 nodes (split in two AZs)?'
    if ( ($Host.UI.PromptForChoice($message, $question, $choices, 1)) -eq 0) {
      $Size = 'Large'
    } else {
      $Size = 'Small'
    }
    $Logging+= (Get-date -Format 'u')+": Chose Size $Size`n"
  }

  ########## To Do
    #Ask if standard waterfall, or double

  #Process to figure out the next VPC ID
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Interfaces = Invoke-PANOperation -Tag $CommonOptions.ProfileName -Addresses ($PANs[0].Management,$PANs[1].Management) -SkipCertificateCheck -Command '<show><interface>all</interface></show>'
    $Interfaces = $Interfaces.result.ifnet.entry | Where-Object { $_.name -match 'tunnel' } | select -ExpandProperty name
    $VPC_Number = ''
    ForEach ($i in 1001..1900) {
      if ( $VPC_Number -eq '' -and -not ($Interfaces -contains ('tunnel.'+$i))) {
        $VPC_Number = $i - 1000
      }
    }
    $Logging+= (Get-date -Format 'u')+": Chose VPC number of $VPC_Number`n"
  }

  

  #Process to Figure out the subnets/names and zones
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    #Decide on AZs
      #Option 1 to choose AZ, spread subnets out over all, formula to might be (($i + $VPC['Number']) % $AZs.count) - may cause higher bandwidth cost
      #Option 2 to Choose AZ, Always first and second
      #Option 3 to choose AZ, only two, but spread based on vpc number ( ($VPC.Number+$i)%2 + ($VPC.Number-1)%$AZs.count )%$AZs.count
      #   While there are three AZs, A&B, B&C, A&C, repeat
    $AZs = Get-EC2AvailabilityZone @CommonOptions
    $AZ_A = $AZs[(($VPC_Number-1)%($AZs.Count))].ZoneName
    $AZ_B = $AZs[(($VPC_Number-0)%($AZs.Count))].ZoneName

    $DownPeer =  (Invoke-PANOperation -Tag $CommonOptions.ProfileName -Addresses ($PANs[0].Management,$PANs[1].Management) -SkipCertificateCheck -Command '<show><routing><protocol><bgp><peer><virtual-router>default</virtual-router></peer></bgp></protocol></routing></show>').result.entry | ? { $_.status -ne 'Established' }
    If ($DownPeer) {
      $Logging+= (Get-date -Format 'u')+": There are down BGP Peers`n"
      $i = 5
      Write-Progress -id 1 -Activity ("Finding subnet") -Status ("Waiting for BGP Peers") -PercentComplete 5
      sleep 15
      while ((Invoke-PANOperation -Tag $CommonOptions.ProfileName -Addresses ($PANs[0].Management,$PANs[1].Management) -SkipCertificateCheck -Command '<show><routing><protocol><bgp><peer><virtual-router>default</virtual-router></peer></bgp></protocol></routing></show>').result.entry | ? { $_.status -ne 'Established' }) { sleep 15 ; Write-Progress -id 1 -Activity "Finding subnet" -Status "Waiting for BGP Peers" -PercentComplete ($i+=5); if ($i -ge 90) {$i = 50} }
      sleep 45 #Sleeping after to allow for routes to propigate after establishment
      Write-Progress -id 1 -Completed -Activity "Completed"
      $Logging+= (Get-date -Format 'u')+": There were down BGP Peers`n"
    }
    $Routes = Invoke-PANOperation -Tag $CommonOptions.ProfileName -Addresses ($PANs[0].Management,$PANs[1].Management) -SkipCertificateCheck -Command '<show><routing><protocol><bgp><loc-rib><virtual-router>default</virtual-router></loc-rib></bgp></protocol></routing></show>'
    $Routes = $Routes.result.entry.'loc-rib'.member | ? { $_.'received-from' -ne 'CO' -and $_.'received-from' -ne 'TMS' -and $_.'received-from' -ne 'Local' } | select -ExpandProperty prefix

    $Temp = '000'+$VPC_Number
    $Temp = $Temp.Substring(($temp.Length-3),3)
    $BaseName = "$Location_Name-$Temp-$VPC_Name"

    #Locate Lowest/highest hole in IP range for VPC Size, Generate Subnets and Names
    if ($Size -eq 'Small') {
      $i = 11; While ($i -le 127) {
        if ( -not ($Routes -contains ('10.56.'+$i+'.0/24'))) {
          $CIDR_Base = $i
          $i = 256
        }
      $i++}
      $Subnets =@(@{'Name'="$Basename-TIER1-A" ;'CIDR'='10.56.'+$CIDR_Base+'.0/27'      ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER1-B" ;'CIDR'='10.56.'+$CIDR_Base+'.32/27'     ;'AZ'=$AZ_B},
                  @{'Name'="$Basename-TIER2-A" ;'CIDR'='10.56.'+$CIDR_Base+'.64/27'     ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER2-B" ;'CIDR'='10.56.'+$CIDR_Base+'.96/27'     ;'AZ'=$AZ_B},
                  @{'Name'="$Basename-TIER3-A" ;'CIDR'='10.56.'+$CIDR_Base+'.128/27'    ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER3-B" ;'CIDR'='10.56.'+$CIDR_Base+'.160/27'    ;'AZ'=$AZ_B},
                  @{'Name'="$Basename-TIER4-A" ;'CIDR'='10.56.'+$CIDR_Base+'.192/27'    ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER4-B" ;'CIDR'='10.56.'+$CIDR_Base+'.224/27'    ;'AZ'=$AZ_B})
      $CIDR = '10.56.'+$CIDR_Base+'.0/24'
    } else {
      $i = 252; While ($i -gt 128) {
        if ( -not ($Routes -contains ('10.56.'+$i+'.0/22'))) {
          $CIDR_Base = $i
          $i = -1
        }
      $i+=-4;}
      $Subnets =@(@{'Name'="$Basename-TIER1-A" ;'CIDR'='10.56.'+($CIDR_Base+0)+'.0/25'  ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER1-B" ;'CIDR'='10.56.'+($CIDR_Base+0)+'.128/25';'AZ'=$AZ_B},
                  @{'Name'="$Basename-TIER2-A" ;'CIDR'='10.56.'+($CIDR_Base+1)+'.0/25'  ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER2-B" ;'CIDR'='10.56.'+($CIDR_Base+1)+'.128/25';'AZ'=$AZ_B},
                  @{'Name'="$Basename-TIER3-A" ;'CIDR'='10.56.'+($CIDR_Base+2)+'.0/25'  ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER3-B" ;'CIDR'='10.56.'+($CIDR_Base+2)+'.128/25';'AZ'=$AZ_B},
                  @{'Name'="$Basename-TIER4-A" ;'CIDR'='10.56.'+($CIDR_Base+3)+'.0/25'  ;'AZ'=$AZ_A},
                  @{'Name'="$Basename-TIER4-B" ;'CIDR'='10.56.'+($CIDR_Base+3)+'.128/25';'AZ'=$AZ_B})
      $CIDR = '10.56.'+$CIDR_Base+'.0/22'
    }
    $Logging+= (Get-date -Format 'u')+": All Data gathered, CIDR=$CIDR`n"
  }
}

#Setup all Names/object
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  $Temp = '000'+$VPC_Number
  $Temp = $Temp.Substring(($temp.Length-3),3)
  $FourthOctet = 4 * (0 + $VPC_Number - 1)
  $NETUTILA_IPs = Switch ($Size) {'Small' {@("10.56.$CIDR_Base.4","10.56.$CIDR_Base.68","10.56.$CIDR_Base.132","10.56.$CIDR_Base.196")};   'Large' {@(("10.56."+($CIDR_Base+0)+".4")  ,("10.56."+($CIDR_Base+1)+".4")  ,("10.56."+($CIDR_Base+2)+".4")  ,("10.56."+($CIDR_Base+3)+".4"  ))}}
  $NETUTILB_IPs = Switch ($Size) {'Small' {@("10.56.$CIDR_Base.100","10.56.$CIDR_Base.36","10.56.$CIDR_Base.164","10.56.$CIDR_Base.228")}; 'Large' {@(("10.56."+($CIDR_Base+1)+".132"),("10.56."+($CIDR_Base+0)+".132"),("10.56."+($CIDR_Base+2)+".132"),("10.56."+($CIDR_Base+3)+".132"))}}
  $VPC=@{'ShortName' = $VPC_Name
         'ZoneName'  = $VPC_Name
         'Name'      = $BaseName
         'Number'    = $VPC_Number
         'CIDR'      = $CIDR
         'Size'      = $Size
         'Default_SG'=@{'Name' ="$BaseName-Default"
                        'Rules'=$DefaultRules}
         'VPN'       =@{"Name"= $BaseName
                         'ASN'=(''+(64800+$VPC_Number))
                           "Primary"=@{"Name"=($PANs | ? { $_.Name -match 'VM300-A' }).Name
                                        'CGW'=($PANs | ? { $_.Name -match 'VM300-A' }).objId
                                    "VPN_IPA"=('169.254.16.'+$FourthOctet+'/30')
                                    "VPN_IPB"=('169.254.17.'+$FourthOctet+'/30')
                                     "PAN_IP"=($PANs | ? { $_.Name -match 'VM300-A' }).Management
                                      }
                         "Secondary"=@{"Name"=($PANs | ? { $_.Name -match 'VM300-B' }).Name
                                        'CGW'=($PANs | ? { $_.Name -match 'VM300-B' }).objId
                                    "VPN_IPA"=('169.254.18.'+$FourthOctet+'/30')
                                    "VPN_IPB"=('169.254.19.'+$FourthOctet+'/30')
                                     "PAN_IP"=($PANs | ? { $_.Name -match 'VM300-B' }).Management
                                      }
                              }
         'RouteTable'=@{'Name'= $BaseName}
         'NETUTIL_A' =@{'Name'=('NETUTIL-'+$Temp+'-'+$VPC_Name+"-A")
                          'IP'= $NETUTILA_IPs[0]
                         'IPs'= $NETUTILA_IPs
                         'AMI'= $AMI.ImageId
                     'amiName'= $AMI.Name}
         'NETUTIL_B' =@{'Name'=('NETUTIL-'+$Temp+'-'+$VPC_Name+"-B")
                          'IP'= $NETUTILB_IPs[0]
                         'IPs'= $NETUTILB_IPs
                         'AMI'= $AMI.ImageId
                     'amiName'= $AMI.Name}
         'Subnets'   =  $Subnets
        }
}

#Display information and Prompt user to continue
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  $message  = 'Review Information';$choices  = '&Yes', '&No'
  $question = "Approve Creation of this VPC?`n`n"+
      " VPC: "+$VPC.Name+"`n"+
      "CIDR: "+$VPC.CIDR+"`n`nSunets:`n "+
      ($VPC.Subnets | %{ $_.AZ+"`t"+$_.CIDR+"`n" })
  if ( ($Host.UI.PromptForChoice($message, $question, $choices, 1)) -ne 0) {
    write-error "Review answered with no" -ErrorAction Stop
  }
  $Logging+= (Get-date -Format 'u')+": User chose to continue`n"
}

}

#Build
if (1 -eq 1) {#Using if statement to shirink sections in ISE
$Logging+= (Get-date -Format 'u')+": Starting to Create VPC`n"

Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Creating VPC Container and adding Tags") -PercentComplete 5
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  $VPC_obj = New-EC2Vpc -CidrBlock $VPC.CIDR @CommonOptions
  If (-not $VPC_obj.VpcId) { write-error "Failed to create VPC" -ErrorAction Stop }
  $VPC+= @{'objId'=$VPC_obj.VpcId}
  New-EC2Tag -Resource $VPC.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', ($VPC.Name))) @CommonOptions
  $Logging+= (Get-date -Format 'u')+": Created and Named VPC`n"
}

Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Setting up Security Groups") -PercentComplete 10
if (1 -eq 1) {#Using if statement to shirink sections in ISE{
  $sg_obj = Get-EC2SecurityGroup  -Filter @{ Name="vpc-id";Values=$VPC.objId} @CommonOptions
  If (-not $sg_obj.GroupId) { write-error "Failed to find default Security Group" -ErrorAction Stop }
  $VPC.Default_SG+= @{"objId"=$sg_obj.GroupId}
  New-EC2Tag -Resource $VPC.Default_SG.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.Default_SG.Name)) @CommonOptions
  Revoke-EC2SecurityGroupIngress -GroupId $VPC.Default_SG.objId -IpPermission $sg_obj.IpPermission @CommonOptions
  foreach ($Rule in $VPC.Default_SG.Rules) {
    ForEach ($Temp2 in $Rule.IpRanges) {
      $Temp3 = New-Object -TypeName Amazon.EC2.Model.IpRange
        $Temp3.CidrIp      = $Temp2
        $Temp3.Description = $Rule.Description
      $Temp = new-object Amazon.EC2.Model.IpPermission
        $Temp.IpProtocol = $Rule.IpProtocol
        $Temp.FromPort   = $Rule.FromPort
        $Temp.ToPort     = $Rule.ToPort
        $temp.Ipv4Ranges = $Temp3
      Grant-EC2SecurityGroupIngress -GroupId $VPC.Default_SG.objId -IpPermissions $Temp @CommonOptions
    }
  }
  $Logging+= (Get-date -Format 'u')+": Setup default securty group`n"

  #Create Tier Security Groups
  if (1 -eq 1) {#Using if statement to shirink sections in ISE{
    $sgs = @((New-EC2SecurityGroup @CommonOptions -VpcId $VPC.objId -Description 'Tier1 Default Security Group' -GroupName ($VPC.Name+'-Tier1')),
             (New-EC2SecurityGroup @CommonOptions -VpcId $VPC.objId -Description 'Tier2 Default Security Group' -GroupName ($VPC.Name+'-Tier2')),
             (New-EC2SecurityGroup @CommonOptions -VpcId $VPC.objId -Description 'Tier3 Default Security Group' -GroupName ($VPC.Name+'-Tier3')),
             (New-EC2SecurityGroup @CommonOptions -VpcId $VPC.objId -Description 'Tier4 Default Security Group' -GroupName ($VPC.Name+'-Tier4')))

    New-EC2Tag -Resource $SGs[0] -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', ($VPC.Name+'-Tier1'))) @CommonOptions

    $Temp = New-Object Amazon.EC2.Model.UserIdGroupPair
      $Temp.GroupId = $SGs[0]
    $Temp2 = new-object Amazon.EC2.Model.IpPermission
      $Temp2.UserIdGroupPair.Add($Temp)
      $Temp2.IpProtocol = -1
    Grant-EC2SecurityGroupIngress -GroupId $SGs[1] -IpPermissions $Temp2 @CommonOptions
    New-EC2Tag -Resource $SGs[1] -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', ($VPC.Name+'-Tier2'))) @CommonOptions

    $Temp = New-Object Amazon.EC2.Model.UserIdGroupPair
      $Temp.GroupId = $SGs[1]
    $Temp2 = new-object Amazon.EC2.Model.IpPermission
      $Temp2.UserIdGroupPair.Add($Temp)
      $Temp2.IpProtocol = -1
    Grant-EC2SecurityGroupIngress -GroupId $SGs[2] -IpPermissions $Temp2 @CommonOptions
    New-EC2Tag -Resource $SGs[2] -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', ($VPC.Name+'-Tier3'))) @CommonOptions

    $Temp = New-Object Amazon.EC2.Model.UserIdGroupPair
      $Temp.GroupId = $SGs[2]
    $Temp2 = new-object Amazon.EC2.Model.IpPermission
      $Temp2.UserIdGroupPair.Add($Temp)
      $Temp2.IpProtocol = -1
    Grant-EC2SecurityGroupIngress -GroupId $SGs[3] -IpPermissions $Temp2 @CommonOptions
    New-EC2Tag -Resource $SGs[3] -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', ($VPC.Name+'-Tier4'))) @CommonOptions

    $VPC+=@{'SecurityGroups'=$SGs}

    $Logging+= (Get-date -Format 'u')+": Created Tier Security Groups`n"
  }
}

Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Creating Redundant VGW/VPN in AWS and PAN") -PercentComplete 20
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  Write-Progress -ParentId 1 -id 2 -Activity ("Creating, associating, and naming AWS VGW") -PercentComplete 0
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $vgw_obj = New-EC2VpnGateway -AmazonSideAsn $VPC.VPN.ASN -Type ipsec.1 @CommonOptions
    If (-not $vgw_obj.VpnGatewayId) { write-error "Failed to create vgw" -ErrorAction Stop }
    $VPC.VPN+=@{'objId'=$vgw_obj.VpnGatewayId}
    New-EC2Tag -Resource $VPC.VPN.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.VPN.Name)) @CommonOptions
    $temp = Add-EC2VpnGateway -VpcId $VPC.objId -VpnGatewayId $VPC.VPN.objId @CommonOptions
    $Logging+= (Get-date -Format 'u')+": Created VGW`n"
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating Zone on Both PAN") -PercentComplete 5
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Data = '<entry name="'+$VPC.ZoneName+'"><network><layer3></layer3></network></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Zone_Location -Data $Data -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Zone" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating PAN to VPC Polling") -PercentComplete 10
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Data = '<entry name="'+$VPC.Name+'"><AWS-VPC><vpc-id>'+$VPC.objId+'</vpc-id><source>ec2.'+$CommonOptions.Region+'.amazonaws.com</source>'+
      '<access-key-id>'+$RO_AccessKey.ID+'</access-key-id><secret-access-key>'+$RO_AccessKey.Key+'</secret-access-key>'+
     '</AWS-VPC></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $vm_info_Location -Data $Data -Addresses ($VPC.VPN.Primary.PAN_IP,$VPC.VPN.Secondary.PAN_IP) -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create VPC polling" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating Primary VPN on AWS Side") -PercentComplete 15
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $options = (New-Object -TypeName Amazon.EC2.Model.VpnTunnelOptionsSpecification), (New-Object -TypeName Amazon.EC2.Model.VpnTunnelOptionsSpecification)
      $options[0].TunnelInsideCidr = $VPC.VPN.Primary.VPN_IPA
      $options[1].TunnelInsideCidr = $VPC.VPN.Primary.VPN_IPB
    $vpn_obj = New-EC2VpnConnection -CustomerGatewayId $VPC.VPN.Primary.CGW -Type ipsec.1 -VpnGatewayId $VPC.VPN.objId -Options_TunnelOption $options @CommonOptions
    If (-not $vpn_obj.VpnConnectionId) { write-error "Failed to create Primary VPN" -ErrorAction Stop }
    $VPC.VPN.Primary+=@{'objId'=$vpn_obj.VpnConnectionId}
    New-EC2Tag -Resource $VPC.VPN.Primary.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.VPN.Primary.Name)) @CommonOptions
    New-EC2Tag -Resource $VPC.VPN.Primary.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('PANMGMT', $VPC.VPN.Primary.PAN_IP)) @CommonOptions
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating PAN Tunnel Interface for Primary") -PercentComplete 20
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Tunnels=([xml]$vpn_obj.CustomerGatewayConfiguration).vpn_connection.ipsec_tunnel
    $Interface_A = 'tunnel.'+(1000+$VPC.Number)
    $Interface_B = 'tunnel.'+(2000+$VPC.Number)
    $Location = '/config/devices/entry[@name="localhost.localdomain"]/network/interface/tunnel/units'
    $Data = '<entry name="'+$Interface_A+'"><ip><entry name="'+$Tunnels[0].customer_gateway.tunnel_inside_address.ip_address+'/30"/></ip>'+
               '<comment>'+$VPC.Name+'-1</comment>'+$Interface_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary Tunnel for A" -ErrorAction Stop }
    $Data = '<entry name="'+$Interface_B+'"><ip><entry name="'+$Tunnels[1].customer_gateway.tunnel_inside_address.ip_address+'/30"/></ip>'+
               '<comment>'+$VPC.Name+'-2</comment>'+$Interface_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary Tunnel A" -ErrorAction Stop }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Adding PAN Interface to sub-components for Primary") -PercentComplete 25
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    ForEach ($Location in (($Router_Location+'/interface'),($Zone_Location+'/entry[@name="'+$VPC.ZoneName+'"]/network/layer3'),$vsys_Import)) {
      ForEach ($Interface in ($Interface_A,$Interface_B)) {
        $Data = '<member>'+$Interface+'</member>'
        $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    }}
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Adding Primary PAN IKE Settings") -PercentComplete 35
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Location = '/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway'
    $Data = '<entry name="'+$VPC.Name+'-1"><authentication><pre-shared-key><key>'+$Tunnels[0].ike.pre_shared_key+'</key></pre-shared-key></authentication>'+
            '<peer-address><ip>'+$Tunnels[0].vpn_gateway.tunnel_outside_address.ip_address+'</ip></peer-address>'+$IKE_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary IKE for A" -ErrorAction Continue }
    $Data = '<entry name="'+$VPC.Name+'-2"><authentication><pre-shared-key><key>'+$Tunnels[1].ike.pre_shared_key+'</key></pre-shared-key></authentication>'+
            '<peer-address><ip>'+$Tunnels[1].vpn_gateway.tunnel_outside_address.ip_address+'</ip></peer-address>'+$IKE_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create secondary IKE for A" -ErrorAction Continue }
  }
  
  Write-Progress -ParentId 1 -id 2 -Activity ("Creating Primary PAN IPsec Tunnel") -PercentComplete 40
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Location = '/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec'
    $Data = '<entry name="'+$VPC.Name+'-1"><auto-key><ike-gateway><entry name="'+$VPC.Name+'-1"/></ike-gateway><ipsec-crypto-profile>AWS</ipsec-crypto-profile></auto-key>'+
              '<tunnel-interface>'+$Interface_A+'</tunnel-interface><tunnel-monitor><enable>no</enable></tunnel-monitor></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary IPsec for A" -ErrorAction Continue }
    $Data = '<entry name="'+$VPC.Name+'-2"><auto-key><ike-gateway><entry name="'+$VPC.Name+'-2"/></ike-gateway><ipsec-crypto-profile>AWS</ipsec-crypto-profile></auto-key>'+
              '<tunnel-interface>'+$Interface_B+'</tunnel-interface><tunnel-monitor><enable>no</enable></tunnel-monitor></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary IPsec for A" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Adding Primary PAN BGP peering") -PercentComplete 45
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Location  = $Router_Location+'/protocol/bgp/peer-group/entry[@name="SubscriberVPCs"]/peer'
    $Data = '<entry name="'+$VPC.Name+'-1"><peer-address><ip>'+$Tunnels[0].vpn_gateway.tunnel_inside_address.ip_address+'</ip></peer-address>'+
            '<local-address><interface>'+$Interface_A+'</interface></local-address>'+
            '<peer-as>'+$VPC.VPN.ASN+'</peer-as></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary BGP peer for A" -ErrorAction Continue }
    $Data = '<entry name="'+$VPC.Name+'-2"><peer-address><ip>'+$Tunnels[1].vpn_gateway.tunnel_inside_address.ip_address+'</ip></peer-address>'+
            '<local-address><interface>'+$Interface_B+'</interface></local-address>'+
            '<peer-as>'+$VPC.VPN.ASN+'</peer-as></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary BGP Peer for A" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Commiting changes for Primary PAN") -PercentComplete 50
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $rc = Invoke-PANCommit -Tag $CommonOptions.ProfileName -Addresses $VPC.VPN.Primary.PAN_IP -SkipCertificateCheck
    $Logging+= (Get-date -Format 'u')+": Setup PAN-A`n"
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating Secondary VPN on AWS Side") -PercentComplete 55
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $options = (New-Object -TypeName Amazon.EC2.Model.VpnTunnelOptionsSpecification), (New-Object -TypeName Amazon.EC2.Model.VpnTunnelOptionsSpecification)
      $options[0].TunnelInsideCidr = $VPC.VPN.Secondary.VPN_IPA
      $options[1].TunnelInsideCidr = $VPC.VPN.Secondary.VPN_IPB
    $vpn_obj = New-EC2VpnConnection -CustomerGatewayId $VPC.VPN.Secondary.CGW -Type ipsec.1 -VpnGatewayId $VPC.VPN.objId -Options_TunnelOption $options @CommonOptions
    If (-not $vpn_obj.VpnConnectionId) { write-error "Failed to create Secondary VPN" -ErrorAction Stop }
    $VPC.VPN.Secondary+=@{'objId'=$vpn_obj.VpnConnectionId}
    New-EC2Tag -Resource $VPC.VPN.Secondary.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.VPN.Secondary.Name)) @CommonOptions
    New-EC2Tag -Resource $VPC.VPN.Secondary.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('PANMGMT', $VPC.VPN.Secondary.PAN_IP)) @CommonOptions
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating PAN Tunnel Interface for Secondary") -PercentComplete 60
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Tunnels=([xml]$vpn_obj.CustomerGatewayConfiguration).vpn_connection.ipsec_tunnel
    $Interface_A = 'tunnel.'+(1000+$VPC.Number)
    $Interface_B = 'tunnel.'+(2000+$VPC.Number)
    $Location = '/config/devices/entry[@name="localhost.localdomain"]/network/interface/tunnel/units'
    $Data = '<entry name="'+$Interface_A+'"><ip><entry name="'+$Tunnels[0].customer_gateway.tunnel_inside_address.ip_address+'/30"/></ip>'+
               '<comment>'+$VPC.Name+'-1</comment>'+$Interface_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary Interface for B" -ErrorAction Stop }
    $Data = '<entry name="'+$Interface_B+'"><ip><entry name="'+$Tunnels[1].customer_gateway.tunnel_inside_address.ip_address+'/30"/></ip>'+
               '<comment>'+$VPC.Name+'-2</comment>'+$Interface_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary Interface for B" -ErrorAction Stop }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Adding PAN Interface to sub-components for Secondary") -PercentComplete 70
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    ForEach ($Location in (($Router_Location+'/interface'),($Zone_Location+'/entry[@name="'+$VPC.ZoneName+'"]/network/layer3'),$vsys_Import)) {
      ForEach ($Interface in ($Interface_A,$Interface_B)) {
        $Data = '<member>'+$Interface+'</member>'
        $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    }}
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Adding Secondary PAN IKE Settings") -PercentComplete 80
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Location = '/config/devices/entry[@name="localhost.localdomain"]/network/ike/gateway'
    $Data = '<entry name="'+$VPC.Name+'-1"><authentication><pre-shared-key><key>'+$Tunnels[0].ike.pre_shared_key+'</key></pre-shared-key></authentication>'+
            '<peer-address><ip>'+$Tunnels[0].vpn_gateway.tunnel_outside_address.ip_address+'</ip></peer-address>'+$IKE_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary IKE for B" -ErrorAction Continue }
    $Data = '<entry name="'+$VPC.Name+'-2"><authentication><pre-shared-key><key>'+$Tunnels[1].ike.pre_shared_key+'</key></pre-shared-key></authentication>'+
            '<peer-address><ip>'+$Tunnels[1].vpn_gateway.tunnel_outside_address.ip_address+'</ip></peer-address>'+$IKE_Common+"</entry>"
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary IKE for B" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Creating Secondary PAN IPsec Tunnel") -PercentComplete 85
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Location = '/config/devices/entry[@name="localhost.localdomain"]/network/tunnel/ipsec'
    $Data = '<entry name="'+$VPC.Name+'-1"><auto-key><ike-gateway><entry name="'+$VPC.Name+'-1"/></ike-gateway><ipsec-crypto-profile>AWS</ipsec-crypto-profile></auto-key>'+
              '<tunnel-interface>'+$Interface_A+'</tunnel-interface><tunnel-monitor><enable>no</enable></tunnel-monitor></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary IPsec for A" -ErrorAction Continue }
    $Data = '<entry name="'+$VPC.Name+'-2"><auto-key><ike-gateway><entry name="'+$VPC.Name+'-2"/></ike-gateway><ipsec-crypto-profile>AWS</ipsec-crypto-profile></auto-key>'+
              '<tunnel-interface>'+$Interface_B+'</tunnel-interface><tunnel-monitor><enable>no</enable></tunnel-monitor></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary IPsec for B" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Adding Primary PAN BGP peering") -PercentComplete 90
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $Location  = $Router_Location+'/protocol/bgp/peer-group/entry[@name="SubscriberVPCs"]/peer'
    $Data = '<entry name="'+$VPC.Name+'-1"><peer-address><ip>'+$Tunnels[0].vpn_gateway.tunnel_inside_address.ip_address+'</ip></peer-address>'+
            '<local-address><interface>'+$Interface_A+'</interface></local-address>'+
            '<peer-as>'+$VPC.VPN.ASN+'</peer-as></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Primary BGP Peer for B" -ErrorAction Continue }
    $Data = '<entry name="'+$VPC.Name+'-2"><peer-address><ip>'+$Tunnels[1].vpn_gateway.tunnel_inside_address.ip_address+'</ip></peer-address>'+
            '<local-address><interface>'+$Interface_B+'</interface></local-address>'+
            '<peer-as>'+$VPC.VPN.ASN+'</peer-as></entry>'
    $rc = Set-PANConfig -Tag $CommonOptions.ProfileName -XPath $Location -Data $Data -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $rc = $rc | ? { $_.status -ne 'success'}
    If ($rc) { write-error "Failed to create Secondary BGP Peer for B" -ErrorAction Continue }
  }

  Write-Progress -ParentId 1 -id 2 -Activity ("Commiting changes for Primary PAN") -PercentComplete 95
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $rc = Invoke-PANCommit -Tag $CommonOptions.ProfileName -Addresses $VPC.VPN.Secondary.PAN_IP -SkipCertificateCheck
    $Logging+= (Get-date -Format 'u')+": Setup PAN-B`n"
  }
  Write-Progress -ParentId 1 -id 2 -Completed -Activity "Completed"
}

#*add* Need to handle both types and prompt  name default ACL
Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Creating Tier ACLs") -PercentComplete 50
if (1 -eq 1) {#Using if statement to shirink sections in ISE
 #$WaterfallType = 'Standard'
 #$WaterfallType = 'Tier1-to-Tier4'

 $Temp = Get-EC2NetworkAcl @CommonOptions -Filter @{ Name="vpc-id";Values=$VPC.objId}
 New-EC2Tag -Resource $Temp.NetworkAclId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $Basename)) @CommonOptions
 $ACL_objs = @()
 ForEach ($i in 1..4) {
  $acl_objs += @( (New-EC2NetworkAcl -VpcId $VPC_obj.VpcId @CommonOptions) )
  New-EC2Tag -Resource $acl_objs[($i - 1)].NetworkAclId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', "$Basename-Tier$i")) @CommonOptions
 }

 #Add Tier 1 and 2 subnet to Tier 1 ACL
 $AddThese = $Subnets | ? { ($_.Name -match 'TIER1' -or $_.Name -match 'TIER2') }
 $i=0
 foreach ($Subnet in $AddThese) {
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $false -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[0].NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $true  -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[0].NetworkAclId @CommonOptions
 $i++}

 #Add Tier 1 to 3 subnet to Tier 2 ACL
 $AddThese = $Subnets | ? { ($_.Name -match 'TIER1' -or $_.Name -match 'TIER2' -or $_.Name -match 'TIER3') }
 $i=0
 foreach ($Subnet in $AddThese) {
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $false -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[1].NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $true  -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[1].NetworkAclId @CommonOptions
 $i++}

 #Add Tier 2 to 4 subnet to Tier 3 ACL
 $AddThese = $Subnets | ? { ($_.Name -match 'TIER2' -or $_.Name -match 'TIER3' -or $_.Name -match 'TIER4') }
 $i=0
 foreach ($Subnet in $AddThese) {
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $false -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[2].NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $true  -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[2].NetworkAclId @CommonOptions
 $i++}

 #Add Tier 3 and 4 subnet to Tier 4 ACL
 $AddThese = $Subnets | ? { ($_.Name -match 'TIER3' -or $_.Name -match 'TIER4') }
 $i=0
 foreach ($Subnet in $AddThese) {
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $false -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[3].NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock $Subnet.CIDR -Egress $true  -Protocol -1 -RuleAction allow -RuleNumber (100+$i) -NetworkAclId $acl_objs[3].NetworkAclId @CommonOptions
 $i++}

 ForEach ($acl in $acl_objs) {
  New-EC2NetworkAclEntry -CidrBlock $VPC.CIDR   -Egress $false -Protocol -1 -RuleAction deny  -RuleNumber (200) -NetworkAclId $acl.NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock $VPC.CIDR   -Egress $true  -Protocol -1 -RuleAction deny  -RuleNumber (200) -NetworkAclId $acl.NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock '0.0.0.0/0' -Egress $false -Protocol -1 -RuleAction allow -RuleNumber (300) -NetworkAclId $acl.NetworkAclId @CommonOptions
  New-EC2NetworkAclEntry -CidrBlock '0.0.0.0/0' -Egress $true  -Protocol -1 -RuleAction allow -RuleNumber (300) -NetworkAclId $acl.NetworkAclId @CommonOptions
 }
 $Logging+= (Get-date -Format 'u')+": Created ACLs`n"
}

Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Creating Subnets") -PercentComplete 60
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  $VPC.Subnets = foreach ($Subnet in $VPC.Subnets) {
    $Subnet_obj = New-EC2Subnet -VpcId $VPC.objId -CidrBlock $Subnet.CIDR -AvailabilityZone $Subnet.AZ @CommonOptions
    $Subnet+=@{'objId' = $Subnet_obj.SubnetId }
    $Subnet
  }
  foreach ($Subnet in $VPC.Subnets) {
    New-EC2Tag -Resource $Subnet.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $Subnet.Name)) @CommonOptions
  }
  $Logging+= (Get-date -Format 'u')+": Created Subnets`n"

  #Associate Subnets to ACLs
  ForEach ($acl in (Get-EC2NetworkAcl -Filter @{ Name="vpc-id";Values=$VPC.objId} @CommonOptions)) {
    ForEach ($Assoc in $acl.Associations) {
      $NetName = ($VPC.Subnets | ? { $_.objId -eq $Assoc.SubnetId }).Name
      if ($null -ne $NetName -and $NetName -ne '') {
       switch ($NetName.Substring($NetName.Length-7,5)) {
        'TIER1' {$rc = Set-EC2NetworkAclAssociation -AssociationId $Assoc.NetworkAclAssociationId -NetworkAclId $ACL_objs[0].NetworkAclId @CommonOptions}
        'TIER2' {$rc = Set-EC2NetworkAclAssociation -AssociationId $Assoc.NetworkAclAssociationId -NetworkAclId $ACL_objs[1].NetworkAclId @CommonOptions}
        'TIER3' {$rc = Set-EC2NetworkAclAssociation -AssociationId $Assoc.NetworkAclAssociationId -NetworkAclId $ACL_objs[2].NetworkAclId @CommonOptions}
        'TIER4' {$rc = Set-EC2NetworkAclAssociation -AssociationId $Assoc.NetworkAclAssociationId -NetworkAclId $ACL_objs[3].NetworkAclId @CommonOptions}
        default {"bad"}
       }
      }
    }
  }
  $Logging+= (Get-date -Format 'u')+": Assigned ACLs to subnets`n"
}

#*add* Net Utils to monitoring
Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Creating Test/Utility VMs") -PercentComplete 70
if (1 -eq 1) {#Using if statement to shirink sections in ISE {
  Write-Progress -ParentId 1 -id 2 -Activity ("Creating "+$VPC.NETUTIL_A.Name) -PercentComplete 20
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $vm_obj = New-EC2Instance -ImageId $AMI.ImageId -MinCount 1 -MaxCount 1 -KeyName $KeyName -SecurityGroupId $VPC.Default_SG.objId -PrivateIpAddress $VPC.NETUTIL_A.IP  -InstanceType t3a.nano -SubnetId $VPC.Subnets[0].objId @CommonOptions
    $VPC.NETUTIL_A+=@{'objId'=$vm_obj.Instances[0].InstanceId}
    #$VPC.NETUTIL_A+=@{'IP'=$vm_obj.Instances[0].PrivateIpAddress;'objId'=$vm_obj.Instances[0].InstanceId}
    New-EC2Tag -Resource $VPC.NETUTIL_A.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @("Name",$VPC.NETUTIL_A.Name)) @CommonOptions
    New-EC2Tag -Resource $VPC.NETUTIL_A.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @("Owner","Network")) @CommonOptions
    Start-Process cmd ("/c ping -t "+$VPC.NETUTIL_A.IP)
    $Logging+= (Get-date -Format 'u')+": Created NETUTIL A`n"
  }
  Write-Progress -ParentId 1 -id 2 -Activity ("Creating "+$VPC.NETUTIL_B.Name) -PercentComplete 40
  if (1 -eq 1) {#Using if statement to shirink sections in ISE
    $vm_obj = New-EC2Instance -ImageId $AMI.ImageId -MinCount 1 -MaxCount 1 -KeyName $KeyName -SecurityGroupId $VPC.Default_SG.objId -PrivateIpAddress $VPC.NETUTIL_B.IP -InstanceType t3a.nano -SubnetId $VPC.Subnets[3].objId @CommonOptions
    $VPC.NETUTIL_B+=@{'objId'=$vm_obj.Instances[0].InstanceId}
    #$VPC.NETUTIL_B+=@{'IP'=$vm_obj.Instances[0].PrivateIpAddress;'objId'=$vm_obj.Instances[0].InstanceId}
    New-EC2Tag -Resource $VPC.NETUTIL_B.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @("Name",$VPC.NETUTIL_B.Name)) @CommonOptions
    New-EC2Tag -Resource $VPC.NETUTIL_B.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @("Owner","Network")) @CommonOptions
    Start-Process cmd ("/c ping -t "+$VPC.NETUTIL_B.IP)
    $Logging+= (Get-date -Format 'u')+": Created NETUTIL B`n"
  }
  Write-Progress -ParentId 1 -id 2 -Activity ("Waiting till VMs are running") -PercentComplete 60
  if (1 -eq 1 ) {#Using if statement to shirink sections in ISE
    ForEach ($NETUTIL in @($VPC.NETUTIL_A,$Vpc.NETUTIL_B)) {
      $Instance = Get-EC2Instance @CommonOptions -InstanceId $NETUTIL.objId
      While ($Instance.Instances[0].State.Name -ne 'running') {
        sleep -Milliseconds 500
        $Instance = Get-EC2Instance @CommonOptions -InstanceId $NETUTIL.objId
      }
    }
    $Logging+= (Get-date -Format 'u')+": VMs running, configuring additional settings`n"
  }
  Write-Progress -ParentId 1 -id 2 -Activity ("Naming vm sub components") -PercentComplete 70
  if (1 -eq 1 ) {#Using if statement to shirink sections in ISE
    ForEach ($NETUTIL in @($VPC.NETUTIL_A,$Vpc.NETUTIL_B)) {
      $NetInt_Obj = Get-EC2NetworkInterface @CommonOptions -Filter @{ Name="attachment.instance-id";Values=$NETUTIL.objId }
      New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $NETUTIL.Name)) @CommonOptions
      $Vol_obj = Get-EC2Volume @CommonOptions -Filter @{ Name="attachment.instance-id";Values=$NETUTIL.objId }
      New-EC2Tag -Resource $Vol_Obj.VolumeId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $NETUTIL.Name)) @CommonOptions
    }
    $Logging+= (Get-date -Format 'u')+": Named automatically created parts`n"
  }
  Write-Progress -ParentId 1 -id 2 -Activity ("Creating and attaching extra network testing interfaces") -PercentComplete 80
  if (1 -eq 1 ) {#Using if statement to shirink sections in ISE
    $NetInt_Obj = New-EC2NetworkInterface @CommonOptions -Group $VPC.Default_SG.objId -subnet $VPC.Subnets[2].objId -PrivateIpAddress $VPC.NETUTIL_A.IPs[1]
    New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.NETUTIL_A.Name)) @CommonOptions
    #nano limited to 2 interface
    #$attach = Add-EC2NetworkInterface -InstanceId $VPC.NETUTIL_A.objId -NetworkInterfaceId $NetInt_Obj.NetworkInterfaceId -DeviceIndex 2 @CommonOptions

    $NetInt_Obj = New-EC2NetworkInterface @CommonOptions -Group $VPC.Default_SG.objId -subnet $VPC.Subnets[4].objId -PrivateIpAddress $VPC.NETUTIL_A.IPs[2]
    New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.NETUTIL_A.Name)) @CommonOptions
    $attach = Add-EC2NetworkInterface -InstanceId $VPC.NETUTIL_A.objId -NetworkInterfaceId $NetInt_Obj.NetworkInterfaceId -DeviceIndex 1 @CommonOptions

    $NetInt_Obj = New-EC2NetworkInterface @CommonOptions -Group $VPC.Default_SG.objId -subnet $VPC.Subnets[6].objId -PrivateIpAddress $VPC.NETUTIL_A.IPs[3]
    New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.NETUTIL_A.Name)) @CommonOptions
    #nano limited to 2 interface
    #$attach = Add-EC2NetworkInterface -InstanceId $VPC.NETUTIL_A.objId -NetworkInterfaceId $NetInt_Obj.NetworkInterfaceId -DeviceIndex 3 @CommonOptions

    $Logging+= (Get-date -Format 'u')+": Created and attached extra nics on NETUTIL A`n"
  }
  Write-Progress -ParentId 1 -id 2 -Activity ("Creating and attaching extra network testing interfaces for AZB") -PercentComplete 90
  if (1 -eq 1 ) {#Using if statement to shirink sections in ISE
    $NetInt_Obj = New-EC2NetworkInterface @CommonOptions -Group $VPC.Default_SG.objId -subnet $VPC.Subnets[1].objId -PrivateIpAddress $VPC.NETUTIL_B.IPs[1]
    New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.NETUTIL_B.Name)) @CommonOptions
    #nano limited to 2 interface
    #$attach = Add-EC2NetworkInterface -InstanceId $VPC.NETUTIL_B.objId -NetworkInterfaceId $NetInt_Obj.NetworkInterfaceId -DeviceIndex 3 @CommonOptions

    $NetInt_Obj = New-EC2NetworkInterface @CommonOptions -Group $VPC.Default_SG.objId -subnet $VPC.Subnets[5].objId -PrivateIpAddress $VPC.NETUTIL_B.IPs[2]
    New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.NETUTIL_B.Name)) @CommonOptions
    #nano limited to 2 interface
    #$attach = Add-EC2NetworkInterface -InstanceId $VPC.NETUTIL_B.objId -NetworkInterfaceId $NetInt_Obj.NetworkInterfaceId -DeviceIndex 2 @CommonOptions

    $NetInt_Obj = New-EC2NetworkInterface @CommonOptions -Group $VPC.Default_SG.objId -subnet $VPC.Subnets[7].objId -PrivateIpAddress $VPC.NETUTIL_B.IPs[3]
    New-EC2Tag -Resource $NetInt_Obj.NetworkInterfaceId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.NETUTIL_B.Name)) @CommonOptions
    $attach = Add-EC2NetworkInterface -InstanceId $VPC.NETUTIL_B.objId -NetworkInterfaceId $NetInt_Obj.NetworkInterfaceId -DeviceIndex 1 @CommonOptions
    $Logging+= (Get-date -Format 'u')+": Created and attached extra nics on NETUTIL B`n"
  }
  Write-Progress -ParentId 1 -id 2 -Completed -Activity "Complete"
}

Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Waiting for VGW to become available...") -PercentComplete 80
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  $Logging+= (Get-date -Format 'u')+": Waiting for VGW`n"
  if (-not ($vgw_obj.State.Value -eq 'available') ) { $vgw_obj = Get-EC2VpnGateway -Filter @{ Name="attachment.vpc-id";Values=$VPC.objId} @CommonOptions }
  $i = 1;While ( ($i -lt 120) -and -not ($vgw_obj.State.Value -eq 'available') ) {
    "Waiting for vgw to become available to enable routing"
    sleep 5
    $vgw_obj = Get-EC2VpnGateway -Filter @{ Name="attachment.vpc-id";Values=$VPC.objId} @CommonOptions
    if ( $vgw_obj.State.Value -eq 'available' ) { $i = 1000 }
    if ( $i -eq 6 -or ($i % 24) -eq 0 ) {
      if ( ($Host.UI.PromptForChoice('Waiting for VGW', 'Do you still want to wait?', ('&Yes', '&No'), 1)) -ne 0) {
        $i = 1000
        $Logging+= (Get-date -Format 'u')+": User chose to cancel wait`n"
      }
    }
  $i++}
  $Logging+= (Get-date -Format 'u')+": Done Waiting`n"
}

Write-Progress -id 1 -Activity ("Creating VPC - "+$VPC.Name) -Status ("Enabling BGP Route Propigation in AWS") -PercentComplete 90
if (1 -eq 1) {#Using if statement to shirink sections in ISE
  $rt_obj = Get-EC2RouteTable -Filter @{ Name="vpc-id";Values=$VPC_obj.VpcId} @CommonOptions
  $VPC.RouteTable+=@{'objId'=$rt_obj.RouteTableId}
  New-EC2Tag -Resource $VPC.RouteTable.objId -Tag (New-Object -TypeName Amazon.EC2.Model.Tag -ArgumentList @('Name', $VPC.RouteTable.Name)) @CommonOptions
  if ( $vgw_obj.State.Value -eq 'available' ) {
    $rc = Enable-EC2VgwRoutePropagation -GatewayId $VPC.VPN.objId -RouteTableId $rt_obj.RouteTableId @commonOptions
    $Logging+= (Get-date -Format 'u')+": enabled routing`n"
   } else {
    "You will need to manually enable route propigation"
    $Logging+= (Get-date -Format 'u')+": Manual route update needed`n"
  }
}

#Save Creation data
$Logging+= (Get-date -Format 'u')+": Done Creating VPC`n"
$VPC+=@{'Log'=$Logging}
$VPC |  Export-Clixml ("$PSScriptRoot\Built\"+$(Get-Date -Format 'yyyyMMdd_HHmmss')+"_Build_"+$env:UserName+"_"+$VPC.Name+".xml")
}
