### This Script pulls the F5 info in an array or custom ps objects
# Check for Required Modules
$requiredModules = @('F5-LTM')
foreach ( $module in $requiredModules )  {
  if ( -not (Get-Module -ListAvailable $Module )) { 
    Install-Module -Name $Module -Scope CurrentUser
  }
  Import-Module $module
}

#Get Credentials
if (-not $f5_cred) {
  $f5_cred = Get-Credential
}

## List of F5 to gather data from
$F5_List = @('192.0.2.11','192.0.2.21')

#Catch Data in this variable
$VS = foreach ( $F5_IP in $F5_List )  {
  #Logon to F5
  $Session1 = New-F5Session -LTMName $F5_IP -LTMCredentials $f5_cred -PassThru
  #Get List of virtual Servers
  $VS = Get-VirtualServer -F5Session $Session1
  for ($i = 0; $i -lt $VS.Count; $i++) {
    if ($VS[$i].pool.Length -gt 1) {
      #If there is a pool, get the pool and its members
      $Pool = Get-Pool -name $VS[$i].pool -F5Session $Session1
      $members = $pool | Get-PoolMember -F5Session $Session1

      #when there is only one member, the function returns the object, need an array
      If ($members.count -lt 1) {$members = @($members) }

      for ($i2 = 0; $i2 -lt $members.count; $i2++) {
        #Format Data
        if ($members[$i2].name -match "^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(%[0-9]{1,4})*:([0-9]{1,5})$") {
          #Name is an IP
          $Name = $Matches[1]
          $Address = $members[$i2].address.Split("%")[0]
          $Port = $Matches[3]
        } elseif (($members[$i2].name -match "^([a-zA-Z0-9.\-]*)(%[0-9]{1,4})*:([0-9]{1,5})$")) {
          #Name looks like a hostname
          $Name = $Matches[1]
          $Address = $members[$i2].address.Split("%")[0]
          $Port = $Matches[3]
        } else {
          #not sure what it is
          $Name = $members[$i2].name
          $Address = $members[$i2].address.Split("%")[0]
          $Port = $members[$i2].name
        }
        #Filter data
        $members[$i2] = [PSCustomObject]@{
          Name = $Name
          Address = $Address
          Port = $Port
          State = $pool_Member[$i2].state
          Pool = $Pool.name
        }
      }
      
      #Format Data
      If ($VS[$i].destination -match "^/$($VS[$i].partition)/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(%[0-9]{1,4})*:([0-9]{1,5})$") {
        #Destination is an IP/port (maybe vlan)
        $Address = $Matches[1]
        $Port = $Matches[3]
      } else {
        #Not sure what it is
        $Address = $VS[$i].destination
        $Port = $VS[$i].destination
      }
      #Filter data
      $VS[$i] = [PSCustomObject]@{
        Name = $VS[$i].name
        Address = $Address
        Port = $Port
        Pool = $Pool.name
        Members = $members
        Balance = $Pool.loadBalancingMode
        Protocol = $VS[$i].ipProtocol
        Profiles = $VS[$i].profilesReference.items.name -join ','
        Rules = $VS[$i].rules -join ','
      }
    } else {
      #Doesn't have a pool, less to gather and return
      If ($VS[$i].destination -match "^/$($VS[$i].partition)/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(%[0-9]{1,4})*:([0-9]{1,5})$") {
        $Address = $Matches[1]
        $Port = $Matches[3]
      } else {
        $Address = $VS[$i].destination
        $Port = $VS[$i].destination
      }
      
      $VS[$i] = [PSCustomObject]@{
        Name = $VS[$i].name
        Address = $Address
        Port = $Port
        Protocol = $VS[$i].ipProtocol
        Profiles = $VS[$i].profilesReference.items.name -join ','
        Rules = $VS[$i].rules -join ','
        F5 = $F5_IP
      }
    }
  }
  $VS
}

#$vs = $vs | select -Unique *
#$redir = $vs | ?{$_.rules -eq '/Common/_sys_https_redirect'}
#$vs = $vs | ?{$_.rules -ne '/Common/_sys_https_redirect'}

#$VS.members | Export-Csv -Path 'pools.csv'
#$VS | Export-Csv -Path 'virtualservers.csv'
#$redir | Export-Csv -Path 'redirect.csv'
