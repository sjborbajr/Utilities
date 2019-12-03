Param (
     [string]$File,
     [switch]$Fix = $false
)
#################################################################################################
Function Get-IniContent {  
    <#  
    .Synopsis  
        Gets the content of an INI file  
          
    .Description  
        Gets the content of an INI file and returns it as a hashtable  
          
    .Notes  
        Author        : Oliver Lipkau <oliver@lipkau.net>  
        Blog        : http://oliver.lipkau.net/blog/  
        Source        : https://github.com/lipkau/PsIni 
                      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91 
        Version        : 1.0 - 2010/03/12 - Initial release  
                      1.1 - 2014/12/11 - Typo (Thx SLDR) 
                                         Typo (Thx Dave Stiff) 
          
        #Requires -Version 2.0  
          
    .Inputs  
        System.String  
          
    .Outputs  
        System.Collections.Hashtable  
          
    .Parameter FilePath  
        Specifies the path to the input file.  
          
    .Example  
        $FileContent = Get-IniContent "C:\myinifile.ini"  
        -----------  
        Description  
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent  
      
    .Example  
        $inifilepath | $FileContent = Get-IniContent  
        -----------  
        Description  
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent  
      
    .Example  
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini"  
        C:\PS>$FileContent["Section"]["Key"]  
        -----------  
        Description  
        Returns the key "Key" of the section "Section" from the C:\settings.ini file  
          
    .Link  
        Out-IniFile  
    #>  
      
    [CmdletBinding()]  
    Param(  
        [ValidateNotNullOrEmpty()]  
        [ValidateScript({(Test-Path $_)})]  
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]  
        [string]$FilePath  
    )  
      
    Begin  
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}  
          
    Process  
    {  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"  
              
        $ini = @{}  
        switch -regex -file $FilePath  
        {  
            "^\[(.+)\]$" # Section  
            {  
                $section = $matches[1]  
                $ini[$section] = @{}  
                $CommentCount = 0  
            }  
            "^(;.*)$" # Comment  
            {  
                if (!($section))  
                {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $value = $matches[1]  
                $CommentCount = $CommentCount + 1  
                $name = "Comment" + $CommentCount  
                $ini[$section][$name] = $value  
            }   
            "(.+?)\s*=\s*(.*)" # Key  
            {  
                if (!($section))  
                {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $name,$value = $matches[1..2]  
                $ini[$section][$name] = $value  
            }  
        }  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"  
        Return $ini  
    }  
          
    End  
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}  
} 
#################################################################################################
#https://www.irs.gov/privacy-disclosure/nessus-audit-files
#https://www.irs.gov/pub/irs-utl/safeguards-windows-2016.audit
if (-not $File) {
  if ($PSScriptRoot) {$ScriptRoot = $PSScriptRoot} else {$ScriptRoot = ".\"}
  $Temp = (Get-WMIObject win32_operatingsystem).name
  if ($Temp.ToLower() -match "windows 10") {
    $File = "win10.audit" #HASH E15D67482B0360837FD2E20FEFBF7E4A9D5BA2C42CB161D2D883ADF2EB4E0514
  } elseif ($Temp.ToLower() -match "server 2016") {
    $File = "safeguards-windows-2016.audit" #HASH 0D4F76EAFFEFDA16DD08961B9DBDCD0D7B310338BD535965944C9B32D8E4E4D9
  }
  if (-not $File) {Write-Error "No default audit file name for OS" -ErrorAction Stop}
  if (Test-Path ($ScriptRoot+$File)) {#Script Directory
    $File = $ScriptRoot+$File
  } elseif (Test-Path "$env:userprofile\Downloads\$File") {#current directory
    $File = "$env:userprofile\Downloads\$File"
  } elseif (Test-Path ".\$File") {#Users download directory
    $File = ".\$File"
  } else {#atempt to download
    wget "https://www.irs.gov/pub/irs-utl/$File" -OutFile $File
    $File = ".\$File"
  }
}
if (-not (Test-Path $File)) {
  write-error "Could not find an audit file" -ErrorAction Stop
}

#Readfile and store hash
$FileData = Get-Content $File
$FileHash = (Get-FileHash $File -Algorithm SHA256).Hash

#Override Data in File based on it's hash
$Overrides = @{
  '0D4F76EAFFEFDA16DD08961B9DBDCD0D7B310338BD535965944C9B32D8E4E4D9' = @{
     "18.3.3" = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" #File had wrong reg path
     "2.2.17" = 'Guests" && "Local account' #File had nessus feature that wasn't implemented in this script
     "2.2.25" = 'administrators" && "local service" && "network service" && "service' #Script doesn't handle the "or" used in this
     "2.2.35" = 'administrators" && "WdiServiceHost' #Script doesn't handle the "or" used in this
  }
  'E15D67482B0360837FD2E20FEFBF7E4A9D5BA2C42CB161D2D883ADF2EB4E0514' = @{
     "2.2.33" = 'Administrators" && "WdiServiceHost' #Script doesn't handle the "or" used in this
     "2.2.2"  = 'Administrators" && "Users' #This is a more restrictive than the SCSEM, better for win 10
  }
}

#Initialize Lists
$Failed = @()
$Passed = @()
$Skipped = @()
$AuditPolicy = @{}

#Harvest Nessus Custom Itmes from audit file
$i = 0
$Items = while ($i -le $FileData.Count) {
  if ($FileData[$i] -match "<custom_item>") {
    $i++
    $Item = @{}
    $In_Quote = $False
    while ($FileData[$i] -notmatch "</custom_item>"){
      #Create hashtable and add key/values for each item
      if ($In_Quote) {
        $Temp_Value+=" "+$FileData[$i].Trim()
      } else {
        $Temp_ix    = $FileData[$i].IndexOf(":")
        $Temp_Key   = $FileData[$i].Substring(0,$Temp_ix).Trim()
        $Temp_Value = $FileData[$i].Substring($Temp_ix+1,$FileData[$i].Length-$Temp_ix-1).Trim()
        if ($Temp_Value.Substring(0,1) -eq '"') {
            $In_Quote = $True
            $Temp_Value = $Temp_Value.Substring(1,$Temp_Value.Length - 1)
        }
      }
      If ($In_Quote -and $Temp_Value.Substring($Temp_Value.Length-1) -eq '"') {
        $In_Quote = $False
        $Temp_Value = $Temp_Value.Substring(0,$Temp_Value.Length-1)
      }
      if ($In_Quote -and (($Temp_Value.ToCharArray() | ? {$_ -eq '"'} ).Count % 2) -eq 1) {
        $In_Quote = $False #there are some value formula's that have an even number of quotes and messed the scripts inturpretation up - quote handling could be improved
      }
      If (-not $In_Quote) {
        If ($Item[$Temp_Key]) {
          $Item[$Temp_Key]+=" "+$Temp_Value
        } else {
          $Item+= @{ $Temp_Key = $Temp_Value }
        }
      }
    $i++}
    $Item.ps_oid = $Item.description.Substring(0,$Item.description.IndexOf(" "))
    If ($Overrides[$FileHash].Keys -contains $Item.ps_oid) {
      if ($Item.type -eq "USER_RIGHTS_POLICY") {
        $Item.value_data = ($Overrides[$FileHash])[$Item.ps_oid]
      } else {
        $Item.reg_key = ($Overrides[$FileHash])[$Item.ps_oid]
      }
    }
    @($Item)
  }
$i++}

#Harvest Audit Policy Items
$Temp = (auditpol.exe /get /Category:*)
$i = 0
while ($i -lt $Temp.Count) {
  If ($Temp[$i].Length -gt 42) {
    $Temp_Key   = $Temp[$i].Substring(0,41).trim()
    $Temp_Value = $Temp[$i].Substring(42).trim()
    if ($Temp_Value -ne "Setting") {
      $AuditPolicy+= @{ $Temp_Key = $Temp_Value }
    }
  }
$i++}

#Harvest secedit export
$Temp = iex "SecEdit.exe /export /cfg $env:temp\test.inf"
$SecEdit = Get-IniContent "$env:temp\test.inf"
# Resolve SIDs to User/group names
$Keys = $SecEdit.'Privilege Rights'.Keys | % { $_ } #extract the keys, otherwise it failes when the hash table is updated
ForEach ($Key in $Keys){
  If ($SecEdit['Privilege Rights'][$Key].Length -gt 2){
    $Temp_Value = ''
    ForEach ($Temp in $SecEdit.'Privilege Rights'[$Key].Replace("*","").Split(",")) {
      If ($Temp.Substring(0,2) -eq 'S-') {
        $Temp_Value+=","+(New-Object System.Security.Principal.SecurityIdentifier($Temp)).Translate( [System.Security.Principal.NTAccount]).Value
      } else {
        $Temp_Value+=","+$Temp
      }    }
    $SecEdit['Privilege Rights'][$Key] = $Temp_Value.Substring(1,$Temp_Value.Length-1)
  }
}

#Pre-processing on harvested items to exclude Items
if (1 -eq 1) {#Using If to shrink script block in ISE
  #Ignoring Checks
  $Checks = $Items | ? { -not ($_.ps_oid.contains(".") -or $_.ps_oid.contains("-")) }
  $Items  = $Items | ? { ($_.ps_oid.contains(".") -or $_.ps_oid.contains("-")) }

  #remove one of the 2.1.15's
  $Skipped+= $Items | ? { $_.ps_oid -eq "2.2.15" -and $_.value_data -ne "Administrators" }
  $Items   = $Items | ? { -not ($_.ps_oid -eq "2.2.15" -and $_.value_data -ne "Administrators") }

  #remove one of the 2.3.10.6's
  $Skipped+= $Items | ? { $_.ps_oid -eq "2.3.10.6" -and $_.value_data -eq "Browser" }
  $Items   = $Items | ? { -not ($_.ps_oid -eq "2.3.10.6" -and $_.value_data -eq "Browser") }

  #May need to use decimal notation to detect dups
  #Finding Duplicate Reg settings, will ignore sence conditions where not implemented in the script
  $Skipped+= $Items | ? {('18.9.80.2.1','18.9.80.2.2') -contains $_.ps_oid}   #These are duplicates of 18.9.80.1.1-2
  $Items = $Items | ? {('18.9.80.2.1','18.9.80.2.2') -notcontains $_.ps_oid}
  $Temp = Foreach ($Item in $Items) {
    if ($Item.type -eq "REGISTRY_SETTING" ) {
      $Item.reg_key+"\"+$Item.reg_item
    }
    if ($Item.type -eq "REG_CHECK" ) {
      $Item.value_data+"\"+$Item.key_item
    }
  }
  $Temp = $Temp | Sort-Object
  $Previous = $null
  $Dups = foreach ($Item in $Temp) {
    if ($Item -eq $Previous) {
      $Item
    } Else {
      $Previous = $Item
    }
  }
  $Temp = $Dups | Sort-Object -Unique
  $Dups =  $Items  | ? { $Temp -contains ($_.reg_key+"\"+$_.reg_item) }
  $Items =  $Items | ? { $Temp -notcontains ($_.reg_key+"\"+$_.reg_item) }
  $Skipped += $Dups
}

#Main: Format, gather and compare
ForEach ($Item in $Items) {
  Switch ($Item.Type) {
    "REG_CHECK" {
      $Temp_ix = $Item.value_data.IndexOf("\")
      Switch ($Item.value_data.Substring(0,$Temp_ix)) {
        "HKLM" {
          $Item.ps_reg_key = "HKLM:"+$Item.value_data.Substring($Temp_ix,$Item.value_data.Length-$Temp_ix)
        }
        "HKU" {#Just do current user for now
          $Item.ps_reg_key = "HKCU:"+$Item.value_data.Substring($Temp_ix,$Item.value_data.Length-$Temp_ix)
        }
        default { Write-Error "Reg Key location not implemented" -ErrorAction Stop }
      }
      Switch ($Item.reg_option) {
        "MUST_NOT_EXIST" {
          if (Test-Path $Item.value_data) {
            $Temp = Get-ItemProperty -Path $Item.ps_reg_key | Select-Object -ExpandProperty $Item.key_item -ErrorAction SilentlyContinue
            If ($Temp) {
              $Fail+=$Item
            } Else {
              $Passed+=$Item
            }
          } Else {
            $Passed+=$Item
          }
        }
        default { Write-Error "Reg Option not implemented" -ErrorAction Stop }
      }
    }
    "REGISTRY_SETTING" {
      #Unused Properties: description, info, reference, see_also, solution
      #Not Implemented Properties: reg_ignore_hku_users
      #Used Properties:
      #       type   Brings it into this section
      #   reg_item   Property name, no formatting
      #    reg_key   Value Location - needs formatting
      # value_data   Allowed values - needs formatting
      # reg_option   CAN_BE_NULL CAN_NOT_BE_NULL MUST_EXIST
      # value_type   POLICY_TEXT POLICY_SET POLICY_MULTI_TEXT POLICY_DWORD
      #Creadted Properties:
      #   ps_reg_key Registry key in PS item format
      #ps_value_data The posible values, and if it is a range
      #     ps_SetTo The value to set to if it is not set to desired
      #  ps_reg_type Registry property type in PS format
      #ps_found_value
      
      #Format Registry Entry for Powershell
      $Temp_ix = $Item.reg_key.IndexOf("\")
      Switch ($Item.reg_key.Substring(0,$Temp_ix)) {
        "HKLM" {
          $Item.ps_reg_key = "HKLM:"+$Item.reg_key.Substring($Temp_ix,$Item.reg_key.Length-$Temp_ix)
        }
        "HKU" {#Just do current user for now
          $Item.ps_reg_key = "HKCU:"+$Item.reg_key.Substring($Temp_ix,$Item.reg_key.Length-$Temp_ix)
        }
        default { Write-Error "Reg key Not Implemented" -ErrorAction Stop }
      }

      #Format Value for Compare and decide on set value and fill most data types
      if ($Item.value_type -eq "POLICY_SET") {
        switch ($Item.value_data) {
          "Enabled"  {$Item.ps_value_data = 1 ; $Item.ps_SetTo = 1 }
          "Disabled" {$Item.ps_value_data = 0 ; $Item.ps_SetTo = 0 }
          default    {Write-Error "POLICY_SET Value_Data Not Implemented" -ErrorAction Stop}
        }
      } Elseif ($Item.value_data.Length -eq 0) {
        $Item.ps_SetTo      = $Item.value_data
        $Item.ps_value_data = $Item.value_data
      } Elseif ($Item.value_data.Substring(0,1) -eq "[") {
        $Temp = $Item.value_data.Substring(1,$Item.value_data.Length-2).replace("..","|").Split("|")
        if ($Temp[1] -eq "MAX") {
          $Temp[1]          = 999999999
          $Item.ps_SetTo    = $Temp[0]
        } Elseif ($Temp[0] -eq "MIN") {
          $Temp[0]          = -1
          $Item.ps_SetTo    = $Temp[1]
        } else {
          $Item.ps_SetTo    = $Temp[1]
        }
        $Item.ps_value_data = @{ "type"="range"; "Min"=$Temp[0] ; "Max"=$Temp[1] }
      } elseif ($Item.value_data.IndexOf('" && "') -gt 0) {
        $Item.ps_value_data = $Item.value_data.Replace('" && "',"|").Split("|")
        $Item.ps_SetTo      = $Item.ps_value_datafs
        $Item.ps_reg_type   = "MultiString"
      } elseif ($Item.value_data.IndexOf('" || "') -gt 0) {
        $Item.ps_value_data = $Item.value_data.Replace('" || "',"|").Split("|")
        $Item.ps_SetTo      = $Item.ps_value_data[0]
      } elseif ($Item.value_data.IndexOf(" || ") -gt 0) {
        $Item.ps_value_data = $Item.value_data.Replace(" || ","|").Split("|")
        $Item.ps_SetTo      = $Item.ps_value_data[0]
      } else {
        $Item.ps_SetTo      = $Item.value_data.Replace("[\s]*"," ").Replace("^(900|[1-9][0-9]|[1-8][0-9]{2})$","900")
        $Item.ps_value_data = $Item.value_data
      }
      
      $Temp = Get-Item -Path $Item.ps_reg_key -ErrorAction SilentlyContinue
      If ($Temp) {
        $Item.ps_found_value = $Temp.GetValue($Item.reg_item,$null,'DoNotExpandEnvironmentNames')
      } else {
        $Item.ps_found_value = ''
      }
      
      if (-not $Item.ps_found_value -and $Item.ps_found_value -ne 0) {
        if ($Item.reg_option -eq "CAN_BE_NULL" -or $Item.ps_oid -eq '2.3.10.6') {#2.3.10.6 should be empty (anonymous named pipes)
          $Passed+=$Item
        } Else {
          $Failed+=$Item
        }
      } elseif ($Item.check_type -eq 'CHECK_REGEX' -and $Item.ps_found_value -match $Item.value_data ) {
        $Passed+=$Item
      } elseif ($Item.ps_value_data.type -eq "range") {
        if ([int]$Item.ps_found_value -ge [int]$Item.ps_value_data.Min -and [int]$Item.ps_found_value -le [int]$Item.ps_value_data.Max) {
          $Passed+=$Item
        } Else {
          $Failed+=$Item
        }
      } elseif ($Item.ps_reg_type -eq "MultiString") {
        if ($Item.ps_value_data.count -ne $Item.ps_found_value.count) {
          $Failed+=$Item
        } else {
          if ($Item.ps_value_data.count -eq 1) {
            if ($Item.ps_value_data -eq $Item.ps_found_value) {
              $Temp = 'notfailed'
            } else {
              $Temp = 'failed'
            }
          } else {
            $i = 0 ; $Temp = "notfailed"
            while ($i -lt $Item.ps_value_data.count -and $Temp -eq 'notfailed') {
              if ($Item.ps_found_value -notcontains $Item.ps_value_data[$i]) {
                $Temp = "failed"
              }
            $i++}
          }
          if ($Temp -eq "notfailed") {
            $Passed+=$Item
          } else {
            $Failed+=$Item
          }
        }
        $Passed+=$Item        
      } elseif ($Item.ps_value_data -contains $Item.ps_found_value) {
        $Passed+=$Item
      #} elseif () {
      } else {
        $Failed+=$Item
      }
    }
    "AUDIT_POLICY_SUBCATEGORY" {
      If ($Item.audit_policy_subcategory -eq "PNP Activity") {#Nessus file has weird Name for this category
        $Item.audit_policy_subcategory = "Plug and Play Events"
      }
      Switch ($Item.value_data) {
        "Success, Failure" {
          $Item.ps_Value_Data =  "Success and Failure"
          $Item.ps_SetTo = @('Success','Failure')
        }
        'Success" || "Success, Failure' {
          $Item.ps_Value_Data =  @("Success","Success and Failure")
          $Item.ps_SetTo = @('Success','Failure')
        }
        'Failure" || "Success, Failure' {
          $Item.ps_Value_Data =  @("Failure","Success and Failure")
          $Item.ps_SetTo = @('Success','Failure')
        }
        default { $Item.ps_Value_Data = $Item.value_data ; $Item.ps_SetTo = $Item.value_data }
      }
      $Item.ps_found_value = $AuditPolicy[$Item.audit_policy_subcategory]
      if ($Item.ps_value_data -eq $Item.ps_found_value) {
        $Passed+=$Item
      } elseif ($Item.ps_value_data -contains $Item.ps_found_value) {
        $Passed+=$Item
      } else {
        $Failed+=$Item
      }
    }
    "USER_RIGHTS_POLICY" {
      If ($Item.value_data.length -eq 0){
        $Item.ps_value_data = ''
      } ElseIf ($Item.value_data.IndexOf('" && "') -gt 0) {
        $Item.ps_value_data = $Item.value_data.tolower().Replace('" && "',"|").Split("|")
      } else {
        $Item.ps_value_data = $Item.value_data.tolower()
      }
      $Temp = ''
      $Temp = $SecEdit['Privilege Rights'][$Item.right_type]
      
      If ($Temp) {
        $Item.ps_found_value = $Temp.Replace("BUILTIN\","").Replace("NT AUTHORITY\","").Replace("NT SERVICE\","").tolower().split(",")
      } else {
        $Item.ps_found_value = ""
      }
      if ($Item.ps_value_data -eq $Item.ps_found_value) {
        $Passed+=$Item
      } elseif ($Item.ps_value_data.count -ne $Item.ps_found_value.count) {
        $Failed+=$Item
      } else {
        $i = 0 ; $Temp = "notfailed"
        while ($i -lt $Item.ps_value_data.count -and $Temp -eq 'notfailed') {
          if ($Item.ps_found_value -notcontains $Item.ps_value_data[$i]) {
            $Temp = "failed"
          }
        $i++}
        if ($Temp -eq "notfailed") {
          $Passed+=$Item
        } else {
          $Failed+=$Item
        }
      }
    }
    default {Switch ($Item.ps_oid) {
               "1.1.1" {$Item.ps_found_value = $Secedit['System Access']['PasswordHistorySize']
                        $Item.ps_SetTo       = 24
                        $Item.ps_value_data  = @{ "type"="range"; "Min"=24 ; "Max"=99999 }
                       }
               "1.1.3" {$Item.ps_found_value = $Secedit['System Access']['MinimumPasswordAge']
                        $Item.ps_SetTo       = 1
                        $Item.ps_value_data  = @{ "type"="range"; "Min"=1 ; "Max"=99999 }
                       }
               "1.1.4" {$Item.ps_found_value = $Secedit['System Access']['MinimumPasswordLength']
                        $Item.ps_SetTo       = 8
                        $Item.ps_value_data  = @{ "type"="range"; "Min"=8 ; "Max"=99999 }
                       }
               "1.1.5" {$Item.ps_found_value = $Secedit['System Access']['PasswordComplexity']
                        $Item.ps_SetTo       = 1
                        $Item.ps_value_data  = 1
                       }
               "1.1.6" {$Item.ps_found_value = $Secedit['System Access']['ClearTextPassword']
                        $Item.ps_SetTo       = 0
                        $Item.ps_value_data  = 0
                       }
               "1.2.1" {$Item.ps_found_value = $Secedit['System Access']['LockoutDuration']
                        $Item.ps_SetTo       = 120
                        $Item.ps_value_data  = @{ "type"="range"; "Min"=120 ; "Max"=99999 }
                       }
               "1.2.2" {$Item.ps_found_value = $Secedit['System Access']['LockoutBadCount']
                        $Item.ps_SetTo       = 3
                        $Item.ps_value_data  = @{ "type"="range"; "Min"=1 ; "Max"=3 }
                       }
               "1.2.3" {$Item.ps_found_value = $Secedit['System Access']['ResetLockoutCount']
                        $Item.ps_SetTo       = 120
                        $Item.ps_value_data  = @{ "type"="range"; "Min"=120 ; "Max"=99999 }
                       }
             "2.3.1.1" {$Item.ps_found_value = $Secedit['System Access']['EnableAdminAccount']
                        $Item.ps_SetTo       = 0
                        $Item.ps_value_data  = 0
                       }
             "2.3.1.3" {$Item.ps_found_value = $Secedit['System Access']['EnableGuestAccount']
                        $Item.ps_SetTo       = 0
                        $Item.ps_value_data  = 0
                       }
             "2.3.1.5" {$Item.ps_found_value = $Secedit['System Access']['NewAdministratorName']
                        $Item.ps_SetTo       = 'anything'
                        $Item.ps_value_data  = '.{1}.*'
                       }
             "2.3.1.6" {$Item.ps_found_value = $Secedit['System Access']['NewGuestName']
                        $Item.ps_SetTo       = 'otherthing'
                        $Item.ps_value_data  = '.{1}.*'
                       }
            "2.3.10.1" {$Item.ps_found_value = $Secedit['System Access']['LSAAnonymousNameLookup']
                        $Item.ps_SetTo       = 0
                        $Item.ps_value_data  = 0
                       }
            "2.3.11.6" {$Item.ps_found_value = $Secedit['System Access']['ForceLogoffWhenHourExpire']
                        $Item.ps_SetTo       = 1
                        $Item.ps_value_data  = 1
                       }
               Default {$Skipped+=$Item}
            }
            if ($Item.ps_found_value.length -gt 3) {if ($Item.ps_found_value.Substring(0,1) -eq '"') {$Item.ps_found_value = $Item.ps_found_value.Substring(1,$Item.ps_found_value.Length-2)}}
            if ($Item.ps_value_data.type -eq "range") {
              if ([int]$Item.ps_found_value -ge [int]$Item.ps_value_data.Min -and [int]$Item.ps_found_value -le [int]$Item.ps_value_data.Max) {
                $Passed+=$Item
              } Else {
                $Failed+=$Item
              }
            } elseif ($Item.ps_value_data -contains $Item.ps_found_value) {
              $Passed+=$Item
            } elseif ($Item.check_type -eq 'CHECK_NOT_REGEX' -and $Item.ps_found_value -notmatch $Item.value_data ) {
              $Passed+=$Item
            } elseif ($Item.check_type -eq 'CHECK_NOT_EQUAL' -and $Item.ps_found_value -notmatch $Item.value_data ) {
              $Passed+=$Item
            } else {
              $Failed+=$Item
            }
    }
  }
}

#If Fix flag on, fix them
If ($Fix) {
  $DONT_FIX = @(
              '9.1.2',     # Force Domain firewall on - allows users to turn enforcement off
              '18.2.1',    # Adding Key doesn't install LAPS
              '18.8.24.1', # Workstations should show this - network settings on logon screen
              '18.8.30.1', # Workstations should allow this - Org Uses remote assistance
              '18.8.30.2', # Workstations should allow this - Org Uses remote assistance
              '18.9.84.3'  # Not sure what Org is doing with windows update defer
            )
  $Temp = $Failed | ? { $_.ps_oid = '18.9.15.1' -and $_.reg_key -eq "HKLM\Software\Policies\Microsoft\Windows\Deliveryoptimization" }
  if ($Temp) {
    $DONT_FIX+= @('18.9.15.1') # Not sure what ORG is doing with windows update sharing, needed to validate reg key before excluding because SCSEM double used the id for the password reveal button on Server
  }
  ForEach ($Item in $Failed) {
   if ($DONT_FIX -notcontains $Item.ps_oid) {
    Switch ($Item.Type) {
      "REG_CHECK" {
        $Item.fix_result = Remove-ItemProperty -Path $Item.ps_reg_key -Name $Item.key_item
        $Fixed+=$Item
      }
      "REGISTRY_SETTING" {
        $Temp = Get-Item -Path $Item.ps_reg_key -ErrorAction SilentlyContinue
        if (-not $Temp) { $Temp = New-Item -Path $Item.ps_reg_key -Force }
        $Options = @{"Path" = $Item.ps_reg_key
                     "Name" = $Item.reg_item
                     "Value"= $Item.ps_SetTo
                    }
        if ($Item.ps_SetTo -match '%') {
          $Options+= @{ "PropertyType" = "ExpandString" }
        } elseif ($Item.value_type -eq "POLICY_TEXT") {
          $Options+= @{ "PropertyType" = "String" }
        } elseif ($Item.ps_SetTo.count -gt 1 -or $Item.value_type -eq "POLICY_MULTI_TEXT") {
          $Options+= @{ "PropertyType" = "MultiString" }
        } elseif ($Item.ps_SetTo -match "^[\d]*$" -or $Item.value_type -eq "POLICY_DWORD") {
          $Options+= @{ "PropertyType" = "DWORD" }
        }
        $Temp = new-ItemProperty -Force @Options
      }
      "AUDIT_POLICY_SUBCATEGORY" {
        $Temp = ''
        $Item.ps_SetTo | %{ $Temp+= " /"+$_+":enable" }
        $Temp = 'auditpol.exe /set /SubCategory:"'+$Item.audit_policy_subcategory+'"'+$Temp
        $Temp = (iex $Temp)
      }
      "USER_RIGHTS_POLICY" {
        #To Do
      }
      default {
      }
    }
   }
  }
}

$Temp = "NessusToConfig_"+$env:username+"_"+$env:computername+"_"+$(Get-Date -Format 'yyyyMMdd_HHmmss')
$Passed  | select-object @{expression={$_.description}; label='Description'}, @{expression={"Passed"};  label='Result'}, @{expression={$_.ps_found_value}; label='Value Found'}, @{expression={$_.ps_SetTo}; label='Set To'} , @{expression={$_.reg_option}; label='reg_option'} | export-csv ($Temp+".csv") -NoTypeInformation -Append
$Failed  | select-object @{expression={$_.description}; label='Description'}, @{expression={"Failed"};  label='Result'}, @{expression={$_.ps_found_value}; label='Value Found'}, @{expression={$_.ps_SetTo}; label='Set To'} , @{expression={$_.reg_option}; label='reg_option'} | export-csv ($Temp+".csv") -NoTypeInformation -Append
$Skipped | select-object @{expression={$_.description}; label='Description'}, @{expression={"Skipped"}; label='Result'}, @{expression={$_.ps_found_value}; label='Value Found'}, @{expression={$_.ps_SetTo}; label='Set To'} , @{expression={$_.reg_option}; label='reg_option'} | export-csv ($Temp+".csv") -NoTypeInformation -Append
@{"Failed"=$Failed;"Passed"=$Passed;"Skipped"=$Skipped;"FileHash"=$FileHash} | Export-Clixml ($Temp+".xml") 
