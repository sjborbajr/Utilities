﻿$API_PRE = "https://api.pwnedpasswords.com/range/"

If (-not $UserAgentString){
  if ($env:PasswordCheckAgentString) {
    $UserAgentString = $env:PasswordCheckAgentString
  } else {
    $UserAgentString = Read-Host -Prompt '!!!  USER AGENT STRING NOT SET  !!!!  PLEASE PROVIDE ONE'
  }
}

$SecurePassword = Read-Host -AsSecureString -Prompt "Password to be Checked"
$SHA = Get-StringHash -String (New-Object PSCredential 0, $SecurePassword).GetNetworkCredential().Password -HashName SHA1

$Data = Invoke-WebRequest -Uri ($API_PRE+$SHA.Substring(0,5)) -UserAgent $UserAgentString

$Possible = $Data.Content.Split("`n")

for ($ix = 0; $ix -lt $Possible.count; $ix++) {
  $Current = $Possible[$ix].split(":")
  if (($SHA.Substring(0,5).ToLower()+$Current[0].tolower()) -eq $SHA){
    "FOUND!!! - "+$Possible[$ix]
  }
}


Function Get-StringHash {
<#
.SYNOPSIS
Returns a hash of a string value
 
.DESCRIPTION
Returns a hash of a string value
 
.PARAMETER String
String value to be converted to a hash.
 
.PARAMETER HashName
Hash type to be generated. Valid values are "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512"
 
.EXAMPLE
Get-StringHash -string "qwerty" -hashname SHA1
 
.OUTPUTS
b1b3773a05c0ed0176787a4f1574ff0075f7521e
 
.NOTES
Daryl Newsholme 2018
#>
    [cmdletbinding()]
    [OutputType([String])]
    param(
        [parameter(ValueFromPipeline, Mandatory = $true, Position = 0)][String]$String,
        [parameter(ValueFromPipelineByPropertyName, Mandatory = $true, Position = 1)]
        [ValidateSet("MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")][String]$HashName
    )
    begin {

    }
    Process {
        $StringBuilder = New-Object System.Text.StringBuilder
        [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))| foreach-object {
            [Void]$StringBuilder.Append($_.ToString("x2"))
        }
        $output = $StringBuilder.ToString()
    }
    end {
        return $output
    }
}