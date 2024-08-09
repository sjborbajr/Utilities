$CloudFlareHeaders = @{'Authorization' = 'Bearer <TOKEN>'}
$CloudFlareBaseUrl = 'https://api.cloudflare.com/client/v4/'

$response = Invoke-RestMethod -Method Get -Uri ($CloudFlareBaseUrl+'zones?match=all') -Headers $CloudFlareHeaders
if ($response.result -eq 'error') {
  throw $($response.msg)
} else {
  $Records = foreach ($zone in $response.result) {
    $dns_response = Invoke-RestMethod -Uri ($CloudFlareBaseUrl+'/zones/'+$zone.id+'/dns_records?match=all') -Headers $CloudFlareHeaders
    if ($dns_response.success -eq $true) {
      [PSCustomObject]@{
       'Zone'       = $zone.name
       'Records'    = ($dns_response.result | select name,type,content,proxied,ttl)
       'Properties' = $zone
      }
    } else {
      Write-Error "There were errors with fetching DNS records for zone {$($zone.Name)} - id {$($zone.id)}"
    }
  }
}
