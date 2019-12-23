SELECT Distinct RemoteIPAddress, RemoteDevice, RemotePlatform, NCM_Nodes.NodeCaption as Observer, NCM_Nodes.AgentIP
  FROM [NCM_Cisco_CDP] inner join NCM_Nodes on NCM_Nodes.NodeID = NCM_Cisco_CDP.NodeID
  where
    RemoteIPAddress not in (SELECT [IpAddress]
                                 FROM [NCM_ConfigInterfacesIpAddresses]
								)
    and RemoteIPAddress not in (select IP_Address
	                             from [Nodes]
								)
    and RemoteIPAddress not in (SELECT [IPAddress]
                                 FROM [NCM_IPAddresses]
								)
    and RemoteIPAddress not in (SELECT [IPAddress]
                                 FROM [NodeIPAddresses]
								)
	and RemoteVersion not like 'NetApp%' and RemotePlatform not like 'Polycom%'
	and RemotePlatform <> 'someexclusion'
	and LastDiscovery > DATEADD(DAY, -5, getdate())
	and RemoteIPAddress <> '0.0.0.0'
  order by RemotePlatform, Observer
