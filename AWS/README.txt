Build Script steps:

Installing module dependancies.
Find the AMI for net utility
Find existing subnet list (connect to firewalls and cache route information)

Prompt user for information and perpare data needed to build

Creating VPC Container and adding Tags
  Setting up Security Groups (default and 4 tiers)
Creating Redundant VGW/VPN in AWS and PAN
  Creating, associating, and naming AWS VGW
  Creating Zone on Both PAN
  Creating PAN to VPC Polling (tags)
  Creating Primary VPN on AWS Side
    Creating PAN Tunnels Interface for Primary AWS VPN
    Adding PAN Interface to sub-components for Primary
    Adding Primary PAN IKE Settings
    Creating Primary PAN IPsec Tunnels
    Adding Primary PAN BGP peering
   Commiting changes for Primary PAN
  Creating Secondary VPN on AWS Side
    Creating PAN Tunnel Interface for Secondary
    Adding PAN Interface to sub-components for Secondary
    Adding Secondary PAN IKE Settings
    Creating Secondary PAN IPsec Tunnel
    Adding Primary PAN BGP peering
   Commiting changes for Primary PAN
  Creating Tier ACLs
  Creating Subnets and associating ACLs

  Creating Test/Utility VMs
    Waiting till VMs are running
    Naming vm sub components
    Creating and attaching extra network testing interfaces for A
    Creating and attaching extra network testing interfaces for B

  Waiting for VGW to become available...
    Enabling BGP Route Propigation in AWS

#################################################################################################
