# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ lib, config, pkgs, ... }:

let
  publicDnsServer = "8.8.8.8";
  
  # Interface Definitions
  wanInterface = "enp0s20f0u3i1";
  phyInterface = "enp1s0";
  
  # Network Segmentation
  vlanMgmtId = 10;
  vlanLabId = 20;
  
  mgmtInterface = "vlan${toString vlanMgmtId}";
  labInterface = "vlan${toString vlanLabId}";
  
  # Subnets
  mgmtIp = "10.13.10.1";
  labIp = "10.13.20.1";
in
{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  boot.kernel.sysctl = {
    "net.ipv4.conf.all.forwarding" = true;
    "net.ipv4.icmp_echo_ignore_broadcasts" = true; 
    "net.ipv4.conf.all.rp_filter" = 1;
  };

  networking = {
    hostName = "nix-router";
    nameservers = [ "${publicDnsServer}" ];
    firewall.enable = false; # Disabling default firewall to use custom nftables

    vlans = {
      "${mgmtInterface}" = { id = vlanMgmtId; interface = phyInterface; };
      "${labInterface}" = { id = vlanLabId; interface = phyInterface; };
    };

    interfaces = {
      "${wanInterface}" = { useDHCP = true; };
      "${phyInterface}" = { useDHCP = false; }; # Physical link, no IP
      
      "${mgmtInterface}" = {
        useDHCP = false;
        ipv4.addresses = [{ address = mgmtIp; prefixLength = 24; }];
      };

      "${labInterface}" = {
        useDHCP = false;
        ipv4.addresses = [{ address = labIp; prefixLength = 24; }];
      };
    };

    nftables = {
      enable = true;
      ruleset = ''
        table ip filter {
          chain input {
            type filter hook input priority 0; policy drop;

            iifname "lo" accept comment "Trust Localhost"
            ct state { established, related } accept comment "Stateful: Allow return traffic"
            ct state invalid drop comment "Sanity: Drop invalid packets early"

            # Management Plane
            iifname "${mgmtInterface}" tcp dport 22 accept comment "Allow SSH from Mgmt VLAN only"

            # Infra for lab - Block everything but DNS/DHCP
            iifname "${labInterface}" udp dport { 53, 67 } accept comment "Allow DNS/DHCP from Lab"
            iifname "${labInterface}" tcp dport 53 accept comment "Allow DNS TCP from Lab"
            
            # WAN ICMP (Limited)
            iifname "${wanInterface}" icmp type { echo-request, destination-unreachable, time-exceeded } counter accept
            
            limit rate 5/minute burst 5 packets log prefix "NFT-DROP-INPUT: " 
          }

          chain forward {
            type filter hook forward priority 0; policy drop;

            iifname "${labInterface}" oifname "${wanInterface}" accept comment "Lab -> Internet"
            iifname "${mgmtInterface}" oifname "${wanInterface}" accept comment "Mgmt -> Internet"
            iifname "${wanInterface}" ct state established,related accept comment "Internet -> LAN (Return)"
            iifname "${labInterface}" oifname "${mgmtInterface}" drop comment "Block Lab to Mgmt"
            limit rate 5/minute burst 5 packets log prefix "NFT-DROP-FWD: "
          }
        }

        table ip nat {
          chain prerouting {
            type nat hook prerouting priority -100; policy accept;
            # uncomment to hook lab http traffic
            # iifname "${labInterface}" tcp dport 80 tproxy to :8080 meta mark set 1 accept
          }
          chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "${wanInterface}" masquerade comment "NAT Source Hiding"
          } 
        }

        table ip6 filter {
          chain input { type filter hook input priority 0; policy drop; }
          chain forward { type filter hook forward priority 0; policy drop; }
        }
      '';
    };
  };

  services = {
    openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "no";
        PasswordAuthentication = false;
        AllowUsers = [ "jared" ];
      };
    };
    
    dnsmasq = {
      enable = true;
      settings = {
        interface = [ "${labInterface}" ]; # bind to lab
        "dhcp-range" = "${labIp},10.13.20.254,255.255.255.0,12h";
        "dhcp-option" = [
           "3,${labIp}" # Gateway
           "6,${labIp}" # DNS
        ];
        "server" = [ "${publicDnsServer}"]; 
        "no-resolv" = true; 
        "cache-size" = 150;
        log-queries = true;
      };
    };
  };

  environment.systemPackages = with pkgs; [
    pciutils
    tcpdump
    htop
    vim
	sl
    tmux
    nftables
    git
    nmap 
    socat
  ];

  time.timeZone = "America/New_York";
  services.xserver.enable = false;

  users.users.jared = {
    isNormalUser = true;
    description = "Jared";
    extraGroups = [ "networkmanager" "wheel" ];
    # make sure to add your public key before using this config!
    # openssh.authorizedKeys.keys = [ "ssh-ed25519 ..." ];
    packages = with pkgs; [];
  };

  system.stateVersion = "25.05";
}
