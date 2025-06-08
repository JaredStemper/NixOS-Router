# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ lib, config, pkgs, ... }:
let
  publicDnsServer = "8.8.8.8";
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
  };

  networking = {
    hostName = "nix-router";
    nameservers = [ "${publicDnsServer}" ];
    firewall.enable = false;

    interfaces = {
      enp0s20f0u3i1 = {
        useDHCP = true;
      };
      enp1s0 = {
        useDHCP = false;
        ipv4.addresses = [{
          address = "10.13.84.1";
          prefixLength = 24;
        }];
      };
    };

    nftables = {
      enable = true;
      ruleset = ''
        table ip filter {
          chain input {
            type filter hook input priority 0; policy drop;
            iifname "lo" accept comment "Allow loopback";
            iifname { "enp1s0" } accept comment "Allow local network (LAN) to access the router";
            ct state { established, related } accept comment "Allow established/related traffic";
            iifname "enp0s20f0u3i1" icmp type { echo-request, destination-unreachable, time-exceeded } counter accept comment "Allow select ICMP from WAN";
          }
          chain forward {
            type filter hook forward priority 0; policy drop;
            # LAN to WAN: allow
            iifname "enp1s0" oifname "enp0s20f0u3i1" accept comment "Allow trusted LAN to WAN";
            # WAN to LAN: allow established/related
            iifname "enp0s20f0u3i1" oifname "enp1s0" ct state established,related accept comment "Allow established back to LAN";
          }
        }
        table ip nat {
          chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "enp0s20f0u3i1" masquerade comment "NAT for LAN to WAN";
          } 
        }
        table ip6 filter {
          chain input {
            type filter hook input priority 0; policy drop;
          }
          chain forward {
            type filter hook forward priority 0; policy drop;
          }
        }
      '';
    };
  };

  services = {
    openssh = {
      enable = true;
      settings.PermitRootLogin = "yes";
    };
    
    dnsmasq = {
      enable = true;
      settings = {
        interface = [ "enp1s0" ]; # interface to serve DHCP leases
        "dhcp-range" = "10.13.84.2,10.13.84.254,255.255.255.0,12h"; # DHCP range and lease time 12 hours
        "dhcp-option" = [
	   "3,10.13.84.1" # 3 is router (gateway)
	   "6,10.13.84.1" # 6 is domain-name-servers
	];
        "server" = [ "${publicDnsServer}"]; # upstream DNS server
        "no-resolv" = true; # explicitly avoid reading /etc/resolv.conf
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
    tmux
    firefox
    nftables
    git
  ];

  # Set your time zone.
  time.timeZone = "America/New_York";

  # Enable the X11 windowing system.
  # You can disable this if you're only using the Wayland session.
  services.xserver.enable = true;

  # Enable the KDE Plasma Desktop Environment.
  services.displayManager.sddm.enable = true;
  services.desktopManager.plasma6.enable = true;

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "us";
    options = "caps:swapescape";
    variant = "";
  };

  users.users.jared = {
    isNormalUser = true;
    description = "Jared";
    extraGroups = [ "networkmanager" "wheel" ];
    packages = with pkgs; [
      kdePackages.kate
    ];
  };

  services.logind.extraConfig = ''
    IdleAction = ignore;
  '';

  system.stateVersion = "25.05";
}

