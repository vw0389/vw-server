# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];
  swapDevices = [ {
    device = "/dev/disk/by-partuuid/817f7059-8766-d443-8894-cdd08756966a";
    randomEncryption = {
      enable = true;
      allowDiscards = true;
    };
  } ];
  boot.supportedFilesystems = [ "zfs" ];
  services.mullvad-vpn.enable = true;
  services.earlyoom.enable = true;
  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.zfs.extraPools = [ "hds" ];
  services.zfs.trim.enable = true;
  services.zfs.autoScrub.enable = true;
  networking.hostName = "vw-server";
  networking.hostId = "8ab86d95";
  # Pick only one of the below networking options.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.
  # networking.networkmanager.enable = true;  # Easiest to use and most distros use this by default.
  nixpkgs.config.allowUnfree = true;
  hardware.enableAllFirmware = true;
  # Set your time zone.
  time.timeZone = "America/Chicago";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  # i18n.defaultLocale = "en_US.UTF-8";
  # console = {
  #   font = "Lat2-Terminus16";
  #   keyMap = "us";
  #   useXkbConfig = true; # use xkbOptions in tty.
  # };

  # Enable the X11 windowing system.
  #services.xserver.enable = true;


  boot = {
  initrd.availableKernelModules = ["r8169"];
  initrd.network = {
    # This will use udhcp to get an ip address.
    # Make sure you have added the kernel module for your network driver to `boot.initrd.availableKernelModules`, 
    # so your initrd can load it!
    # Static ip addresses might be configured using the ip argument in kernel command line:
    # https://www.kernel.org/doc/Documentation/filesystems/nfs/nfsroot.txt
    enable = true;
    ssh = {
      enable = true;
      # To prevent ssh clients from freaking out because a different host key is used,
      # a different port for ssh is useful (assuming the same host has also a regular sshd running)
      port = 2222; 
      # hostKeys paths must be unquoted strings, otherwise you'll run into issues with boot.initrd.secrets
      # the keys are copied to initrd from the path specified; multiple keys can be set
      # you can generate any number of host keys using 
      # `ssh-keygen -t ed25519 -N "" -f /path/to/ssh_host_ed25519_key`
      hostKeys = [ /root/secrets/initramfs_hostkey_ed25519 ];
      # public ssh key used for login
      authorizedKeys = [ "REDACTED" ];
    };
  };
};





  # Enable the GNOME Desktop Environment.
  #services.xserver.displayManager.gdm.enable = true;
  #services.xserver.desktopManager.gnome.enable = true;
  

  # Configure keymap in X11
  # services.xserver.layout = "us";
  # services.xserver.xkbOptions = {
  #   "eurosign:e";
  #   "caps:escape" # map caps to escape.
  # };

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # sound.enable = true;
  # hardware.pulseaudio.enable = true;

  # Enable touchpad support (enabled default in most desktopManager).
  # services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.victor = {
     isNormalUser = true;
     extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
     packages = with pkgs; [
    ];
  };
  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    wget
    glances
    htop
    rsync
    openssl
    git
    qemu_kvm
    unzip
    ripgrep
    exa
    du-dust
    fd
    zip
    tmux
  ];
  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # VIRTUALIZATION
  virtualisation.libvirtd.enable = true;
  virtualisation.forwardPorts = [
    {
      from = "host";
      host.port=60022;
      guest.port=22;
      guest.address="192.168.122.5";
    }
  ];
  
  #Enable the OpenSSH daemon.
  services.openssh = {
    enable = true;
    ports = [
      22
      54142
    ];
  };
  networking = {
    firewall = {
      enable = true;
      allowedTCPPorts = [ 80 443];
      allowedUDPPorts = [ 2456 2457 ];
#      extraCommands = ''
#       iptables -t nat -A POSTROUTING -d 192.168.122.5 -p udp -m udp --dport 2456 -j MASQUERADE;
#       iptables -t nat -A POSTROUTING -d 192.168.122.5 -p udp -m udp --dport 2457 -j MASQUERADE;
#      '';
    };
#    nat = {
#      enable = true;
#      internalInterfaces = [ "virbr0" ];
#      externalInterface = "enp42s0";
#      forwardPorts = [
#        {
#          sourcePort = 2456;
#          proto = "udp";
#          destination = "192.168.122.5:2456";
#        }
#        {
#         sourcePort = 2457;
#          proto = "udp";
#          destination = "192.168.122.5:2457";
#        }
#      ];
#    };
  };
  environment.variables.LIBVIRT_DEFAULT_URI = "qemu:///system";
  #environment.variables.DOCKER_HOST = "unix://$XDG_RUNTIME_DIR/docker.sock";
  # Open ports in the firewall.
  #networking.firewall.allowedTCPPorts = [ 80 443 ];
  #networking.firewall.allowedUDPPorts = [ 2456 2457 ];
  # Or disable the firewall altogether.
  #networking.firewall.enable = false;
  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;
  #gitlab
  users.users.gitlab.extraGroups = [ "gitlab" ];
  services.gitlab = {
    enable = true;
    port = 443;
    https = true;
    host = "gitlab.vw-server.lan";
    #host = "vw-server.lan";
    initialRootPasswordFile = "/secrets/gitlab/gitlabinitialpasswd";
    secrets = {
      secretFile = "/secrets/gitlab/secretFile";
      otpFile = "/secrets/gitlab/otpFile";
      jwsFile = "/secrets/gitlab/jwsFile";
      dbFile = "/secrets/gitlab/dbFile";
    };
    extraConfig = {
      gitlab_shell.ssh_host = "gitlab.vw-server.lan";
      
    };
#    extraGitlabRb = 
#      ''
#        gitlab_rails['gitlab_ssh_host'] = 'gitlab.vw-server.lan'
#      '';    
  };
  #nginx and jellyfin
  services.jellyfin.enable = true;
  hardware.opengl.enable = true;
  users.users.jellyfin.extraGroups = [ "video" ];
  services.nginx =  {
    enable = true;
    virtualHosts = 
      
    let 
      proxyPass = url: {
            recommendedProxySettings = true;
            proxyPass = url;
            extraConfig = ''
              proxy_set_header Upgrade $http_upgrade;
              proxy_set_header Connection $connection_upgrade;
            '';
        };
    in {
      "gitlab.vw-server.lan" = {
        forceSSL = true;
        sslCertificate = "/secrets/nginx/jellyfin.vw-server.lan.crt";
        sslCertificateKey = "/secrets/nginx/jellyfin.vw-server.lan.key";
        locations."/" = proxyPass "http://unix:/run/gitlab/gitlab-workhorse.socket";
      };
      "jellyfin.vw-server.lan" = {
        forceSSL = true;
        sslCertificate = "/secrets/nginx/jellyfin.vw-server.lan.crt";
        sslCertificateKey = "/secrets/nginx/jellyfin.vw-server.lan.key";
        locations."/" = proxyPass "http://localhost:8096/";
      };
    };
  };
  #backups
  programs.ssh.knownHosts."borgbase/rsa" = {
    hostNames = [ "c8vmhdk6.repo.borgbase.com" ];
    publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6r8zHXR11Xja/o7HLIlrfo1L9i6RR1NDJUQB93hsVcD0Vh+rZB2yqHPt3xpgEGbKfxBaELcENms/GB1QgBJXLBSNwk7+0xaGTTYJWasyy9KMP6W51KkM97pCy3INzdZBT5jpY5awbSuns6ekcl5UALGroAkXnDMzgWLE7DyAp1ZNdcRYGzT7lPFFxfyczDkTeNBoNwFdqheZLO+LcX80Ds4H2Maj/04lfzVXDWShdvEPH04pazzcxidUysqNOc5MNMCqTmzLw8aiUZuc4k7MubpQ/soRPSVOq6iPB+Aw47fBzzpB0/I5Z6cAANNY0pRYbjyFZHIPcMKYIZLgbcWuj";
  };
  programs.ssh.knownHosts."borgbase/ecdsa" = {
    hostNames = [ "c8vmhdk6.repo.borgbase.com" ];
    publicKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHYDOAh9uJnuVsYEZHDORpMbLHPWUoNSFTA84/Q4U/d99rDp2LE4Kr+kHHpuR6IXOSpoiTAg500CX+Q6IWJybHE=";
  };
  programs.ssh.knownHosts."borgbase/ed25519" = {
    hostNames = [ "c8vmhdk6.repo.borgbase.com" ];
    publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGU0mISTyHBw9tBs6SuhSq8tvNM8m9eifQxM+88TowPO";
  };
  services.borgmatic = {
    enable = true;
    configurations.main = {
      consistency.checks = [ "repository" "archives" ];
      retention = {
        keep_daily = 7;
        keep_weekly = 4;
        keep_monthly = 3;
      };
      location = {
        source_directories = [ "/var/gitlab/state/" "/etc/" "/hds/backups/" "/secrets/"];
        repositories = [ "ssh://c8vmhdk6@c8vmhdk6.repo.borgbase.com/./repo" ];
      };
      storage = {
        ssh_command = "ssh -o PasswordAuthentication=no -i /secrets/borgmatic/main/ssh-main";
        encryption_passcommand = "${pkgs.busybox}/bin/cat /secrets/borgmatic/main/passphrase";
      };
    };
  };
  #services.jellyfin.openFirewall = true;
  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "23.05"; # Did you read the comment?
}

