#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Error: this script must be executed as root" 
   exit 1
fi

ln -sf /usr/share/zoneinfo/Europe/Paris /etc/localtime


if [ -f /etc/debian_version ]; then
    echo "The operating system is Debian, continuing"
else
    echo "The operating system is not Debian, exiting"
    exit 1
fi

version=$(cat /etc/os-release | grep VERSION_ID | cut -d '"' -f 2)

if [ $version = "11" ]; then
    echo "------------ UPDATING SOURCE.LIST FOR BULLSEYE -----------"
    cat > /etc/apt/sources.list << "EOF"
	deb http://deb.debian.org/debian bullseye main
	deb-src http://deb.debian.org/debian bullseye main

	deb http://deb.debian.org/debian-security/ bullseye-security main
	deb-src http://deb.debian.org/debian-security/ bullseye-security main

	deb http://deb.debian.org/debian bullseye-updates main
	deb-src http://deb.debian.org/debian bullseye-updates main
	EOF
fi

sudo apt-get update && sudo apt-get dist-upgrade && sudo apt-get autoremove && sudo apt-get autoclean
apt-get install -y aria2 bash-completion exfat-fuse git vim curl wget


echo "What package repos do you want to install ?"
echo "1) Whonix"
echo "2) Kicksecure"
echo "3) Brave"
echo "4) Codium"
echo "5) Oxen"

read -p "Enter the numbers corresponding to the choices, separated by commas:" choices

IFS=',' read -ra choices_array <<< "$choices"

for choice in "${choices_array[@]}"
do
    case $choice in
        1)
            echo "------------ GETTING WHONIX KEYS -----------"
            wget https://www.kicksecure.com/derivative.asc
            cp ./derivative.asc /usr/share/keyrings/derivative.asc
            sudo apt-key --keyring /etc/apt/trusted.gpg.d/whonix.gpg add ./derivative.asc
	        echo "deb https://deb.whonix.org bullseye main contrib non-free" | sudo tee /etc/apt/sources.list.d/whonix.list
            ;;
        2)
	        curl --tlsv1.3 --proto =https --max-time 180 --output ~/derivative.asc https://www.kicksecure.com/keys/derivative.asc
	        mv ~/derivative.asc /usr/share/keyrings/derivative.asc
	        echo "deb [signed-by=/usr/share/keyrings/derivative.asc] https://deb.kicksecure.com bullseye main contrib non-free" | sudo tee /etc/apt/sources.list.d/derivative.list
            ;;
        3)
            echo "------------ GETTING BRAVE KEYS -----------"
            curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main"| tee /etc/apt/sources.list.d/brave-browser-release.list
            ;;
        4)
            echo "------------ GETTING CODIUM KEYS -----------"
            wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg     | gpg --dearmor     | dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg
            echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://download.vscodium.com/debs vscodium main'     | tee /etc/apt/sources.list.d/vscodium.list
            ;;
        5)
            echo "------------ GETTING OXEN KEYS -----------"
            curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
            echo "deb https://deb.oxen.io bullseye main" | tee /etc/apt/sources.list.d/oxen.list
            ;;
        *)
            echo "Choix invalide : $choice"
            ;;
    esac
done


echo "------------UPDATING WITH NEW SOURCES.LIST + INSTALLING -----------"
sudo apt-get update && sudo apt-get dist-upgrade && sudo apt-get autoremove && sudo apt-get autoclean


echo "Which installation do you want to do?"
echo "1) NORMAL (Extensive list of packages required to compile/build projects)"
echo "2) EXTRA (Desktop, thunderbird)"
read choice

if [ $choice = "1" ]; then
    sudo apt-get install -y mosh macchanger jitterentropy-rngd hddtemp lm-sensors htop tree hardened-kernel bison build-essential curl git gnat libncurses5-dev m4 zlib1g-dev build-essential zlib1g-dev uuid-dev libdigest-sha-perl libelf-dev bc bzip2 bison flex git gnupg gawk iasl m4 nasm patch python python2 python3 wget gnat cpio ccache pkg-config cmake libusb-1.0-0-dev autoconf texinfo ncurses-dev doxygen graphviz udev libudev1 libudev-dev automake libtool rsync innoextract sudo libssl-dev device-tree-compiler u-boot-tools
	if [ -f /etc/apt/sources.list.d/whonix.list ]; then
	    sudo apt install kloak hardened-malloc
	fi
fi

if [ $choice = "2" ]; then
	sudo apt install ristretto thunderbird keepassxc fortunes vlc evince gedit qbittorrent gparted bleachbit ffmpeg fish fzf gedit
	if [ -f /etc/apt/sources.list.d/brave-browser-release.list ]; then
		sudo apt install brave-browser
    fi
	if [ -f /etc/apt/sources.list.d/vscodium.list ]; then		
		sudo apt install codium
	fi
    if [ -f /etc/apt/sources.list.d/oxen.list ]; then
		sudo apt install oxen-electron-wallet session-desktop
	fi
    if [[ -f /etc/apt/sources.list.d/oxen.list && dpkg -s systemd >/dev/null 2>&1 ]]; then
    	sudo apt install lokinet lokinet-gui
    fi

	desktop_environment=$(echo "$XDG_CURRENT_DESKTOP" | tr '[:upper:]' '[:lower:]')
    if [[ $desktop_environment = "xfce" && $desktop_environment = "lxqt" && $desktop_environment = "lxde" ]]; then
        	sudo apt install xscreensaver xscreensaver-data-extra lightdm-gtk-greeter-settings
    fi
fi

if systemctl status graphical.target | grep -q "Active: active"; then
    
    echo "Voulez-vous installer Veracrypt ? (y/n)"
    read veracrypt_choice

    echo "Voulez-vous installer Discord ? (y/n)"
    read discord_choice

    echo "Voulez-vous installer Exif-cleaner ? (y/n)"
    read exif_cleaner_choice

    if [[ $veracrypt_choice == "y" && $version = "11" ]]; then
        echo "------------ DL + INSTALL VERACRYPT -----------"
        aria2c https://launchpad.net/veracrypt/trunk/1.25.9/+download/veracrypt-1.25.9-Debian-11-amd64.deb
        sudo apt install -y ./veracrypt-*.deb
    fi

    if [[ $discord_choice == "y" ]]; then
        echo "------------ DL + INSTALL DISCORD -----------"
        aria2c https://discord.com/api/download?platform=linux&format=deb
        sudo apt install -y ./discord-*.deb
    fi

    if [[ $exif_cleaner_choice == "y" ]]; then
        echo "------------ DL + INSTALL EXIF-CLEANER -----------"
        aria2c https://github.com/szTheory/exifcleaner/releases/download/v3.6.0/exifcleaner_3.6.0_amd64.deb
        dpkg-deb -x exifcleaner_*_amd64.deb unpack
        dpkg-deb --control exifcleaner_*_amd64.deb 
        mv DEBIAN unpack
        cat > ./unpack/DEBIAN/control << "EOF"
        Package: exifcleaner
        Version: 3.6.0
        License: MIT
        Vendor: szTheory <szTheory@users.noreply.github.com>
        Architecture: amd64
        Maintainer: szTheory <szTheory@users.noreply.github.com>
        Installed-Size: 203446
        Depends: libgtk-3-0, libnotify4, libnss3, libxss1, libxtst6, xdg-utils, libatspi2.0-0, libuuid1, libayatana-appindicator3-1, libsecret-1-0
        Section: default
        Priority: extra
        Homepage: https://github.com/szTheory/exifcleaner#readme
        Description: 
        Clean exif metadata from images, videos, and PDF documents
        EOF
        dpkg -b unpack exif-fixed.deb
        sudo apt install -y ./exif-fixed.deb

    fi
fi


echo "------------UPDATING SYSCTL PARAMETERS -----------"
cat > /etc/sysctl.conf << "EOF"
#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#

#kernel.domainname = example.com

# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3

###################################################################
# Functions previously found in netbase
#

# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
#net.ipv4.conf.all.rp_filter=1

# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1

# Uncomment the next line to enable packet forwarding for IPv4
#net.ipv4.ip_forward=1

# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1


###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
# net.ipv4.conf.all.secure_redirects = 1
#
# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
#net.ipv4.conf.all.log_martians = 1
#

###################################################################
# Magic system request Key
# 0=disable, 1=enable all, >1 bitmask of sysrq functions
# See https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
# for what other values do
#kernel.sysrq=438

net.ipv4.conf.all.arp_filter=1
kernel.panic_on_oops=1
kernel.sysrq=0
kernel.yama.ptrace_scope=3
fs.file-max =9223372036854775807
fs.inotify.max_user_watches=524288
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1 
fs.suid_dumpable=0
kernel.core_uses_pid=1
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
kernel.kptr_restrict=2
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.perf_event_paranoid=3
kernel.pid_max=65536
kernel.randomize_va_space=2
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=0
net.core.bpf_jit_harden=2
net.core.netdev_max_backlog=250000
net.core.rmem_default=8388608
net.core.rmem_max=8388608
net.core.wmem_default=8388608
net.core.wmem_max=8388608
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.arp_announce=2
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.default.drop_gratuitous_arp=1
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.shared_media=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_base_mss=1024
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_rmem=4096 87380 8388608
net.ipv4.tcp_sack=0
net.ipv4.tcp_synack_retries=5
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0
net.ipv4.tcp_window_scaling=0
net.ipv4.tcp_wmem=4096 87380 8388608
#net.ipv6.conf.all.accept_ra=0
#net.ipv6.conf.all.accept_ra_defrtr=0
#net.ipv6.conf.all.accept_ra_pinfo=0
#net.ipv6.conf.all.accept_ra_rtr_pref=0
#net.ipv6.conf.all.accept_redirects=0
#net.ipv6.conf.all.accept_source_route=0
#net.ipv6.conf.all.autoconf=0
#net.ipv6.conf.all.dad_transmits=0
#net.ipv6.conf.all.forwarding=0
#net.ipv6.conf.all.max_addresses=1
#net.ipv6.conf.all.router_solicitations=0
#net.ipv6.conf.all.use_tempaddr=2
#net.ipv6.conf.default.accept_ra=0
#net.ipv6.conf.default.accept_ra_defrtr=0
#net.ipv6.conf.default.accept_ra_pinfo=0
#net.ipv6.conf.default.accept_ra_rtr_pref=0
#net.ipv6.conf.default.accept_redirects=0
#net.ipv6.conf.default.accept_source_route=0
#net.ipv6.conf.default.autoconf=0
#net.ipv6.conf.default.dad_transmits=0
#net.ipv6.conf.default.forwarding=0
#net.ipv6.conf.default.max_addresses=1
#net.ipv6.conf.default.router_solicitations=0
#net.ipv6.conf.default.use_tempaddr=2
vm.mmap_min_addr=65536
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
kernel.printk=3 3 3 3
dev.tty.ldisc_autoload=0
vm.unprivileged_userfaultfd=0
vm.max_map_count=1048576
kernel.core_pattern=|/bin/false
vm.swappiness=10
#net.ipv6.conf.default.disable_ipv6=1
#net.ipv6.conf.all.disable_ipv6=1

EOF

modprobe -r dccp
modprobe -r sctp
modprobe -r rds
modprobe -r tipc
modprobe -r n-hdlc
modprobe -r ax25
modprobe -r netrom
modprobe -r x25
modprobe -r rose
modprobe -r decnet
modprobe -r econet
modprobe -r af_802154
modprobe -r ipx
modprobe -r appletalk
modprobe -r psnap
modprobe -r p8023
modprobe -r p8022
modprobe -r can
modprobe -r atm
modprobe -r cramfs
modprobe -r freevxfs
modprobe -r jffs2
modprobe -r hfs
modprobe -r hfsplus
modprobe -r squashfs
modprobe -r udf
modprobe -r cifs
modprobe -r ksmbd
modprobe -r gfs2
modprobe -r vivid
modprobe -r bluetooth
modprobe -r btusb
modprobe -r uvcvideo

update-initramfs -u -k `uname -r` -v

echo "------------UPDATING GRUB PARAMETERS -----------"
cat > /etc/default/grub << "EOF"

# If you change this file, run 'update-grub' afterwards to update
# /boot/grub/grub.cfg.
# For full documentation of the options in this file, see:
#   info -f grub -n 'Simple configuration'

GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor slab_nomerge slub_debug=FZP init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality lsm=lockdown,yama,apparmor mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=seccomp tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force l1d_flush=on nosmt=force kvm.nx_huge_pages=force random.trust_cpu=off intel_iommu=on randomize_kstack_offset=1 page_poison=on rng_core.default_quality=500 ipv6.disable=1"

# Uncomment to enable BadRAM filtering, modify to suit your needs
# This works with Linux (no patch required) and with any kernel that obtains
# the memory map information from GRUB (GNU Mach, kernel of FreeBSD ...)
#GRUB_BADRAM="0x01234567,0xfefefefe,0x89abcdef,0xefefefef"

# Uncomment to disable graphical terminal (grub-pc only)
#GRUB_TERMINAL=console

# The resolution used on graphical terminal
# note that you can use only modes which your graphic card supports via VBE
# you can see them in real GRUB with the command `vbeinfo'
#GRUB_GFXMODE=640x480

# Uncomment if you don't want GRUB to pass "root=UUID=xxx" parameter to Linux
#GRUB_DISABLE_LINUX_UUID=true

# Uncomment to disable generation of recovery mode menu entries
#GRUB_DISABLE_RECOVERY="true"

# Uncomment to get a beep at grub start
#GRUB_INIT_TUNE="480 440 1"

EOF

echo "------------ TELLING X11 HE DOESN'T NEED ROOT ACCESS -----------"
cat > /etc/X11/Xwrapper.config << "EOF"
# Xwrapper.config (Debian X Window System server wrapper configuration file)
#
# This file was generated by the post-installation script of the
# xserver-xorg-legacy package using values from the debconf database.
#
# See the Xwrapper.config(5) manual page for more information.
#
# This file is automatically updated on upgrades of the xserver-xorg-legacy
# package *only* if it has not been modified since the last upgrade of that
# package.
#
# If you have edited this file but would like it to be automatically updated
# again, run the following command as root:
#   dpkg-reconfigure xserver-xorg-legacy
allowed_users=console
needs_root_rights = no
EOF

echo "------------ DEFAULTING MACHINE-ID IN /var -----------"
cat > /var/lib/dbus/machine-id << "EOF"
b08dfa6083e7567a1921a715000001fb
EOF

echo "------------ DEFAULTING MACHINE-ID IN /etc -----------"
cat > /etc/machine-id << "EOF"
b08dfa6083e7567a1921a715000001fb
EOF

echo "------------ SYSTEMD CORE DUMP -----------"
mkdir -p /etc/systemd/coredump.conf.d/
touch /etc/systemd/coredump.conf.d/disable.conf
cat > /etc/systemd/coredump.conf.d/disable.conf << "EOF"
[Coredump]
Storage=none
EOF

echo "------------ ULIMIT -----------"
cat > /etc/security/limits.conf << "EOF"
# /etc/security/limits.conf
#
#Each line describes a limit for a user in the form:
#
#<domain>        <type>  <item>  <value>
#
#Where:
#<domain> can be:
#        - a user name
#        - a group name, with @group syntax
#        - the wildcard *, for default entry
#        - the wildcard %, can be also used with %group syntax,
#                 for maxlogin limit
#        - NOTE: group and wildcard limits are not applied to root.
#          To apply a limit to the root user, <domain> must be
#          the literal username root.
#
#<type> can have the two values:
#        - "soft" for enforcing the soft limits
#        - "hard" for enforcing hard limits
#
#<item> can be one of the following:
#        - core - limits the core file size (KB)
#        - data - max data size (KB)
#        - fsize - maximum filesize (KB)
#        - memlock - max locked-in-memory address space (KB)
#        - nofile - max number of open file descriptors
#        - rss - max resident set size (KB)
#        - stack - max stack size (KB)
#        - cpu - max CPU time (MIN)
#        - nproc - max number of processes
#        - as - address space limit (KB)
#        - maxlogins - max number of logins for this user
#        - maxsyslogins - max number of logins on the system
#        - priority - the priority to run user process with
#        - locks - max number of file locks the user can hold
#        - sigpending - max number of pending signals
#        - msgqueue - max memory used by POSIX message queues (bytes)
#        - nice - max nice priority allowed to raise to values: [-20, 19]
#        - rtprio - max realtime priority
#        - chroot - change root to directory (Debian-specific)
#
#<domain>      <type>  <item>         <value>
#

#*               soft    core            0
#root            hard    core            100000
#*               hard    rss             10000
#@student        hard    nproc           20
#@faculty        soft    nproc           20
#@faculty        hard    nproc           50
#ftp             hard    nproc           0
#ftp             -       chroot          /ftp
#@student        -       maxlogins       4
* hard core 0
# End of file
EOF

cat > /etc/asound.conf << "EOF"
# Use PulseAudio plugin hw
pcm.!default {
   type plug
   slave.pcm hw
}
EOF

echo "------------ ENABLING JITTERENTROPY -----------"
cat > /usr/lib/modules-load.d/jitterentropy.conf << "EOF"
jitterentropy_rng
EOF

echo "------------ ENABLING APT SANDBOX -----------"
cat > /etc/apt/apt.conf.d/40sandbox << "EOF"
APT::Sandbox::Seccomp "true";
EOF

cat > /etc/sudoers << "EOF"

#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# This fixes CVE-2005-4890 and possibly breaks some versions of kdesu
# (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
Defaults	use_pty

# This preserves proxy settings from user environments of root
# equivalent users (group sudo)
#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

# This allows running arbitrary commands, but so does ALL, and it means
# different sudoers have their choice of editor respected.
#Defaults:%sudo env_keep += "EDITOR"

# Completely harmless preservation of a user preference.
#Defaults:%sudo env_keep += "GREP_COLOR"

# While you shouldn't normally run git as root, you need to with etckeeper
#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

# Per-user preferences; root won't have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

# Ditto for GPG agent
#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:


Cmnd_Alias UPDATE = /usr/bin/apt-get update
Cmnd_Alias UPGRADE = /usr/bin/apt-get dist-upgrade
Cmnd_Alias AUTOREMOVE = /usr/bin/apt-get autoremove
Cmnd_Alias AUTOCLEAN = /usr/bin/apt-get autoclean
Cmnd_Alias REBOOT = /sbin/reboot ""
Cmnd_Alias SHUTDOWN = /sbin/poweroff ""

@includedir /etc/sudoers.d
EOF

echo "Quel utilisateur doit être autorisé à mettre à jour le système sans le mot de passe de root ?"
read user

if [[ -z $user ]]; then
    echo "Nom d'utilisateur invalide."
    exit 1
fi

# Vérifier si l'utilisateur existe
if ! id -u $user >/dev/null 2>&1; then
    echo "L'utilisateur $user n'existe pas."
    exit 1
fi

# Modifier les lignes de /etc/sudoers
sed -i "s/^${user}.*$/#&/" /etc/sudoers
echo "${user} ALL=(root) NOPASSWD: /usr/bin/apt-get update" >> /etc/sudoers
echo "${user} ALL=(root) NOPASSWD: /usr/bin/apt-get dist-upgrade" >> /etc/sudoers
echo "${user} ALL=(root) NOPASSWD: /usr/bin/apt-get autoremove" >> /etc/sudoers
echo "${user} ALL=(root) NOPASSWD: /usr/bin/apt-get autoclean" >> /etc/sudoers
echo "${user} ALL=(root) NOPASSWD: /sbin/reboot" >> /etc/sudoers
echo "${user} ALL=(root) NOPASSWD: /sbin/poweroff" >> /etc/sudoers
echo "@includedir /etc/sudoers.d" >> /etc/sudoers


echo "Les autorisations de mise à jour du système ont été accordées à l'utilisateur $user."


cat > /etc/sudoers << "EOF"

#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# This fixes CVE-2005-4890 and possibly breaks some versions of kdesu
# (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
Defaults	use_pty

# This preserves proxy settings from user environments of root
# equivalent users (group sudo)
#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

# This allows running arbitrary commands, but so does ALL, and it means
# different sudoers have their choice of editor respected.
#Defaults:%sudo env_keep += "EDITOR"

# Completely harmless preservation of a user preference.
#Defaults:%sudo env_keep += "GREP_COLOR"

# While you shouldn't normally run git as root, you need to with etckeeper
#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

# Per-user preferences; root won't have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

# Ditto for GPG agent
#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:


Cmnd_Alias UPDATE = /usr/bin/apt-get update
Cmnd_Alias UPGRADE = /usr/bin/apt-get dist-upgrade
Cmnd_Alias AUTOREMOVE = /usr/bin/apt-get autoremove
Cmnd_Alias AUTOCLEAN = /usr/bin/apt-get autoclean
Cmnd_Alias REBOOT = /sbin/reboot ""
Cmnd_Alias SHUTDOWN = /sbin/poweroff ""

@includedir /etc/sudoers.d
EOF

update-grub && update-grub2

cat > .config/pulse/daemon.conf << "EOF"
resample-method = speex-float-10
flat-volumes = no
avoid-resampling = yes
default-sample-format = float32le
default-sample-rate = 48000
alternate-sample-rate = 44100
default-sample-channels = 2
default-channel-map = front-left,front-right
default-fragments = 2
default-fragment-size-msec = 125
resample-method = soxr-vhq
enable-lfe-remixing = no
high-priority = yes
nice-level = -11
realtime-scheduling = yes
realtime-priority = 9
rlimit-rtprio = 9
daemonize = no
EOF

#mkdir applications && cd applications
#git clone https://github.com/JKirchartz/fortunes.git
#git clone --recursive https://github.com/osresearch/heads.git
#git clone https://github.com/aristocratos/btop.git
#git clone https://github.com/GrapheneOS/hardened_malloc.git
#git clone https://gitlab.com/madaidan/secure-time-sync.git
#git clone --recursive https://github.com/oxen-io/lokinet
#git clone --recursive https://github.com/rizinorg/cutter.git
#git clone --recursive https://github.com/radareorg/radare2.git
#git clone https://github.com/andres-jurado/audiophile-linux.git

#echo "------------ Increasing the number of hashing rounds -----------"
#cat > /etc/pam.d/passwd << "EOF"
##
# The PAM configuration file for the Shadow `passwd' service
#

#@include common-password

#password required pam_unix.so sha512 shadow nullok rounds=65536

#EOF

#passwd


