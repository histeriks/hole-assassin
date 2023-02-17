#!/bin/bash
# ubuntu18-20 hardening & optimization frankenscript
# assembled by root @ root.tips on february 2nd 2023
# vegan alert:  may contain cartilages & hairy bits!
# ##################################################

XS_APTIPV4="yes"
XS_APTUPGRADE="yes"
XS_BASHRC="yes"
XS_DISABLERPC="yes"
XS_ENTROPY="yes"
XS_FAIL2BAN="yes"
XS_GUESTAGENT="yes"
XS_IFUPDOWN2="yes"
XS_JOURNALD="yes"
XS_KERNELHEADERS="yes"
XS_KEXEC="yes"
XS_KSMTUNED="yes"
XS_LANG="en_US.UTF-8"
XS_LIMITS="yes"
XS_LOGROTATE="yes"
XS_LYNIS="yes"
XS_MAXFS="yes"
XS_MEMORYFIXES="yes"
XS_NET="yes"
XS_NOAPTLANG="yes"
XS_PIGZ="yes"
XS_SWAPPINESS="yes"
XS_TCPBBR="yes"
XS_TCPFASTOPEN="yes"
XS_TIMESYNC="yes"
XS_TIMEZONE=""
XS_UTILS="yes"
XS_PSAD="yes"
XS_COMP="yes"
XS_ARTI="yes"
XS_KERN="yes"
XS_IPTABLES="yes"
XS_SSHD="yes"
XS_TEMP="yes"
XS_LOGIN="yes"
XS_UPGR="yes"
XS_ACCT="yes"
XS_SYSSTAT="yes"
XS_ARPWATCH="yes"
XS_PERMISS="yes"
XS_AUDITD="yes"
XS_VARIOUS="yes"

clear
echo -e "\033[5m\e[1m\e[104m\e[93mprocessing...\e[0m"

if [ "$XS_LANG" == "" ] ; then
XS_LANG="en_US.UTF-8"
fi
export LANG="$XS_LANG"
export LC_ALL="C"

RAM_SIZE_GB=$(( $(vmstat -s | grep -i "total memory" | xargs | cut -d" " -f 1) / 1024 / 1000))

apt-get update > /dev/null 2>&1

apt-get -y install apt-transport-https ca-certificates curl

if [ "$XS_UTILS" == "yes" ] ; then
    apt-get -y install \
    axel \
    build-essential \
    dialog \
    dnsutils \
    dos2unix \
    git \
    gnupg-agent \
    grc \
    htop \
    iftop \
    iotop \
    iperf \
    ipset \
    iptraf \
    mlocate \
    msr-tools \
    nano \
    net-tools \
    omping \
    software-properties-common \
    sshpass \
    tmux \
    unzip \
    vim \
    vim-nox \
    wget \
    whois \
    zip
fi

if [ "$XS_LYNIS" == "yes" ] ; then
wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key | apt-key add -
echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" > /etc/apt/sources.list.d/cisofy-lynis.list
apt-get update > /dev/null 2>&1
apt-get -y install lynis
fi

if [ "$XS_KSMTUNED" == "yes" ] ; then
apt-get -y install ksm-control-daemon
    if [[ RAM_SIZE_GB -le 16 ]] ; then
        KSM_THRES_COEF=50
        KSM_SLEEP_MSEC=80
    elif [[ RAM_SIZE_GB -le 32 ]] ; then
        KSM_THRES_COEF=40
        KSM_SLEEP_MSEC=60
    elif [[ RAM_SIZE_GB -le 64 ]] ; then
        KSM_THRES_COEF=30
        KSM_SLEEP_MSEC=40
    elif [[ RAM_SIZE_GB -le 128 ]] ; then
        KSM_THRES_COEF=20
        KSM_SLEEP_MSEC=20
    else
        KSM_THRES_COEF=10
        KSM_SLEEP_MSEC=10
    fi
sed -i -e "s/\# KSM_THRES_COEF=.*/KSM_THRES_COEF=${KSM_THRES_COEF}/g" /etc/ksmtuned.conf
sed -i -e "s/\# KSM_SLEEP_MSEC=.*/KSM_SLEEP_MSEC=${KSM_SLEEP_MSEC}/g" /etc/ksmtuned.conf
systemctl enable ksmtuned
systemctl restart ksmtuned
fi

apt-get -y install qemu-guest-agent open-vm-tools virtualbox-guest-utils

if [ "$XS_FAIL2BAN" == "yes" ] ; then
apt-get -y install fail2ban
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
banaction = iptables-ipset-proto4
EOF
systemctl enable fail2ban
systemctl restart fail2ban
fi

if [ "$XS_LIMITS" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-maxwatches.conf
fs.inotify.max_user_watches=1048576
fs.inotify.max_user_instances=1048576
fs.inotify.max_queued_events=1048576
EOF
cat <<EOF >> /etc/security/limits.d/99-xs-limits.conf
* soft     nproc          256000
* hard     nproc          256000
* soft     nofile         256000
* hard     nofile         256000
root soft     nproc          256000
root hard     nproc          256000
root soft     nofile         256000
root hard     nofile         256000
EOF
cat <<EOF > /etc/sysctl.d/99-xs-maxkeys.conf
kernel.keys.root_maxkeys=1000000
kernel.keys.maxkeys=1000000
EOF
echo "DefaultLimitNOFILE=256000" >> /etc/systemd/system.conf
echo "DefaultLimitNOFILE=256000" >> /etc/systemd/user.conf
echo 'session required pam_limits.so' >> /etc/pam.d/common-session
echo 'session required pam_limits.so' >> /etc/pam.d/runuser-l
echo "ulimit -n 256000" >> /root/.profile
fi

if [ "$XS_LOGROTATE" == "yes" ] ; then
cat <<EOF > /etc/logrotate.conf
daily
su root adm
rotate 7
create
compress
size=10M
delaycompress
copytruncate
include /etc/logrotate.d
EOF
systemctl restart logrotate
fi

if [ "$XS_JOURNALD" == "yes" ] ; then
cat <<EOF > /etc/systemd/journald.conf
[Journal]
Storage=persistent
SplitMode=none
RateLimitInterval=0
RateLimitIntervalSec=0
RateLimitBurst=0
ForwardToSyslog=no
ForwardToWall=yes
Seal=no
Compress=yes
SystemMaxUse=64M
RuntimeMaxUse=60M
MaxLevelStore=warning
MaxLevelSyslog=warning
MaxLevelKMsg=warning
MaxLevelConsole=notice
MaxLevelWall=crit
EOF
systemctl restart systemd-journald.service
journalctl --vacuum-size=64M --vacuum-time=1d;
journalctl --rotate
fi

if [ "$XS_ENTROPY" == "yes" ] ; then
apt-get -y install haveged
cat <<EOF > /etc/default/haveged
DAEMON_ARGS="-w 1024"
EOF
systemctl daemon-reload
systemctl enable haveged
systemctl restart haveged
fi

if [ "$XS_MEMORYFIXES" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-memory.conf
vm.min_free_kbytes=524288
vm.nr_hugepages=72
vm.max_map_count=262144
vm.overcommit_memory = 1
EOF
fi

if [ "$XS_TCPBBR" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-kernel-bbr.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
fi

if [ "$XS_TCPFASTOPEN" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-tcp-fastopen.conf
net.ipv4.tcp_fastopen=3
EOF
fi

if [ "$XS_NET" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-net.conf
net.core.netdev_max_backlog=8192
net.core.optmem_max=8192
net.core.rmem_max=16777216
net.core.somaxconn=8151
net.core.wmem_max=16777216
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_challenge_ack_limit = 999999999
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=240
net.ipv4.tcp_limit_output_bytes=65536
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_rmem=8192 87380 16777216
net.ipv4.tcp_sack=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_wmem=8192 65536 16777216
net.netfilter.nf_conntrack_generic_timeout = 60
net.netfilter.nf_conntrack_helper=0
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 28800
net.unix.max_dgram_qlen = 4096
EOF
fi

if [ "$XS_SWAPPINESS" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-swap.conf
vm.swappiness=10
EOF
fi

if [ "$XS_MAXFS" == "yes" ] ; then
cat <<EOF > /etc/sysctl.d/99-xs-fs.conf
fs.nr_open=12000000
fs.file-max=9000000
EOF
fi

if [ "$XS_BASHRC" == "yes" ] ; then
cat <<EOF > ~/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
[ -z "$PS1" ] && return
HISTCONTROL=ignoredups:ignorespace
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac
force_color_prompt=yes
if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi
if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
    . /etc/bash_completion
fi
export HISTTIMEFORMAT="%d/%m/%y %T "
export PS1='\u@\h:\W $ '
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
source /etc/profile.d/bash_completion.sh
export PS1="\[\e[31m\][\[\e[m\]\[\e[38;5;172m\]\u\[\e[m\]@\[\e[38;5;153m\]\h\[\e[m\] \[\e[38;5;214m\]\W\[\e[m\]\[\e[31m\]]\[\e[m\]\$ "
EOF

echo "source /root/.bashrc" >> /root/.bash_profile
fi

if [ "$XS_PSAD" == "yes" ] ; then
apt install psad -y
sed -i -e "s/ENABLE_AUTO_IDS             N;/ENABLE_AUTO_IDS             Y;/g" /etc/psad/psad.conf
systemctl enable psad
systemctl start psad
psad --sig-update
systemctl restart psad
fi

if [ "$XS_LOGIN" == "yes" ] ; then
cat <<EOF > /etc/login.defs
# /etc/login.defs - Configuration control definitions for the login package.
MAIL_DIR        /var/mail
FAILLOG_ENAB        yes
LOG_UNKFAIL_ENAB    no
LOG_OK_LOGINS       no
SYSLOG_SU_ENAB      yes
SYSLOG_SG_ENAB      yes
FTMP_FILE   /var/log/btmp
SU_NAME     su
HUSHLOGIN_FILE  .hushlogin
ENV_SUPATH  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH    PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
TTYGROUP    tty
TTYPERM     0600
ERASECHAR   0177
KILLCHAR    025
UMASK       027
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   7
UID_MIN          1000
UID_MAX         60000
GID_MIN          1000
GID_MAX         60000
LOGIN_RETRIES       5
LOGIN_TIMEOUT       60
CHFN_RESTRICT       rwh
DEFAULT_HOME    yes
USERGROUPS_ENAB yes
ENCRYPT_METHOD SHA512
EOF
fi

if [ "$XS_TEMP" == "yes" ] ; then
clear
echo "creating /tmp filesystem & setting right permissions"
dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000 status=progress
mkdir /tmpbackup
cp -Rpf /tmp /tmpbackup
mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
chmod 1777 /tmp
cp -Rpf /tmpbackup/* /tmp/
rm -rf /tmpbackup
echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
sudo mount -o remount /tmp
echo "done!"
sleep 3
fi

if [ "$XS_SSHD" == "yes" ] ; then
cat <<EOF > /etc/ssh/sshd_config
Port 372
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
SyslogFacility AUTH
ClientAliveCountMax 2
Compression no
LogLevel VERBOSE
MaxAuthTries 2
MaxSessions 2
LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
UseDNS no
MaxStartups 2
Banner /etc/motd
EOF
fi

clear
echo -e "\033[5m\e[1m\e[104m\e[93mSSH PORT CHANGED TO 372, USE \e[97m"ssh user@host -p 372"\033[5m\e[1m\e[104m\e[93m FROM NOW ON WHEN CONNECTING!\e[0m"
sleep 7
clear

if [ "$XS_IPTABLES" == "yes" ] ; then
cat <<EOF > /etc/init.d/iptables.sh
#! /bin/sh
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -j LOG
iptables -A FORWARD -j LOG
iptables -A INPUT -i lo -p all -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 13 -j DROP
iptables -A INPUT -p icmp --icmp-type 17 -j DROP
iptables -A INPUT -p icmp --icmp-type 14 -j DROP
iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
iptables -A INPUT -p tcp -m tcp --dport 372 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
EOF
chmod +x /etc/init.d/iptables.sh
ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
fi

if [ "$XS_KERN" == "yes" ] ; then
cat <<EOF > /etc/sysctl.conf
# kernel sysctl conf
net.ipv4.ip_forward = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
vm.panic_on_oom = 1
kernel.panic = 30
kernel.panic_on_oops = 30
kernel.exec-shield = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.secure_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
fs.suid_dumpable = 0
EOF
cat <<EOF > /etc/default/ufw
# /etc/default/ufw
IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="DROP"
DEFAULT_APPLICATION_POLICY="SKIP"
MANAGE_BUILTINS=no
IPT_SYSCTL=/etc/sysctl.conf
IPT_MODULES="nf_conntrack_ftp nf_nat_ftp nf_conntrack_netbios_ns"
EOF
sysctl -e -p
fi

if [ "$XS_COMP" == "yes" ] ; then
echo "disabling the compilers..."
chmod 000 /usr/bin/as >/dev/null 2>&1
chmod 000 /usr/bin/byacc >/dev/null 2>&1
chmod 000 /usr/bin/yacc >/dev/null 2>&1
chmod 000 /usr/bin/bcc >/dev/null 2>&1
chmod 000 /usr/bin/kgcc >/dev/null 2>&1
chmod 000 /usr/bin/cc >/dev/null 2>&1
chmod 000 /usr/bin/gcc >/dev/null 2>&1
chmod 000 /usr/bin/*c++ >/dev/null 2>&1
chmod 000 /usr/bin/*g++ >/dev/null 2>&1
echo ""
echo "to enable again restore permissions. for example: chmod 755 /usr/bin/gcc"
sleep 10
clear
fi

if [ "$XS_UPGR" == "yes" ] ; then
dpkg-reconfigure -plow unattended-upgrades
fi

if [ "$XS_ACCT" == "yes" ] ; then
apt-get install -y acct
touch /var/log/wtmp
fi

if [ "$XS_SYSSTAT" == "yes" ] ; then
apt-get install -y sysstat
sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
systemctl enable sysstat
service sysstat start
fi

if [ "$XS_ARPWATCH" == "yes" ] ; then
apt install -y arpwatch
systemctl enable arpwatch.service
service arpwatch start
fi

if [ "$XS_PERMISS" == "yes" ] ; then
chmod -R g-wx,o-rwx /var/log/*
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow
chown root:root /etc/passwd-
chmod 600 /etc/passwd-
chown root:root /etc/shadow-
chmod 600 /etc/shadow-
chown root:root /etc/group-
chmod 600 /etc/group-
chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-
fi

if [ "$XS_AUDITD" == "yes" ] ; then
apt-get install -y auditd

cat <<EOF > /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 6
max_log_file_action = keep_logs
space_left = 75
space_left_action = email
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = SUSPEND
disk_error_action = SUSPEND
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF

cat <<EOF > /etc/audit/auditd.rules
-D
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/run/wtmp -p wa -k session
-w /var/run/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

systemctl enable auditd
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1 audit=1"/g' /etc/default/grub
update-grub
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
"-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
-k privileged" } ' >> /etc/audit/audit.rules
echo " " >> /etc/audit/audit.rules
echo "#End of Audit Rules" >> /etc/audit/audit.rules
echo "-e 2" >>/etc/audit/audit.rules
cp /etc/audit/audit.rules /etc/audit/rules.d/audit.rules
fi

# VARIOUS OTHER SETTINGS
if [ "$XS_VARIOUS" == "yes" ] ; then
# disabling network protocols and filesystems
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

chmod -R g-wx,o-rwx /var/log/*
chown root:root /etc/cron*
chmod og-rwx /etc/cron*
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
    usermod -s /usr/sbin/nologin $user
  fi
  fi
done

usermod -g 0 root
sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc
apt-get remove -y telnet
echo "* hard core 0" >> /etc/security/limits.conf

cat <<EOF > /etc/motd
################################################################################
              All connections are monitored and recorded
  Intrusion attempts will be reported to appropriate Law Enforcement Agencies
################################################################################
EOF

cp /etc/motd /etc/issue && cp /etc/motd /etc/issue.net
chown root:root /etc/motd /etc/issue /etc/issue.net
chmod 644 /etc/motd /etc/issue /etc/issue.net
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

cat <<EOF > /etc/pam.d/common-passwd
password    requisite           pam_pwquality.so  try_first_pass retry=3
password    [success=1 default=ignore]  pam_unix.so obscure use_authtok try_first_pass sha512
password    requisite           pam_deny.so
password    required            pam_permit.so
password sufficient pam_unix.so remember=5
EOF

cat <<EOF > /etc/security/pwquality.conf
minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1
EOF

cat <<EOF > /etc/pam.d/common-auth
auth    [success=1 default=ignore]  pam_unix.so nullok_secure
auth    requisite           pam_deny.so
auth    required            pam_permit.so
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
EOF

echo tty1 > /etc/securetty
chmod 0600 /etc/securetty
chmod 700 /root
chmod 600 /boot/grub/grub.cfg
apt purge -y at
apt install -y libpam-cracklib
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
fi

clear
echo -e "\033[1;32m\033[40m####################################################"
echo -e "\033[1;32m\033[40m####################################################"
echo -e "\033[1;32m\033[40m##                                                ##"
echo -e "\033[1;32m\033[40m##\033[1;93m  SYSTEM HARDENING & OPTIMIZATION SUCCESSFULL!\033[1;32m\033[40m  ##"
echo -e "\033[1;32m\033[40m##\033[5m   press \033[1;91mR\033[1;32m\033[40m to reboot or any other key to quit   \033[0m\033[1;32m\033[40m##"
echo -e "\033[1;32m\033[40m##                                                ##"
echo -e "\033[1;32m\033[40m####################################################"
echo -e "\033[1;32m\033[40m####################################################"

read -n1 confirm
if echo $confirm | grep '^[Rr]\?$'; then
reboot
fi
echo -e "quitting instead of rebooting. please do reboot as soon as you're done making changes! thanks"
exit 0
