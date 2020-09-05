# Mr Robot

10.10.5.30

## Scan

```
$ nmap -sV -sC -oA nmap/mrrobot 10.10.5.30
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-04 22:22 CDT
Nmap scan report for 10.10.5.30
Host is up (0.20s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  closed ssh
80/tcp  closed http
443/tcp closed https
```

```
curl -o mr_robot.html 10.10.5.30
```

Extract script tag content to `script.js`. Appears to be some kind of logging script that prints to the console

## Gobuster

```
$ gobuster dir -e -u http://10.10.5.30/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt 

/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/0 (Status: 301)
/0000 (Status: 301)
/Image (Status: 301)
/admin (Status: 301)
/atom (Status: 301)
/audio (Status: 301)
/blog (Status: 301)
/css (Status: 301)
/dashboard (Status: 302)
/favicon.ico (Status: 200)
/feed (Status: 301)
/image (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/index.php (Status: 301)
/intro (Status: 200)
/js (Status: 301)
/license (Status: 200)
/login (Status: 302)
/page1 (Status: 301)
/phpmyadmin (Status: 403)
/readme (Status: 200)
/rdf (Status: 301)
/robots (Status: 200)
/robots.txt (Status: 200)
/rss (Status: 301)
/rss2 (Status: 301)
/sitemap (Status: 200)
/sitemap.xml (Status: 200)
```

## Robots

```
10.10.5.30/robots.txt

User-agent: *
fsocity.dic
key-1-of-3.txt
```

## Key 1
```
curl -o key-1-of-3.txt 10.10.5.30/key-1-of-3.txt
cat key-1-of-3.txt
073403c8a58a1f80d943455fb30724b9
```

## FSocity.dic

```
curl -o fsocity.dic 10.10.5.30/fsocity.dic
```

Appears to be a wordlist of some kind

## MRROBOT/0

Browsing to http://10.10.5.30/0 and http://10.10.5.30/0000 appear to be word press sites. Perhaps there is a vulnerability here

## License

http://10.10.5.30/license

<blockquote>
what you do just pull code from Rapid9 or some s@#% since when did you become a script kitty?<br>
do you want a password or something?<br>
ZWxsaW90OkVSMjgtMDY1Mgo=
</blockquote>

```
echo "ZWxsaW90OkVSMjgtMDY1Mgo=" | base64 -d
elliot:ER28-0652
```

Can use this user/pass to log into wordpress as admin role
