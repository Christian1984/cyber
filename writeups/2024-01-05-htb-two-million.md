---
machine: two million
date: 2024-01-05
url: https://app.hackthebox.com/machines/TwoMillion
---

# two million

## recon

as usual i ran several nmap scans against the target. the full-range scan didn't reveal anything in addition, so we'll take a closer look at the scan where i ran the default scripts against the previously identified open ports:

```
$ nmap 10.10.11.221 -sV -oA two-million-nmap-scripts -sC -p22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-05 10:04 EST
Nmap scan report for 10.10.11.221
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds
```

as we can see, there's a redirect to the vhost `2million.htb`, and a curl supports this...

```
$ curl 10.10.11.221 -i                
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Fri, 05 Jan 2024 15:08:41 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive
Location: http://2million.htb/

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

let's add this host to our local `/etc/hosts` file.

```
$ echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.10.11.221 2million.htb
```

when we now browse to the server's ip address or `curl -L`, we get redirected here:

![2million.htb](images/2024-01-05-htb-two-million/twomillion-htb.png)

when browsing the website i find a few things of interest:

1. there is an faq section and it tells us that we will want to solve an entry-level-challenge that is presented "here". here takes us to an invite form at http://2million.htb/invite - i assume that the invite code will be somewhere in the page source

2. there is a high score list at the bottom of the page with links that look like this: https://www.hackthebox.eu/profile/2846 - they lead nowhere, neither inside the vpn nor outside. we might want to add this to our `/etc/hosts` file, but on the other hand it doesn't really look like these typical .htb addresses that we encounter often.

i might return to #2 later. also, we might consider enumerating subdomains/vhosts and directories on the machine. however, i have the feeling that i should focus on finding that invite code first...

for both the landing page and the /invite page i looked at both the source code and the console output in the dev tools. nothing special here. the invite page, however, loads a suspicious script: `/js/inviteapi.min.js` - a few ideas:

1. deobfuscate the script and see where it takes us. my assumption is that the code is here!

2. looking at the embedded script, we can see that on submit the page will call `/api/v1/invite/verify` and then evaluate the response locally and forward us to `/register`. on register, the embedded script will insert the previously entered code and submit it to `/api/v1/user/register`. we could check what this endpoint does and if it even takes the code into consideration.

i'll try #2 first, even though i think #1 is more promising. i just wanna see what this api does... maybe, we do not even need the code at all. then i will look at #1.

i think this is a good use case for burp suite, so let's fire it up... i removed the `readonly` property from the form so that i could enter some random invite code into the input element, filled out all other fields with dummy data, and passed it through burp:

```
POST /api/v1/user/register HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 90
Origin: http://2million.htb
Connection: close
Referer: http://2million.htb/register
Cookie: PHPSESSID=5329jc4e6qlsbpo2bo5mttprt0
Upgrade-Insecure-Requests: 1

code=hallo&username=hans&email=hans%40byom.de&password=passwd&password_confirmation=passwd
```

```
HTTP/1.1 302 Found

Server: nginx
Date: Sat, 06 Jan 2024 07:31:32 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /register?error=Code+is+invalid!
Content-Length: 0
```

and as expected, we get a "Code is invalid" response. fair enough. let's now look at the script...

... this looks promising! looking at the function signature (`function(p, a, c, k, e, d)`) suggests that packer was used to minify and obfuscate the code. so let's run it through https://matthewfl.com/unPacker.html, which yields:

```js
function verifyInviteCode(code)
	{
	var formData=
		{
		"code":code
	};
	$.ajax(
		{
		type:"POST",dataType:"json",data:formData,url:'/api/v1/invite/verify',success:function(response)
			{
			console.log(response)
		}
		,error:function(response)
			{
			console.log(response)
		}
	}
	)
}
function makeInviteCode()
	{
	$.ajax(
		{
		type:"POST",dataType:"json",url:'/api/v1/invite/how/to/generate',success:function(response)
			{
			console.log(response)
		}
		,error:function(response)
			{
			console.log(response)
		}
	}
	)
}
```

and that second method and api endpoint look interesting. so let's send a POST request there via curl:

```
$ curl http://2million.htb/api/v1/invite/how/to/generate -X POST | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   249    0   249    0     0   3785      0 --:--:-- --:--:-- --:--:--  3830
{
  "0": 200,                                                                                                       
  "success": 1,                                                                                                   
  "data": {                                                                                                       
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",               
    "enctype": "ROT13"                                                                                            
  },                                                                                                              
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."         
} 
```

as the hint suggests the data is encrypted. and, kindly enough, the data section even gives us the encryption type, which is ROT13, or ceasar. we can use `tr` to decrypit it, for example:

```
$ echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
https://www.hackthebox.eu/
```

all we need is some indicator that let's us now how the letters where shifted (a shift by 13 letters is the standard ROT13). sometimes we need to guess, but here we have a pretty good indicator. the end looks like a url, and i bet that `/ncv/i1` decrypts to `/api/v1`. so, in fact, "a" was encrypted as "n" and we can decrypt the message exactly as we did with the example:

```
$ echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

let's do it:

```
$ curl http://2million.htb/api/v1/invite/generate -X POST | jq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    91    0    91    0     0   1520      0 --:--:-- --:--:-- --:--:--  1542
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "SDZGQUEtSkU5NEwtUVNFTUEtVDA5Qk0=",
    "format": "encoded"
  }
}
```

there it is, but it is still encoded, as the `format` field suggests. this looks very base64-ish, so lets decode it:

```
$ echo SDZGQUEtSkU5NEwtUVNFTUEtVDA5Qk0= | base64 -d
H6FAA-JE94L-QSEMA-T09BM
```

with this code, we can now officially proceed through the signup and login flow to log in to our dashboard:

![2million dashboard](images/2024-01-05-htb-two-million/dashboard.png)

to sum up: to get to this point, we have identified the following pages and api endpoints:

```
- http://2million.htb/
- http://2million.htb/invite
- http://2million.htb/register
- http://2million.htb/api/v1/invite/verify
- http://2million.htb/api/v1/invite/register
- http://2million.htb/api/v1/invite/how/to/generate
- http://2million.htb/api/v1/invite/generate
```

plus this script

```
- http://2million.htb/js/inviteapi.min.js
```

we did most of by following breadcrumbs in the source code. i bet that we would also have found this generate endpoint by dirbusting the application.

so let's look closer at the page that we have at hand... many of the pages that have links in the main navigation do not work properly. those that do:

```
- http://2million.htb/home
- http://2million.htb/home/rules
- http://2million.htb/home/changelog
- http://2million.htb/home/access
```

i verified this with a `curl 'http://2million.htb/home' ... | grep href` that i had copied from firefox (to include the session cookie) and it looks like i didn't miss anything. despite two social media links everything else appears to be pointing to `#`.

the regenerate button on the access-page let's us, indeed, download new vpn credentials. i checked the file, but it does not look very interesting... let's see if it actually works.

i added the host of the vpn server to `/etc/hosts` and then tried it, but i always get a connection refused.

```
$ sudo openvpn chrisvomrhein.ovpn
2024-01-06 03:29:04 WARNING: Compression for receiving enabled. Compression has been used in the past to break encryption. Sent packets are not compressed unless "allow-compression yes" is also set.
2024-01-06 03:29:04 Note: --data-cipher-fallback with cipher 'AES-128-CBC' disables data channel offload.
2024-01-06 03:29:04 OpenVPN 2.6.7 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2024-01-06 03:29:04 library versions: OpenSSL 3.0.11 19 Sep 2023, LZO 2.10
2024-01-06 03:29:04 DCO version: N/A
2024-01-06 03:29:04 TCP/UDP: Preserving recently used remote address: [AF_INET]10.10.11.221:1337
2024-01-06 03:29:04 Socket Buffers: R=[212992->212992] S=[212992->212992]
2024-01-06 03:29:04 UDPv4 link local: (not bound)
2024-01-06 03:29:04 UDPv4 link remote: [AF_INET]10.10.11.221:1337
2024-01-06 03:29:04 read UDPv4 [ECONNREFUSED]: Connection refused (fd=3,code=111)
2024-01-06 03:29:06 read UDPv4 [ECONNREFUSED]: Connection refused (fd=3,code=111)
...
```

let's run nmap to see if there's anything running at the 1337 port that we may have missed before:

```
$ nmap 10.10.11.221 -p1337                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-06 03:32 EST
Nmap scan report for 2million.htb (10.10.11.221)
Host is up (0.026s latency).

PORT     STATE  SERVICE
1337/tcp closed waste

Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

nothing there.

at this point i felt a bit lost and i briefly looked at the official writeup. it appears that the next step is enumerating the backend api. when we click the "connection pack" button, we can see in the developer tools that a request is fired against the api endpoint `http://2million.htb/api/v1/user/vpn/generate`. let's see if there are more endpoints...

// TODO

## initial foothold

## user flag

## escalation to root