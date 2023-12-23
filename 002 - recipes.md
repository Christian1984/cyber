# 1

- ping ip
- nmap ip
- deep nmap: `nmap <ip> -sC -sV -p- [-v] [--min-rate 1000]`
- found http server?
  - browse to domain
  - check with Wappalizer https://www.wappalyzer.com/
- stumbled accross a domain? enter into `/etc/hosts`
  - enumerate subdomains with gobuster in vhost mode: `gobuster vhost -u <ip/domain, both with protocol, e.g. http://thetoppers.htbgobus> -w <wordlist> --append-domain`
  - add subdomains to `/etc/hosts`
  - rinse, repeat

# 2

- enumeration/scanning with nmap - perform a quick scan for open ports followed by a full port scan
- web footprinting - check any identified web ports for running web applications, and any hidden files/directories. some useful tools for this phase include whatweb and gobuster
- if you identify the website url, you can add it to your '/etc/hosts' file with the ip you get in the question below to load it normally, though this is unnecessary.
- after identifying the technologies in use, use a tool such as searchsploit to find public exploits or search on google for manual exploitation techniques
- after gaining an initial foothold, use the python3 pty trick to upgrade to a pseudo tty
- perform manual and automated enumeration of the file system, looking for misconfigurations, services with known vulnerabilities, and sensitive data in cleartext such as credentials
- organize this data offline to determine the various ways to escalate privileges to root on this target
- there are two ways to gain a foothold—one using metasploit and one via a manual process. challenge ourselves to work through and gain an understanding of both methods.

(https://academy.hackthebox.com/module/77/section/859)
