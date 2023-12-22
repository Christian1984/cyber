# privilege escalation

the goal here is to get root/administrator access to the machine.

## checklists

- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://book.hacktricks.xyz/welcome/readme

## enumeration scripts

- linux:
  - https://github.com/rebootuser/LinEnum
  - https://github.com/sleventyeleven/linuxprivchecker
- win:
  - https://github.com/GhostPack/Seatbelt
  - https://github.com/411Hall/JAWS
- both:
  - https://github.com/carlospolop/PEASS-ng

> note: these scripts will run many commands known for identifying vulnerabilities and create a lot of "noise" that may trigger anti-virus software or security monitoring software that looks for these types of events. this may prevent the scripts from running or even trigger an alarm that the system has been compromised. in some instances, we may want to do a manual enumeration instead of running scripts.

linPEAS can easily be run with `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`.

## other approaches

### kernel exploits

whenever we encounter a server running an old operating system, we should start by looking for potential kernel vulnerabilities that may exist. suppose the server is not being maintained with the latest updates and patches. in that case, it is likely vulnerable to specific kernel exploits found on unpatched versions of linux and windows.

### vulnerable software

use `dpkg -l` or look at `C:\Program Files` for installed software and vulnerabilities

## user privileges

- check if user is in the list of sudoers and what commands he may excute. to do so, run `sudo -l`, and/or read `/etc/sudoers`.q
- to switch to the root user, use `sudo su -`

Once we find a particular application we can run with sudo, we can look for ways to exploit it to get a shell as the root user. GTFOBins contains a list of commands and how they can be exploited through sudo. We can search for the application we have sudo privilege over, and if it exists, it may tell us the exact command we should execute to gain root access using the sudo privilege we have.

- https://gtfobins.github.io/
- https://lolbas-project.github.io/#

## scheduled tasks

there are usually two ways to take advantage of scheduled tasks (windows) or cron jobs (linux) to escalate our privileges:

- add new scheduled tasks/cron jobs
- trick them to execute a malicious software

to add schedules tasks, check if we have write permission to any of these typical files and folders

- /etc/crontab
- /etc/cron.d
- /var/spool/cron/crontabs/root

> if we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

## exposed credentials

next, we can look for files we can read and see if they contain any exposed credentials. this is very common with configuration files, log files, and user history files (bash_history in linux and psreadline in windows). the enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us.

if a password was found, we may also check for password reuse, as the system user may have used their password for the databases, which may allow us to use the same password to switch to that user, as follows:

## ssh keys

if we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server. if we can read the `/root/.ssh/` directory and can read the id_rsa file, we can copy it to our machine and use the `-i` flag to log in with it:

```
ChrisVomRhein@htb[/htb]$ vim id_rsa
ChrisVomRhein@htb[/htb]$ chmod 600 id_rsa
ChrisVomRhein@htb[/htb]$ ssh user@10.10.10.10 -i id_rsa

root@remotehost#
```

> note that we used the command 'chmod 600 id_rsa' on the key after we created it on our machine to change the file's permissions to be more restrictive. if ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.

if we find ourselves with write access to a users/.ssh/ directory, we can place our public key in the user's ssh directory at /home/user/.ssh/authorized_keys. this technique is usually used to gain ssh access after gaining a shell as that user.
