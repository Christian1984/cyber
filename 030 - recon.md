# Recon

## Wordlists

- https://github.com/danielmiessler/SecLists/tree/master

# service scanning

## tools

### nmap:

- scan for open ports
- use `-A` to run "everything" (os detection, version detection, script scanning and traceroute (run with `sudo` for traceroute))
- use `sC` to run the default scipts against the target, i.e. `--script=default`
- use `sV` to probe open ports for service/version info
- by default, it scans the most common ports. use
  - `-p-` to scan all 65k-ish ports, or
  - `-p100-200` to specify a range, or
  - `p21,22` to specify exact ports
- use `-v` for verbose output, also to report ports on the fly as they are detected
- use `-oA <filename>` to output to a file

# web enumeration

After discovering a web application, it is always worth checking to see if we can uncover any hidden files or directories on the webserver that are not intended for public access.

## strategies

- check robots.txt for hidden paths
- use gobuster in dir mode and dns mode to reveal hidden resources
- use whatweb to identify software, plugins, versions etc.
- check the source code for resources, scripts, etc.

## tools

### gobuster:

- brute force
- https://hackertarget.com/gobuster-tutorial/

### ffuf

### eyewitness

- https://github.com/RedSiege/EyeWitness

### whatweb

- run whatweb against a url to reveil tons of information
- use -v for verbose, well-formatted output
