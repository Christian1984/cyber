---
module: attacking web applications with ffuf
url: https://academy.hackthebox.com/module/54
---

# fuzzing

the term fuzzing refers to a testing technique that sends various types of user input to a certain interface to study how it would react. if we were fuzzing for sql injection vulnerabilities, we would be sending random special characters and seeing how the server would react. if we were fuzzing for a buffer overflow, we would be sending long strings and incrementing their length to see if and when the binary would break.

- Fuzzing for directories
- Fuzzing for files and extensions
- Identifying hidden vhosts
- Fuzzing for PHP parameters
- Fuzzing for parameter values


## wordlists

to determine which pages exist, we should have a wordlist containing commonly used words for web directories and pages, very similar to a password dictionary attack, which we will discuss later in the module. though this will not reveal all pages under a specific website, as some pages are randomly named or use unique names, in general, this returns the majority of pages, reaching up to 90% success rate on some websites.

we will not have to reinvent the wheel by manually creating these wordlists, as great efforts have been made to search the web and determine the most commonly used words for each type of fuzzing. some of the most commonly used wordlists can be found under the github seclists repository, which categorizes wordlists under various types of fuzzing, even including commonly used passwords, which we'll later utilize for password brute forcing.

i typically clone SecLists into `/opt/wordlists/SecLists`

"default" wordlists come with kali and can be found inside `usr/share/wordlists`

# fuff

we use `fuff` like so, for example:

```
$ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://83.136.251.235:53921/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.251.235:53921/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 282, Words: 20, Lines: 10, Duration: 58ms]
.htaccess               [Status: 403, Size: 282, Words: 20, Lines: 10, Duration: 79ms]
                        [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 1109ms]
blog                    [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 24ms]
forum                   [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 21ms]
.hta                    [Status: 403, Size: 282, Words: 20, Lines: 10, Duration: 4103ms]
index.php               [Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 21ms]
server-status           [Status: 403, Size: 282, Words: 20, Lines: 10, Duration: 20ms]
:: Progress: [4614/4614] :: Job [1/1] :: 746 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

we can now dig deeper by running fuff on the directories we found. however, we first need to find out what file extensions are used on the server, so we can run a scan that would look like this:

```
$ ffuf -w /usr/share/wordlists/dirb/extensions_common.txt:EXT -u http://83.136.251.235:53921/blog/indexEXT 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.251.235:53921/blog/indexEXT
 :: Wordlist         : EXT: /usr/share/wordlists/dirb/extensions_common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.php                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 67ms]
:: Progress: [29/29] :: Job [1/1] :: 260 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

we could event extend our search by running our fuzz like so, and exclude any 403 responses (which appear on this server with any `/.something.someextension` result)

```
$ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -w /usr/share/wordlists/dirb/extensions_common.txt:EXT -u http://83.136.251.235:53921/blog/FUZZEXT -fc 403

... SNIP ...
```

this doesn't yield any interesting results... now that we know the server uses php, we can use this information to fuzz for php pages:

```
$ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://83.136.251.235:53921/blog/FUZZ.php -v -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.251.235:53921/blog/FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

[Status: 200, Size: 1046, Words: 438, Lines: 58, Duration: 18ms]
| URL | http://83.136.251.235:53921/blog/home.php
    * FUZZ: home

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 21ms]
| URL | http://83.136.251.235:53921/blog/index.php
    * FUZZ: index

:: Progress: [4614/4614] :: Job [1/1] :: 1315 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

doing this, we find `/blog/home.php` which contains the flag for the task ahead.

# recursive fuzzing

to enumerate nested files and directories automatically, we can use recursive fuzzing. important things to note:

- use both the `-recursion` and `-recusrion-depth` flags
- use the `-e` flag (e.g. `-e .php`) to also find files inside the recursively discovered directories
- use `-v` to print the full urls
- the the url in the `-u` flag needs to end in the `FUZZ` keyword

example:

```
$ ffuf -w /usr/share/wordlists/dirb/small.txt:FUZZ -u http://83.136.251.235:53921/FUZZ -v -recursion -recursion-depth 1 -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.251.235:53921/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/small.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 15ms]
| URL | http://83.136.251.235:53921/blog
| --> | http://83.136.251.235:53921/blog/
    * FUZZ: blog

[INFO] Adding a new job to the queue: http://83.136.251.235:53921/blog/FUZZ

[Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 22ms]
| URL | http://83.136.251.235:53921/forum
| --> | http://83.136.251.235:53921/forum/
    * FUZZ: forum

[INFO] Adding a new job to the queue: http://83.136.251.235:53921/forum/FUZZ

[Status: 200, Size: 986, Words: 423, Lines: 56, Duration: 21ms]
| URL | http://83.136.251.235:53921/index.php
    * FUZZ: index.php

[INFO] Starting queued job on target: http://83.136.251.235:53921/blog/FUZZ

[Status: 200, Size: 1046, Words: 438, Lines: 58, Duration: 23ms]
| URL | http://83.136.251.235:53921/blog/home.php
    * FUZZ: home.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 21ms]
| URL | http://83.136.251.235:53921/blog/index.php
    * FUZZ: index.php

[INFO] Starting queued job on target: http://83.136.251.235:53921/forum/FUZZ

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 23ms]
| URL | http://83.136.251.235:53921/forum/index.php
    * FUZZ: index.php

:: Progress: [1918/1918] :: Job [3/3] :: 21 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

with this, i couldn't find the flag, but using the wordlist `usr/share/wordlists/dirb/directory-list-2.3-small.txt` worked!