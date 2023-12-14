# basics

- https://academy.hackthebox.com/module/77/

## the CIA triad

in a nutshell, infosec is the practice of protecting data from unauthorized access, changes, unlawful use, disruption, etc. infosec professionals also take actions to reduce the overall impact of any such incident.

data can be electronic or physical and tangible (e.g., design blueprints) or intangible (knowledge). a common phrase that will come up many times in our infosec career is protecting the

- confidentiality,
- integrity, and
- availability

of data," or the cia triad.

## risk management

we must understand the bigger picture of the risks an organization faces and its environment to evaluate and rate vulnerabilities discovered during testing accurately. a deep understanding of the risk management process is critical for anyone starting in information security.

data protection must focus on efficient yet effective policy implementation without negatively affecting an organization's business operations and productivity. to achieve this, organizations must follow a process called the risk management process. this process involves the following five steps:

- identifying the risk: identifying risks the business is exposed to, such as legal, environmental, market, regulatory, and other types of risks.
- analyze the risk: analyzing the risks to determine their impact and probability. the risks should be mapped to the organization's various policies, procedures, and business processes.
- evaluate the risk: evaluating, ranking, and prioritizing risks. then, the organization must decide to accept (unavoidable), avoid (change plans), control (mitigate), or transfer risk (insure).
- dealing with risk: eliminating or containing the risks as best as possible. this is handled by interfacing directly with the stakeholders for the system or process that the risk is associated with.
- monitoring risk: all risks must be constantly monitored. risks should be constantly monitored for any situational changes that could change their impact score, i.e., from low to medium or high impact.
- as mentioned previously, the core tenet of infosec is information assurance, or maintaining the cia of data and making sure that it is not compromised in any way, shape, or form when an incident occurs. an incident could be a natural disaster, system malfunction, or security incident.

## project organization

### folder structure

When attacking a single box, lab, or client environment, we should have a clear folder structure on our attack machine to save data such as: scoping information, enumeration data, evidence of exploitation attempts, sensitive data such as credentials, and other data obtained during recon, exploitation, and post-exploitation. A sample folder structure may look like follows:

```
Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

## VPNs

We can use a VPN service such as NordVPN or Private Internet Access and connect to a VPN server in another part of our country or another region of the world to obscure our browsing traffic or disguise our public IP address. This can provide us with some level of security and privacy. Still, since we are connecting to a company's server, there is always the chance that data is being logged or the VPN service is not following security best practices or the security features that they advertise. Using a VPN service comes with the risk that the provider is not doing what they are saying and are logging all data. Usage of a VPN service does not guarantee anonymity or privacy but is useful for bypassing certain network/firewall restrictions or when connected to a possible hostile network (i.e., a public airport wireless network). A VPN service should never be used with the thought that it will protect us from the consequences of performing nefarious activities.

When connected to HTB VPN (or any penetration testing/hacking-focused lab), we should always consider the network to be "hostile." We should only connect from a virtual machine, disallow password authentication if SSH is enabled on our attacking VM, lockdown any web servers, and not leave sensitive information on our attack VM (i.e., do not play HTB or other vulnerable networks with the same VM that we use to perform client assessments).

### connecting

run `sudo openvpn user.ovpn`

> `sudo` is required for certain tunneling functionality.

run `ifconfig` to see the adapter (e.g. `tun0`) used by the vpn connection.

`netstat -rn` shows the networks accessible via the vpn.

## ports

well known ports:

```
- 20/21 (TCP): FTP
- 22 (TCP): SSH
- 23 (TCP): Telnet
- 25 (TCP): SMTP
- 80 (TCP): HTTP
- 161 (TCP/UDP): SNMP
- 389 (TCP/UDP): LDAP
- 443 (TCP): SSL/TLS (HTTPS)
- 445 (TCP): SMB
- 3389 (TCP): RDP
```

### cheat sheets

- https://www.stationx.net/common-ports-cheat-sheet/
- https://packetlife.net/media/library/23/common-ports.pdf

## vulnerabilities

the OWASP project maintains a list of the top 10 web application vulnerabilities: https://owasp.org/www-project-top-ten/

This list is considered the top 10 most dangerous vulnerabilities and is not an exhaustive list of all possible web application vulnerabilities. Web application security assessment methodologies are often based around the OWASP top 10 as a starting point for the top categories of flaws that an assessor should be checking for.

## essentials tools

- ssh: secure shell, e.g. `ssh Bob@10.10.10.10`
- netcat: allows to connect to any listening port (lternative on windows is called `PowerCat`), e.g. `netcat <ip> <port>`, or `nc`
- tmux: terminal multiplexer, tutorial: https://www.youtube.com/watch?v=Lqehvpe_djs, cheat sheet: https://tmuxcheatsheet.com/
- vim: editor, cheat sheet: https://vimsheet.com/
