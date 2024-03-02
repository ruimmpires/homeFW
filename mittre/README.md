# MITTRE ATTACK analysis

# **Iteration 1**
This first iteration is based on the status where there were some exposed services.

| Tactics	| Techniques | Sub-tech	| Attack details	| Results	| Mitigations	| Detection	| Issues |
|---|---|---|---|---|---|---|---|
|Reconnaissance TA0043	| Active Scanning	T1595	| 0.001	Scanning IP Blocks	| connected via a mobile phone to get an externl IP ping home.pires.xyz results the 2.80.44.128
sudo nmap -sV | IP is 2.80.44.128
sudo nmap -sV home.rpires.xyz
DNS record for 2.80.44.128: bl19-44-128.dsl.telepac.pt
PORT     STATE  SERVICE  VERSION
80/tcp   open   http     lighttpd 1.4.69
113/tcp  closed ident
443/tcp  closed https
1883/tcp open mqtt
8000/tcp open   ssl/http Splunkd httpd |	M1056        Pre-compromise
detect and block uncommon data flows| My temporary IP is 87.196.80.59, which can be found at a webservice such as https://whatismyipaddress.com/.
Or via cli with: dig +short myip.opendns.com @resolver1.opendns.com
87.196.80.59
There are 2 alerts generated, but the scan is not detected.|	No detection of uncommon data flows.
Reconnaissance TA0043	Active Scanning	T1595	0.002	Vulnerability Scanning	"splunk: https://book.hacktricks.xyz/network-services-pentesting/8089-splunkd Shodan does not find this server.
mqtt: : mosquitto_sub -t ""#"" -h home.rpires.xyz
91
13
38.50 |	"Above scan indentifies 3 open ports: 80, 1883 and 8000. Some analysis around the web raises some paths for an attack:
- 80/lighttpd 1.4.69, no vulnerabilities found https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=lighttpd
- 1883/mqtt, no vulnerabilities found. However a quick test confirms that mqtt is not secured. https://book.hacktricks.xyz/network-services-pentesting/1883-pentesting-mqtt-mosquitto
- 8000/splunk: possibly unhautenticated, confirmed with accessing via a browser to https://home.rpires.xyz:8000/en-US/app/launcher/home. Authentication GUI is restricted to paid licenses. https://book.hacktricks.xyz/network-services-pentesting/8089-splunkd"	"
M1042        Disable or Remove Feature or Program
M1056        Pre-compromise
activate authentication on splunk
activate authentiction and encryption in mqtt service"	"DS0029        Network Traffic
not detected"	"mqtt server is not secured.
splunk server may be compromised by a malicious actor by analyzing the logs and installing apps. One specific app may provide reverse shell"
Reconnaissance TA0043	Active Scanning	T1595	0.003	Wordlist Scanning	dirbuster and zap scanning	no major issues raised	"detect and block uncommon data flows such as scans or crawlers
M1042        Disable or Remove Feature or Program
M1056        Pre-compromise"	"DS0029        Network Traffic
not detected"	updated ssh password and pihole password which were simple old passwords, collected in past breaches, confirmed in https://haveibeenpwned.com/
Initial Access TA0001	Exploit Public-Facing Application	T1190	n/a	n/a			"The Spluk server can be protected by updating to the licensed version and thus:
M1026        Privileged Account Management
M1051        Update Software
As last resort, put it in a DMZ:
M1030        Network Segmentation
Other mitigation is to use a reverse proxy:
M1050        Exploit Protection"	"DS0015        Application Log, not detected
DS0029        Network Traffic, not detected"	root access to the splunk server machine

https://github.com/0xjpuff/reverse_shell_splunk
