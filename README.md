# homeFW
Home FW is a project that may be subject to several iteractions

## 1st iteration - RJ45 wire tap connected to a computer
This iteration of the project  holds several parts:
* RJ 45 Wire tap
* Suricata

### RJ 45 Wire tap

### Suricata

### Results
...
#### Good
...
#### Bad
...

## 2nd iteration - DNS filtering with Pi-Hole
This iteration of the project holds several parts:
* install PiHole in a RaspberyPi
* Configure DNS in the home APs

### PiHole
...
### configuring DNS
...
### Results
...
#### Good
...
#### Bad
...

## 3rd iteration - Detect Wifi attacks with Kismet
This iteration of the project is just about installing Kismet
### Kismet
...
### Results
...
#### Good
...
#### Bad
...

## 4th iteration - collect logs into Splunk
This iteration of the project holds several parts:
* install Splunk
* collect logs from local server
* collect logs from home ssh server
* push alarms to Slack
* push alarms to MQTT
* collect logs from home web server
### Splunk
...
### Splunk to Slack
...
In Splunk, configure the alert, add actions and select the "Slack" add-on, select the channel and configure the message:
![pic](suricata_alarm_config_1.png)
I got the scheduled alarms in my Slack for mobile: 
![pic](splunk_to_slack_alarm_mobile_1.png).

However, the message is not populated as I expected. The link also fails because the link refers the machine local name.

...
### Splunk to MQTT
...
### collect logs from local server
...
### collect logs from home ssh server
...
#### Syslog receiver in Splunk
...
#### Syslog sending in RPi
...
#### Dashboard in Splunk
Created the new searches and saved to the RPI4 dashboard:
* city of the IP of the invalid usernames: source="tcp:514" "Invalid user"  | rex field=_raw "(?<src_ip>[[ipv4]])" | iplocation src_ip | stats count by City  | sort -count
* invalid usernames: source="tcp:514" "Invalid user"  | rex field=_raw "(?<src_ip>ipv4)"  | rex "(Invalid user )(?<InvUser>\w+)" | stats count by InvUser | sort -count
* failed authentiction: source="tcp:514" "authentication failure" "user=" | rex "(user=)(?<UnauthUser>\w+)" | stats count by UnauthUser | sort -count
And I was able to create a dashboard with ssh attacks to the RPi:
![pict](splunk_dashboard_ssh_attacks_rpi4.jpg)

### collect logs from home web server
...

##  5th iteration - reduce ssh attacks with fail2ban
fail2ban is a simple tool that reads the 

More info here: https://blog.swmansion.com/limiting-failed-ssh-login-attempts-with-fail2ban-7da15a2313b
### fail2ban
Install and use the default config: ```sudo apt install fail2ban```
Checking installation:
```
sudo fail2ban-client status sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed: 12
|  |- Total failed:     2443
|  `- File list:        /var/log/auth.log
`- Actions
   |- Currently banned: 7
   |- Total banned:     386
   `- Banned IP list:   194.93.25.163 103.179.57.150 161.230.84.140 190.35.38.231 186.230.74.198 85.215.34.119 64.226.120.7
```
```
sudo iptables -L -n -v
Chain f2b-sshd (1 references)
 pkts bytes target     prot opt in     out     source               destination
   20  1616 REJECT     all  --  *      *       64.226.120.7         0.0.0.0/0            reject-with icmp-port-unreachable
   21  1668 REJECT     all  --  *      *       85.215.34.119        0.0.0.0/0            reject-with icmp-port-unreachable
   17  1272 REJECT     all  --  *      *       186.230.74.198       0.0.0.0/0            reject-with icmp-port-unreachable
   16  1236 REJECT     all  --  *      *       190.35.38.231        0.0.0.0/0            reject-with icmp-port-unreachable
   26  1960 REJECT     all  --  *      *       161.230.84.140       0.0.0.0/0            reject-with icmp-port-unreachable
   27  1980 REJECT     all  --  *      *       103.179.57.150       0.0.0.0/0            reject-with icmp-port-unreachable
   26  2012 REJECT     all  --  *      *       194.93.25.163        0.0.0.0/0            reject-with icmp-port-unreachable
   19  1392 REJECT     all  --  *      *       209.45.73.18         0.0.0.0/0            reject-with icmp-port-unreachable
   23  1740 REJECT     all  --  *      *       43.159.45.214        0.0.0.0/0            reject-with icmp-port-unreachable
10615 1609K RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
```
