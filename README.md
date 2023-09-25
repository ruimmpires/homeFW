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
* install PiHole in a RaspberryPi
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
I got the scheduled alarms in my Slack for mobile:  !([pic]suricata_alarm_mobile_1.png).

However, the message is not populated as I expected. The link also fails because the link refers the machine local name.

...
### Splunk to MQTT
...
### collect logs from local server
...
### collect logs from home ssh server
...
### collect logs from home web server
...
### Results
Still ongoing, but already have some results.
#### Good
...
#### Bad
...
