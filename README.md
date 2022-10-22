# Daniele's Tools Firewall Monitor
DTFirewallMonitor<br>
Displays briefly what your firewall is blocking.<br>
Copyright (C) 2022 daniznf

### Description
This script can be run when you want to see in realtime what your firewall is blocking.
Each time an application gets blocked by firewall it will be displayed **briefly** by this script.
After displaying some recent events, every new event will be displayed (follow).<br>
By editing the included CSV (and passing it via the parameter -Exclusions), unwanted events can be excluded from the monitor.

### Requirements
DTTestAdministrator module installed.
https://github.com/daniznf/DTTestAdministrator

### Install
By setting the firewall to block all Inbound and Outbound connections that do not match a rule, only traffic explicitly permitted by rules will flow, while blocked traffic will be logged into the system's Security log,
and at the same time this monitor script will be able to retrieve it. <br/>
To have this log available, the "Failure" property in the group policy "Audit Filtering Platform Connection" must be checked.

### Run
Right click on this script and choose "Run with Powershell" or launch this script from powershell.

### Output example
```
4/6/2022 4:21:52 PM
Application: (10123) C:\users\daniznf\application\application.exe
Protocol:    UDP OUT
Source:      192.168.100.101 : 10123
Destination: 10.0.0.1        : 80

4/6/2022 4:32:18 PM
Application: (8012) C:\program files\program1\program1.exe
Protocol:    TCP OUT
Source:      192.168.100.101 : 20123
Destination: 10.0.0.2        : 443

4/6/2022 4:33:01 PM
Application: (9045) C:\program files\program2\program2.exe
Protocol:    TCP IN
Source:      10.0.0.3        : 30123
Destination: 192.168.100.101 : 80
```

### Output example in Compact mode
```
PS C:\> .\DTFirewallMonitor.ps1 -Compact
```
```
16:34:51  (9012) application1.exe UDP OUT
192.168.100.1: 40123  -> 10.0.0.4: 80

16:35:11  (8034) application2.exe TCP IN
10.0.0.4: 40123  -> 192.168.100.1 : 443
```

### Exclude events by CSV exclusions
```
PS C:\> .\DTFirewallMonitor.ps1 -Exclusions $env:USERPROFILE\Exclusions.csv
```

### Help
```
PS C:\> Get-Help .\DTFirewallMonitor.ps1
```

