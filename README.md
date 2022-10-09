# Daniele's Tools Firewall Monitor
DTFirewallMonitor
Displays briefly what your firewall is blocking
Copyright (C) 2022 daniznf

### Description
Each time an application gets blocked by firewall it will be displayed **briefly** by this script.
After displaying some recent events, every new event will be displayed (follow).

### Install
When firewall blocks inbound or outbound communication, it has to be configured to log it in the Security log. Actually, it is the "Filtering Platform Connection" that writes the log. To have this log available, in the group policy "Audit Filtering Platform Connection" the "Failure" property must be checked.

### Run
Right click on this script and chose "Run with Powershell" (double-clicking will not work) or launch this script from powershell.


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

### Compact mode
```
16:34:51  (9012) application1.exe UDP OUT
192.168.100.1: 40123  -> 10.0.0.4: 80

16:35:11  (8034) application2.exe TCP IN
10.0.0.4: 40123  -> 192.168.100.1 : 443
```

### Help
```
Get-Help .\DTFirewallMonitor.ps1
```

