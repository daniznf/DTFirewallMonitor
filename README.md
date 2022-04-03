# DTFirewallEvents
Displays briefly what your firewall is blocking

### Description
Each time an application gets blocked by firewall it will be displayed **briefly** by this script.
After displaying some recent events, every new event will be displayed (follow).

### Install
1. When firewall blocks inbound or outbound communication, it will log it in the Security log. Actually, it is the "Filtering Platform Connection" that writes the log. To have this log available, in the group policy "Audit Filtering Platform Connection" the "Failure" property must be checked.
2. Right click on this script and chose "Run with Powershell" (double-clicking will not work) or launch this script from powershell.


### Output example
```
4/3/2022 4:21:52 PM
Application: (10123) \device\harddiskvolume2\users\daniznf\application\application.exe
Protocol:    UDP OUT
Source:      192.168.100.101 : 49123
Destination: 10.0.0.1        : 80

4/3/2022 4:32:18 PM
Application: (8012) \device\harddiskvolume2\program files\program1\program1.exe
Protocol:    TCP OUT
Source:      192.168.100.101 : 58123
Destination: 10.0.0.2        : 443

4/3/2022 4:33:01 PM
Application: (9045) \device\harddiskvolume2\program files\program2\program2.exe
Protocol:    TCP IN
Source:      10.0.0.3        : 30123
Destination: 192.168.100.101 : 80
```
