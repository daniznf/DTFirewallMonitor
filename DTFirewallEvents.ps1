<#
    Dani's Tools Firewall Events
    Copyright (C) 2022 Daniznf

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
    
    https://github.com/daniznf/DTFirewallEvents
#>

param(
    [String]
    # CSV File path with items to exclude
    $Exclusions,

    [Int32] 
    # Initially shows this number of events
    $RecentEvents = 20,
    
    [Int32]
    # Time to wait between each follow cycle
    $FollowTime = 1,

    [switch]
    # Show informations using less space
    $Compact,

    [switch]
    # Show some additional informations
    $Debug
)

if ($RecentEvents -lt 1) { $RecentEvents = 1 }

function Test-Administrator  
{  
    # Returns true if this script is run as administrator
    # thanks to https://serverfault.com/a/97599
    
    $User = [Security.Principal.WindowsIdentity]::GetCurrent();
    if ($Debug) { Write-Host $User.Name }
    (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not $(Test-Administrator))
{
    Write-Output "Restarting as administrator..."
     
    $Arguments = "-ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Path + "`""
    
    $PSBoundParameters.Keys | ForEach-Object {
        $Arguments += " -" + $_
        if ($PSBoundParameters[$_].GetType() -ne [System.Management.Automation.SwitchParameter])
        {
            $Arguments += " " + $PSBoundParameters[$_]
        }
    }

    Start-Process Powershell -Verb RunAs -ArgumentList $Arguments
    exit
}

function ParseEvent {
    param([System.ComponentModel.Component] $Event)

    if ($Debug) { Write-Host $Event.Index }

    # 5154 Listen permitted
    # 5155 Listen blocked
    # 5156 Connection permitted
    # 5157 Connection blocked
    # 5158 Bind permitted
    # 5159 Bind blocked
    if ($Event.InstanceId -NotIn "5154","5155","5156","5157","5158","5159") { Return $Event.Index }
    
    $EvMsg = $Event.Message
    $EvTime = $Event.TimeGenerated

    $MsgLines = $EvMsg.Split([System.Environment]::NewLine)
    $MsgLines | ForEach-Object {
        $Splitted = $_.Split(":")

        $Left = $Splitted[0]
        $Right = $Splitted[1]
        
        if ($Left -ne $null -and $Right -ne $null)
        {
            $Left = $Left.Trim()
            $Right = $Right.Trim()

            if ($Debug) { Write-Host "|" $Left ":" $Right }

            if ($Left.Equals("Application Name"))
            {
                $AppName = $Right
                # $AppName is something like 
                # \device\harddiskvolume1\program files\program\program.exe
                # or something like
                # System
                if ($AppName.Contains("\"))
                {
                    $Letter = (Get-Volume -FilePath $AppName).DriveLetter
                    $AppName = $AppName.Remove(0, $AppName.IndexOf("\",1))
                    $AppName = $AppName.Remove(0, $AppName.IndexOf("\",1))
                    $AppName = $Letter + ":" + $AppName 
                }
            }

            if ($Left.Equals("Process ID"))
            {
                $ProcID = $Right
            }

            if ($Left.Equals("Direction"))
            {
                if ($Right.Equals("%%14592"))
                {
                    $Direction = "IN"
                    $BgColor = "Red"
                    $FgColor = "White"
                }
                elseif ($Right.Equals("%%14593"))
                {
                    $Direction = "OUT"
                    $BgColor = "DarkGreen"
                    $FgColor = "White"
                }
                else
                {
                    $Direction = "UNKNOWN!"
                    $BgColor = "DarkGray"
                    $FgColor = "White"
                }
            }

            if ($Left.Equals("Source Address"))
            {
                $SrcAddress = $Right
            }

            if ($Left.Equals("Source Port"))
            {
                $SrcPort = $Right
            }

            if ($Left.Equals("Destination Address"))
            {
                $DstAddress = $Right
            }

            if ($Left.Equals("Destination Port"))
            {
                $DstPort = $Right
            }

            if ($Left.Equals("Protocol"))
            {
                switch ($Right)
                {
                    # IPv6 Hop-by-Hop Option
                    0 { $Protocol = "HOPOPT" }
                }

                switch ($Right)
                {
                    # Internet Control Message
                    1 { $Protocol = "ICMP" }
                }
                    
                switch ($Right)
                {
                    # Internet Group Management
                    2 { $Protocol = "IGMP" }
                }
                    
                switch ($Right)
                {
                    # IPv4 Encapsulation 
                    4 { $Protocol = "IPv4" }
                }

                switch ($Right)
                {
                    # Transmission Control
                    6 { $Protocol = "TCP" }
                }
                    
                switch ($Right)
                {
                    # User Datagram
                    17 { $Protocol = "UDP" }
                }
                    
                switch ($Right)
                {
                    # IPv6 Encapsulation
                    41 { $Protocol = "IPv6" }
                }
                    
                switch ($Right)
                {
                    # Routing Header for IPv6
                    43 { $Protocol = "IPv6 Route" }
                }

                switch ($Right)
                {
                    # Fragment Header for IPv6
                    44 { $Protocol = "IPv6 Frag" }
                }

                switch ($Right)
                {
                    # Generic Routing Encapsulation
                    47 { $Protocol = "GRE" }
                }

                switch ($Right)
                {
                    # ICMP for IPv6
                    58 { $Protocol = "IPv6 ICMP" }
                }

                switch ($Right)
                {
                    # No Next Header for IPv6
                    59 { $Protocol = "IPv6 NoNxt" }
                }

                switch ($Right)
                {
                    # Destination Options for IPv6
                    60 { $Protocol = "IPv6 Opts" }
                }

                switch ($Right)
                {
                    # Virtual Router Redundancy Protocol
                    112 { $Protocol = "VRRP" }
                }

                switch ($Right)
                {
                    # PGM Reliable Transport Protocol
                    113 { $Protocol = "PGM" }
                }

                switch ($Right)
                {
                    # Layer Two Tunneling Protocol
                    115 { $Protocol = "L2TP" }
                }
            }
        }
    }
    
    # ForEach-Object doesn't Return out of function
    foreach ($ExcRow in $ListExclusions) {
    # For each line of the CSV, that has at least one not empty value, all
    # not empty values must be equal to this event's corresponding value
    # to exclude this event
        if (($ExcRow.SourceIP -ne "") -or ($ExcRow.SourcePort -ne "") -or 
            ($ExcRow.DestinationIP -ne "") -or ($ExcRow.DestinationPort -ne "") -or 
            ($ExcRow.Protocol -ne "") -or ($ExcRow.Direction -ne "") -or 
            ($ExcRow.ProgramPath -ne ""))
        {
            if ((($ExcRow.SourceIP -eq "") -or ($ExcRow.SourceIP -eq $SrcAddress)) -and
                (($ExcRow.SourcePort -eq "") -or ($ExcRow.SourcePort -eq $SrcPort)) -and
                (($ExcRow.DestinationIP -eq "") -or ($ExcRow.DestinationIP -eq $DstAddress)) -and
                (($ExcRow.DestinationPort -eq "") -or ($ExcRow.DestinationPort -eq $DstPort)) -and
                (($ExcRow.Protocol -eq "") -or ($ExcRow.Protocol -eq $Protocol)) -and
                (($ExcRow.Direction -eq "") -or ($ExcRow.Direction -eq $Direction)) -and
                (($ExcRow.ProgramPath -eq "") -or ($ExcRow.ProgramPath -eq $AppName)) )
            {
                if ($Debug)
                {
                    Write-Host "Excluding" $ExcRow.SourceIP $ExcRow.SourcePort `
                        $ExcRow.DestinationIP $ExcRow.DestinationPort `
                        $ExcRow.Protocol $ExcRow.Direction $ExcRow.ProgramPath - $ExcRow.Note
                }
                Return $Event.Index
            }
        }
    }

    if ($Compact)
    {
        Write-Host $EvTime.TimeOfDay.ToString() " " -NoNewline
        Write-Host "($ProcID)" ( Split-Path $AppName -Leaf ) "" -NoNewline
        Write-Host $Protocol "" -NoNewline
        Write-Host $Direction -BackgroundColor $BgColor -ForegroundColor $FgColor
        Write-Host $SrcAddress":" $SrcPort " -> " -NoNewline
        Write-Host $DstAddress":" $DstPort
        Write-Host
    }
    else
    {
        $PadLenght = 12
        Write-Host $EvTime
        Write-Host "Application:".PadRight($PadLenght) "($ProcID)" $AppName
        Write-Host "Protocol:".PadRight($PadLenght) $Protocol "" -NoNewline 
        Write-Host $Direction -BackgroundColor $BgColor -ForegroundColor $FgColor
        Write-Host "Source:".PadRight($PadLenght) $SrcAddress.PadRight(15) ":" $SrcPort
        Write-Host "Destination:".PadRight($PadLenght) $DstAddress.PadRight(15) ":" $DstPort
        Write-Host
    }
    $Event.Index
}

$ListExclusions = @()
if ($Exclusions)
{
    $ListExclusions = Import-Csv $Exclusions
}

# Print some recent events
Get-EventLog -LogName Security -Newest $RecentEvents | Sort-Object -Property Index | ForEach-Object {
    $OldIndex = ParseEvent $_
}

# Continue to follow new events
while ($true)
{
    $NewIndex = (Get-EventLog -LogName Security -Newest 1).Index
    if ($Debug) { Write-Host "Old Index: " $OldIndex  "; New Index: " $NewIndex }
    if ($NewIndex -gt $OldIndex)
    {
        # Asking by index is really slow: Get-EventLog -LogName Security -Index $i
        $ListEvt = Get-EventLog -LogName Security -Newest ($NewIndex - $OldIndex) | Sort-Object -Property Index
        $ListEvt | ForEach-Object {
            $OldIndex = ParseEvent $_
        }

    }
    Start-Sleep $FollowTime
}


<#
.SYNOPSIS
Displays briefly what your firewall is blocking

.DESCRIPTION
Dani's Tools Firewall Events
Version 1.5.0 - June 2022
Each time an application gets blocked by firewall it will be displayed briefly by this script. 
After displaying some recent events, every new event will be displayed (follow).
When firewall blocks inbound or outbound communication, it will log it in the Security log. 
Actually, it is the "Filtering Platform Connection" that writes the log. 
To have this log available, in the group policy "Audit Filtering Platform Connection" 
the "Failure" property must be checked.
#>
