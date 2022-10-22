<#
    Daniele's Tools Firewall Monitor
    Copyright (C) 2022 daniznf

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

    https://github.com/daniznf/DTFirewallMonitor
#>

<#PSScriptInfo

.VERSION 1.11.0

.GUID 23902d50-3002-4336-b75c-eca95651f051

.AUTHOR daniznf

.COMPANYNAME

.COPYRIGHT (c) 2022 daniznf. All rights reserved.

.TAGS Firewall Events Monitor

.LICENSEURI https://www.gnu.org/licenses/gpl-3.0.txt

.PROJECTURI https://github.com/daniznf/DTFirewallMonitor

.ICONURI

.EXTERNALMODULEDEPENDENCIES DTTestAdministrator

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

#>


#Requires -Modules DTTestAdministrator

param(
    [Parameter(ParameterSetName="Default")]
    [String]
    $Exclusions,

    [Parameter(ParameterSetName="Default")]
    [Int32]
    $RecentEvents = 20,

    [Parameter(ParameterSetName="Default")]
    [Int32]
    $FollowTime = 1,

    [Parameter(ParameterSetName="Default")]
    [switch]
    $Compact,

    [Parameter(Mandatory, ParameterSetName="Version")]
    [switch]
    $Version
)

function Get-Version()
{
    try
    {
        $Content = Get-Content -Path $MyInvocation.ScriptName
        for ($i = 0; $i -lt $Content.Length; $i++)
        {
            $Line = $Content[$i].Trim()
            if ($Line.Contains(".VERSION"))
            {
                $Split = $Line.Split(" ")
                return [version]::new($Split[1])
            }
        }
    }
    catch
    {
        Write-Host $_
        exit 1
    }
}

function ParseEvent {
    param(
        [System.ComponentModel.Component]
        $Event
    )

    Write-Verbose ("Event index: " + $Event.Index)

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

    for ($i = 0; $i -lt $MsgLines.Length ; $i++)
    {
        $Splitted = $MsgLines[$i].Split(":")

        $Left = $Splitted[0]
        $Right = $Splitted[1]

        if ($Left -ne $null -and $Right -ne $null)
        {
            $Left = $Left.Trim()
            $Right = $Right.Trim()

            Write-Verbose ("{0}: {1}" -f $Left, $Right)

            if ($Left.Equals("Application Name"))
            {
                $AppName = $Right
                # $AppName is something like:
                #   \device\harddiskvolume1\program files\program\program.exe
                # or something like:
                #   System
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

    for ($j = 0; $j -lt $ListExclusions.Length; $j++)
    {
        $ExcRow = $ListExclusions[$j]
        # For each line of the CSV, that has at least one not empty value, all
        # not empty values must be equal to this event's corresponding value
        # to exclude this event
        if (($ExcRow.SourceIP -ne "") -or ($ExcRow.SourcePort -ne "") -or
            ($ExcRow.DestinationIP -ne "") -or ($ExcRow.DestinationPort -ne "") -or
            ($ExcRow.Protocol -ne "") -or ($ExcRow.Direction -ne "") -or
            ($ExcRow.Application -ne ""))
        {
            if ((($ExcRow.SourceIP -eq "") -or ($ExcRow.SourceIP -eq $SrcAddress)) -and
                (($ExcRow.SourcePort -eq "") -or ($ExcRow.SourcePort -eq $SrcPort)) -and
                (($ExcRow.DestinationIP -eq "") -or ($ExcRow.DestinationIP -eq $DstAddress)) -and
                (($ExcRow.DestinationPort -eq "") -or ($ExcRow.DestinationPort -eq $DstPort)) -and
                (($ExcRow.Protocol -eq "") -or ($ExcRow.Protocol -eq $Protocol)) -and
                (($ExcRow.Direction -eq "") -or ($ExcRow.Direction -eq $Direction)) -and
                (($ExcRow.Application -eq "") -or ($AppName.Contains($ExcRow.Application))))
            {
                Write-Verbose ( "Excluding {0}:{1} {2}:{3} {4} {5} {6} - {7}" -f $ExcRow.SourceIP, $ExcRow.SourcePort,
                    $ExcRow.DestinationIP, $ExcRow.DestinationPort,
                    $ExcRow.Protocol, $ExcRow.Direction, $ExcRow.Application, $ExcRow.Note)

                    Write-Verbose ""

                # Do not print anything, just return
                return $Event.Index
            }
        }
    }

    if ($Compact)
    {
        Write-Host $EvTime.TimeOfDay.ToString() " " -NoNewline
        Write-Host "($ProcID)" (Split-Path $AppName -Leaf) "" -NoNewline
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

    return $Event.Index
}

if ($Version)
{
    $Ver = Get-Version
    if ($Ver)
    {
        Write-Host ("{0} - Version {1}" -f $MyInvocation.MyCommand.Name, $Ver.ToString())
        exit 0
    }
    exit 1
}

if ($RecentEvents -lt 1) { $RecentEvents = 1 }
if ($FollowTime -lt 1) { $FollowTime = 1 }

if (-not (Test-Administrator))
{
    Write-Output "Restarting as administrator..."
    Restart-AsAdministrator -BypassExecutionPolicy -BoundParameters $PSBoundParameters

    exit
}

$ListExclusions = @()
if ($Exclusions)
{
    Write-Verbose "Reading csv $Exclusions ..."
    $ListExclusions = Import-Csv $Exclusions
}

# Print some recent events
$NewestEvents = Get-EventLog -LogName Security -Newest $RecentEvents | Sort-Object -Property Index

for ($i = 0; $i -lt $NewestEvents.Length; $i++)
{
    $OldIndex = ParseEvent $NewestEvents[$i]
}

# Continue to follow new events
while ($true)
{
    $NewIndex = (Get-EventLog -LogName Security -Newest 1).Index
    Write-Verbose ("Old Index: {0}; New Index: {1}" -f $OldIndex, $NewIndex)
    if ($NewIndex -gt $OldIndex)
    {
        # Asking by index is really slow: Get-EventLog -LogName Security -Index $i
        $ListEvt = Get-EventLog -LogName Security -Newest ($NewIndex - $OldIndex) | Sort-Object -Property Index

        for ($i = 0; $i -lt $ListEvt.Length; $i++)
        {
            $OldIndex = ParseEvent $ListEvt[$i]
        }

    }
    Start-Sleep $FollowTime
}


<#
.SYNOPSIS
    Displays briefly what your firewall is blocking

.DESCRIPTION
    Each time an application gets blocked by firewall it will be displayed briefly by this script.
    After displaying some recent events, every new event will be displayed (follow).

.PARAMETER Exclusions
    CSV File path with items to exclude

.PARAMETER RecentEvents
    Initially shows this number of events

.PARAMETER FollowTime
    Time to wait between each follow cycle

.PARAMETER Compact
    Show informations using less space

.PARAMETER Version
    Print script version and exit

.NOTES
    When firewall blocks inbound or outbound communication, it will log it in the Security log.
    To have this log available, the "Failure" property must be checked in the group policy "Audit Filtering Platform Connection".

.EXAMPLE
    DTFirewallMonitor.ps1 -RecentEvents 50 -FollowTime 5
    Show firewall events starting with last 50 events and then waiting 5 seconds between each follow cycle.
#>
