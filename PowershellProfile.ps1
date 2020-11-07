$uname=("$env:USERDOMAIN\$env:USERNAME")
$cred = Get-Credential $uname

$vCenters = @(
"contoso.vc01.example"
"contoso.vc02.example"
)
        
$vcenterconnections = Start-Job -ScriptBlock {
foreach ($vCenter in $vCenters){
      [void](Connect-VIServer $vcenter -Credential $cred -ErrorAction SilentlyContinue)
      }
    }

function global:prompt {
    $Success = $?

    ## Time calculation
    $LastExecutionTimeSpan = if (@(Get-History).Count -gt 0) {
        Get-History | Select-Object -Last 1 | ForEach-Object {
            New-TimeSpan -Start $_.StartExecutionTime -End $_.EndExecutionTime
        }
    }
    else {
        New-TimeSpan
    }

    $LastExecutionShortTime = if ($LastExecutionTimeSpan.Days -gt 0) {
        "$($LastExecutionTimeSpan.Days + [Math]::Round($LastExecutionTimeSpan.Hours / 24, 2)) d"
    }
    elseif ($LastExecutionTimeSpan.Hours -gt 0) {
        "$($LastExecutionTimeSpan.Hours + [Math]::Round($LastExecutionTimeSpan.Minutes / 60, 2)) h"
    }
    elseif ($LastExecutionTimeSpan.Minutes -gt 0) {
        "$($LastExecutionTimeSpan.Minutes + [Math]::Round($LastExecutionTimeSpan.Seconds / 60, 2)) m"
    }
    elseif ($LastExecutionTimeSpan.Seconds -gt 0) {
        "$($LastExecutionTimeSpan.Seconds + [Math]::Round($LastExecutionTimeSpan.Milliseconds / 1000, 2)) s"
    }
    elseif ($LastExecutionTimeSpan.Milliseconds -gt 0) {
        "$([Math]::Round($LastExecutionTimeSpan.TotalMilliseconds, 2)) ms"
    }
    else {
        "0 s"
    }

    if ($Success) {
        Write-Host -Object "[$LastExecutionShortTime] " -NoNewline -ForegroundColor Green
    }
    else {
        Write-Host -Object "! [$LastExecutionShortTime] " -NoNewline -ForegroundColor Red
    }

    ## History ID
    $HistoryId = $MyInvocation.HistoryId
    # Uncomment below for leading zeros
    # $HistoryId = '{0:d4}' -f $MyInvocation.HistoryId
    Write-Host -Object "$HistoryId`: " -NoNewline -ForegroundColor Cyan

    ## User
    $IsAdmin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Write-Host -Object "$($env:USERNAME) ($(if ($IsAdmin){ 'A' } else { 'U' })) " -NoNewline -ForegroundColor DarkRed

    ## Path
    $Drive = $pwd.Drive.Name
    $Pwds = $pwd -split "\\" | Where-Object { -Not [String]::IsNullOrEmpty($_) }
    $PwdPath = if ($Pwds.Count -gt 3) {
        $ParentFolder = Split-Path -Path (Split-Path -Path $pwd -Parent) -Leaf
        $CurrentFolder = Split-Path -Path $pwd -Leaf
        "..\$ParentFolder\$CurrentFolder"
    }
    elseif ($Pwds.Count -eq 3) {
        $ParentFolder = Split-Path -Path (Split-Path -Path $pwd -Parent) -Leaf
        $CurrentFolder = Split-Path -Path $pwd -Leaf
        "$ParentFolder\$CurrentFolder"
    }
    elseif ($Pwds.Count -eq 2) {
        Split-Path -Path $pwd -Leaf
    }
    else { "" }

    Write-Host -Object "$Drive`:\$PwdPath" -NoNewline -ForegroundColor Magenta

    return "> "
}

Function Get-workerprocess {

#Function to fetch IIS worker process information

   Param(
   [CmdletBinding()]
   [parameter(Mandatory=$true,Position=0)][string]$ComputerName,
   [parameter(Mandatory=$false,Position=1)][string]$WorkerId,
   [switch]$all
   )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    if ($all) {
        $res = Invoke-Command -computername $ComputerName -Credential $cred {Import-Module WebAdministration ; gci IIS:\AppPools | select -expandproperty name | % {gci IIS:\AppPools\$_\WorkerProcesses | select  appPoolName, state, processid, starttime}}
        Write-Host $res
        $res | clip
    } else{
        if ($WorkerId -eq $null) {
	        echo "App Pool name: " -BackgroundColor Black -ForegroundColor Yellow -NoNewline
	        $WorkerId = Read-Host
        } else {
	        $res = Invoke-Command -computername $ComputerName -Credential $cred -ArgumentList $WorkerId -ScriptBlock {Import-Module WebAdministration ; gci IIS:\AppPools | select -expandproperty name | % {gci IIS:\AppPools\$_\WorkerProcesses | select  appPoolName, state, processid, starttime} | Where-Object appPoolName -IMatch $args[0]}
            echo $res
            $res | clip
        }
    }
}

Function Get-lastlogon {

#Fetching last logins on a remote computer

    Param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    Write-Host "Number of logons: " -BackgroundColor Black -ForegroundColor Yellow -NoNewline
	$lastnum = Read-Host

    if ($lastnum -eq $null) {
        $lastnum = "5"
    }

	Invoke-Command -computername $ComputerName -ArgumentList $lastnum -ScriptBlock {Get-EventLog -logname system -source user32 -newest $args[0] | format-table -wrap}
}

Function Get-uptime {

#Getting uptime of remote computer

    Param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

	Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock {(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime} | Select-Object Days,Hours,Minutes,Seconds
}

Function Get-UniqueDiskID {

# Gets disk with unique ID and shows it's state.
# -online parameter brings the offline disk back online
# -onlineAll brings all available disks online
# Example: Get-UniqueDiskID dc01.contoso.test <Disk ID> -online

    Param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [parameter(Mandatory=$true,Position=1)][string]$uniqueId,
    [switch]$online,
    [switch]$onlineAll
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    if ($online){ 
        Invoke-Command -computername $ComputerName -Credential $cred -ArgumentList $uniqueId -ScriptBlock {Get-Disk -UniqueId $args[0] | Set-Disk -IsOffline $false}
    }

    if ($onlineAll){
        Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-Disk | Where-Object -Property OperationalStatus -EQ "Offline" | Set-Disk -IsOffline $false}
    }
	Invoke-Command -computername $ComputerName -Credential $cred -ArgumentList $uniqueId -ScriptBlock {Get-Disk -UniqueId $args[0] | Format-Table -AutoSize -Wrap}
}

function major-incident {

    #Major Incident script
        $inc = Read-Host "Incident nr"
        $ch1 = Read-Host "Create etherpad for new major?[y/n]"
        $urls1 = @("https://url1","https://url2")
        $urls2 = @("https://url1","https://url2")
        $firefox=Get-Process *firefox* | select-object ProcessName -First 1 | Select-String -Pattern "firefox"
        $chrome=Get-Process *chrome* | select-object ProcessName -First 1 | Select-String -Pattern "chrome"
    
    if ($ch1 -eq 'y') 
        {
        if ($firefox -like '*firefox*') {Start-Process firefox $urls1}
        elseif ($chrome -like '*chromell*') {Start-Process chrome.exe $urls1}
        else {Start-Process $urls1}
        }
      
    else 
        {
        if ($firefox -like '*firefox*') {Start-Process firefox $urls2}
        elseif ($chrome -like '*chromell*') {Start-Process chrome.exe $urls2}
        else {Start-Process $urls2}
        }
    }

Function Get-vCenter {

# Function to get the vCenter for a vm
# -o parameter opens a web browser search for the vm in vCenter
# Example: Get-vCenter dc01.contoso.test -o

    param(
    [CmdletBinding()]
    [parameter(Position=0)][string]$ComputerName,
    [switch]$o
    )

    if ($node -eq $false) {
        Write-Host "Missind Node!"
        Write-Host "Get-vCenter <hostname> [-o]"
    }

  foreach ($vm in $ComputerName)
    {
    foreach ($vCenter in $vCenters){
        [void](Connect-VIServer $vcenter -Credential $cred -ErrorAction SilentlyContinue)
        if ($vm -cmatch "esx" -cmatch "3par") {
        [void]($res = Get-VMhost $vm* -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })
        } else {
        [void]($res = Get-VM $vm*  -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })
        }
        if ($res -ne $null)
        {
            Write-host "VM: " -f Cyan -NoNewline; Write-Host "$res " -f Yellow -NoNewline; Write-Host "vCenter: " -f Cyan -NoNewline; Write-Host "$vcenter" -f Green
            if ($o) {Start-Process firefox "https://$vcenter/ui/#?extensionId=vsphere.core.search.domainView&query=$res&searchType=simple&forceNavigate"}
            break
            }
        }
        if ($res -eq $null) {
        $res=Get-SCVirtualMachine | Where-Object {$_.ComputerNameString -cmatch $vm} | Select-Object Name | foreach { $_.Name }
        if ($res -ne $null){
        Write-host "VM: " -f Cyan -NoNewline; Write-Host "$res " -f Yellow -NoNewline; Write-Host "vCenter: " -f Cyan -NoNewline; Write-Host "CloudOS" -f Green
        }
      }
      if ($res -eq $null) {Write-Host "Could not find hypervisor" -f Red}
    }
}

function Extend-VMdisk {

# Function to extend a vm disk both in vCenter and expand the disk on the vm
# Take catuion using this function since there is no 2nd validation before th changes takes effekt after parameters have been given.

    Param(
    [CmdletBinding()]
    [Parameter(Mandatory,Position=0)][ValidateNotNullOrEmpty()][String]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

  foreach ($vCenter in $vCenters) 
            {
            [void](Connect-VIServer $vcenter -ErrorAction SilentlyContinue)
            [void]($res = Get-VM $ComputerName*  -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })

            if ($res -ne $null)
                {
                $vc = $vcenter
                $ComputerName = $res
                break
                }
            }


    [void]($winres = Test-NetConnection $ComputerName -Port 3389 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded)
    if ($winres -imatch "true") {$os = "windows"} else {$os = "linux"}

            $Disks = Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-WmiObject Win32_Volume -Filter "DriveType='3'"}
            foreach ($PSObject in $Disks) {
                New-Object PSObject -Property @{
                    Name = $PSObject.Name
                    Label = $PSObject.Label
                    FreeSpace_GB = ([Math]::Round($PSObject.FreeSpace /1GB,2))
                    TotalSize_GB = ([Math]::Round($PSObject.Capacity /1GB,2))
                }
            }

            $Disks = Invoke-Command -computername $ComputerName -Credential $cred {Get-wmiobject  Win32_LogicalDisk -ErrorAction SilentlyContinue -filter "DriveType= 3"}
            $Servername = Invoke-Command -ComputerName $ComputerName -Credential $cred {(Get-wmiobject  CIM_ComputerSystem).Name}
            foreach ($objdisk in $Disks) 
            {
    	        $out=New-Object PSObject
	            $total=“{0:N0}” -f ($objDisk.Size/1GB) 
	            $free=[math]::Round($objDisk.FreeSpace/1GB,2)
	            $freePercent=“{0:P0}” -f ([double]$objDisk.FreeSpace/[double]$objDisk.Size) 
    	            $out | Add-Member -MemberType NoteProperty -Name "Servername" -Value $Servername
    	            $out | Add-Member -MemberType NoteProperty -Name "Drive" -Value $objDisk.DeviceID 
    	            $out | Add-Member -MemberType NoteProperty -Name "Total size (GB)" -Value $total
    	            $out | Add-Member -MemberType NoteProperty -Name “Free Space (GB)” -Value $free
    	            $out | Add-Member -MemberType NoteProperty -Name “Free Space (%)” -Value $freePercent
    	            $out | Add-Member -MemberType NoteProperty -Name "Name " -Value $objdisk.volumename
    	            $out | Add-Member -MemberType NoteProperty -Name "DriveType" -Value $objdisk.DriveType
	                $out | Format-Table
            }

            Connect-VIServer $vc
            $dres = get-vm $ComputerName | Get-HardDisk | Select-Object CapacityGB, Name | Out-GridView -PassThru
            $disk = $dres | foreach { $_.Name }
            $vsize = Read-Host "Total size (GB)"
            Get-VM $ComputerName | Get-HardDisk | where {$_.Name -eq "$disk"} | Set-HardDisk -CapacityGB $vsize -Confirm:$false
    Start-Sleep -Seconds 2
            if ($os -eq "windows"){

                    $sel =Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, @{Name="GB";Expression={$_.size/1GB}}} | Out-GridView -PassThru
                    Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $sel -ScriptBlock {
                    $sel = $args[0]
                    $disknumber = $sel | foreach { $_.DiskNumber }
                    $parnumber = $sel | foreach { $_.PartitionNumber }
                    $size = (Get-PartitionSupportedSize -DiskNumber $disknumber -PartitionNumber $parnumber)
                    Resize-Partition -DiskNumber $disknumber -PartitionNumber $parnumber -Size $size.SizeMax
                    }
              }
            

    Write-Host "Volume successfully expanded"
    if ($os -eq "linux") {Write-Host "Remember to expand LVM"}
}

function Extend-VMmemory {

# Extending VM memory in vCenter
# Example: Extend-VMmemory dc01.contoso.test

    Param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

  foreach ($vm in $ComputerName)
        {
        foreach ($vCenter in $vCenters) 
            {
            [void](Connect-VIServer $vcenter -ErrorAction SilentlyContinue)
            [void]($res = Get-VM $vm* -ErrorAction SilentlyContinue | Select-Object Name)

            if ($res -ne $null)
                {
                $vc = $vcenter
                break
                }
            }
    
            Connect-VIServer $vc
            Get-VM $vm | Select-Object MemoryGB | Format-List
            $vsize = Read-Host "Total size (GB)"
            Get-VM $vm | Set-VM -MemoryGB $vsize -Confirm:$false
    }
}

function os {

# Determine if it is a windows or linux node
# Example: os dc01.contoso.test

    Param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    foreach ($pc in $ComputerName)
        {
        [void]($winres = Test-NetConnection $pc -Port 3389 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded)
        [void]($linres = Test-NetConnection $pc -Port 22 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded)
        [void]($hname = nslookup.exe $pc | Select-String -Pattern 'Name' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

        if ($winres -imatch "true") {
            Write-Host "Host: " -f Cyan -NoNewline; Write-Host "$pc  " -f Yellow -NoNewline; Write-Host "==Windows==" -f Green
            if ([bool]($pc -as [ipaddress]) -eq $true) {Write-Host $hname -f Cyan -NoNewline}
        } elseif ($linres -imatch "true") {
            Write-Host "Host: " -f Cyan -NoNewline; Write-Host "$pc  " -f Yellow -NoNewline; Write-Host "==Linux==" -f Green
            if ([bool]($pc -as [ipaddress]) -eq $true) {Write-Host $hname -f Cyan -NoNewline}
        } else {
            Write-Host "Host: " -f Cyan -NoNewline; Write-Host "$pc  " -f Yellow -NoNewline; Write-Host "==No response==" -f Red
            }
        }
}

function Get-VMdisk {

# Fetching VM node disks and size from vCenter
# Example: Get-VMdisk dc01.contoso.test

    Param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

  foreach ($vm in $ComputerName)
        {
        foreach ($vCenter in $vCenters) 
            {
            [void](Connect-VIServer $vcenter -ErrorAction SilentlyContinue)
            [void]($res = Get-VM $vm*  -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })

            if ($res -ne $null)
                {
                $vc = $vcenter
                $vm = $res
                break
                }
            }
    
            Connect-VIServer $vc
            Get-VM $vm | Get-HardDisk | Select-Object CapacityGB, Name | Format-List
    }
}

function get-mountpoints {

# Fetching mount points on a windows node
# Example: get-mountpoints dc01.contoso.test

    Param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    Invoke-Command -ComputerName $ComputerName -Credential $cred {
        $TotalGB = @{Name="Capacity(GB)";expression={[math]::round(($_.Capacity/ 1073741824),2)}}
        $FreeGB = @{Name="FreeSpace(GB)";expression={[math]::round(($_.FreeSpace / 1073741824),2)}}
        $FreePerc = @{Name="Free(%)";expression={[math]::round(((($_.FreeSpace / 1073741824)/($_.Capacity / 1073741824)) * 100),0)}}
        $volumes = Get-WmiObject win32_volume -Filter "DriveType='3'"
        $volumes | Select Name, Label, DriveLetter, FileSystem, $TotalGB, $FreeGB, $FreePerc
        }
}

Function Get-VMLog {

# Getting VM logs from vCenter
# Example: Get-VMLog dc01.contoso.test -out -maxsamples 5

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [switch]$out,
    [switch]$today,
    [string]$maxsamples
    )

  $dt = get-date -Format MM/dd

  foreach ($vm in $ComputerName)
        {


        foreach ($vCenter in $vCenters) 
            {
            [void](Connect-VIServer $vcenter -ErrorAction SilentlyContinue)
            if ($vm -cmatch "esx") {
            [void]($res = Get-VMhost $vm* -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })
            } else {
            [void]($res = Get-VM $vm*  -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })
            }

            if ($res -ne $null)
                {
                $vc = $vcenter
                $vm = $res
                break
                }
            }

            if (!$maxsamples) {
                $maxsamples = "20"
                }

            [void](Connect-VIServer $vc)
            if ($today) {
            $res=Get-VIEvent -Entity $vm -MaxSamples $maxsamples -start $dt
            } else {
            $res=Get-VIEvent -Entity $vm -MaxSamples $maxsamples
            }
            if ($out){
            $res | Select-Object ObjectName,CreatedTime,FullFormattedMessage,UserName,Initiator | Out-GridView -PassThru | Format-Table -AutoSize -Wrap | clip
            }
            $res | Select-Object ObjectName,CreatedTime,FullFormattedMessage,UserName,Initiator | Format-Table -AutoSize -Wrap
            $res | Select-Object ObjectName,CreatedTime,FullFormattedMessage,UserName,Initiator | Format-Table -AutoSize -Wrap | clip
    }
}

Function Service {

# Getting the service on remote machine 
# Example: service dc01.contoso.test *health* -start

    param(
    [CmdletBinding()]
    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][string]$ComputerName,
    [Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true)][string]$comm,
    [switch]$start,
    [switch]$stop,
    [switch]$restart,
    [switch]$dependencies
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    if ($dependencies) {
        Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList "$comm" -ScriptBlock {(get-service $args[0]).DependentServices | ft -AutoSize -Wrap}
        }

    if ($start)
        {
        Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList "$comm" -ScriptBlock {Start-Service $args[0] | ft -AutoSize -Wrap}
        }
  
    if ($stop) {
        Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList "$comm" -ScriptBlock {stop-Service $args[0]| ft -AutoSize -Wrap}
        }

    $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList "$comm" -ScriptBlock {Get-Service -displayname $args[0] -ErrorAction SilentlyContinue | select status,name,displayname,StartType | ft -AutoSize -Wrap}
    if ($res -ne $null) {
        echo $res
        } else {
            Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList "$comm" -ScriptBlock {Get-Service -name $args[0] | select status,name,displayname,StartType | ft -AutoSize -Wrap}
            }
}

Function Get-Time {

# Getting the clock time on remote machine 
# Example: get-time dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$True,Position=0)][string]$ComputerName,
    [switch]$sync
    )
    if ($sync) {Invoke-Command -ComputerName $ComputerName {w32tm.exe /resync}}
    Invoke-Command -ComputerName $ComputerName {w32tm.exe /query /status}
}

Function Get-RealTimeProtectionStaus {

# Getting the real time protection status on remote machine 
# Example: Get-RealTimeProtectionStaus dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [switch]$enable
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

   echo ""

   if ($enable) {
   Invoke-Command -ComputerName $ComputerName -Credential $cred {Set-MpPreference -DisableRealtimeMonitoring $false}
   }

   $res = Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-MpPreference | foreach {$_.DisableRealtimeMonitoring}}

   if ($res -eq $true) {
       Write-Host -ForegroundColor Cyan "======================="
       Write-Host -ForegroundColor Yellow "RTP is disabled."
       Write-Host -ForegroundColor Cyan "======================="
   }

   if ($res -eq $false) {
       Write-Host -ForegroundColor Cyan "======================="
       Write-Host -ForegroundColor Green "RTP is enabled."
       Write-Host -ForegroundColor Cyan "======================="
   }

   echo ""

   Write-Host -ForegroundColor Green "GPO for Real time monitoring"
   Write-Host -ForegroundColor Cyan "==================================================================================================="
   Invoke-Command -ComputerName $ComputerName -Credential $cred {gpresult.exe /v} | Select-String -Pattern "DisableRealtimeMonitoring"
}

Function Get-Definitionstatus {

# Gettng/Update defender definitions on remote machine 
# Example: Get-Definitionstatus dc01.contoso.test -update

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [switch]$update
    )

    if ($update) {
        Invoke-Command -ComputerName $ComputerName -Credential $cred {Update-MpSignature}
        $res=Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-MpComputerStatus | Select-Object NISSignatureLastUpdated} | foreach {$_.NISSignatureLastUpdated}
        Write-Host -ForegroundColor Yellow -NoNewline "Forefront Definitions updated: "; Write-Host -ForegroundColor Green $res
    } else {
    $res=Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-MpComputerStatus | Select-Object NISSignatureLastUpdated} | foreach {$_.NISSignatureLastUpdated}
    Write-Host -ForegroundColor Yellow -NoNewline "Forefront Definitions updated: "; Write-Host -ForegroundColor Green $res
    }
}

Function Get-Info {

# Gettng uptime, last reboot log and logged-on users on remote machine
# Example: Get-Info dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$false,Position=0)][string]$ComputerName,
    [string]$newest
    )
        
    if (!$newest) {$newest = "1"}
    if (!$ComputerName){$ComputerName = Get-Clipboard}
    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

        function out {
        $uptime = Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock {(get-date) - (gcim Win32_OperatingSystem).LastBootUpTime} | Select-Object Days,Hours,Minutes,Seconds
        Write-Host -ForegroundColo Green "Uptime $ComputerName";$uptime
        Invoke-Command -computername $ComputerName -Credential $cred -ArgumentList $newest -ScriptBlock {Get-EventLog -logname system -source user32 -newest $args[0] | format-table -wrap}
        query USER /SERVER:$ComputerName
        }
        $fout = out;$fout | clip;$fout
}

Function Get-UsersSessions{

# Gettng logged-on users on remote machine
# Example: Get-UsersSessions dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )
        query USER /SERVER:$ComputerName
}

Function log {

<# .SYNOPSIS

     EventLog parser 

.DESCRIPTION

     Fetching event logs on remote PC
     Example : log hostname.test.net -logname system -before 11:00 -after 10:00 -date 10/14

.NOTES

     Author     : Trond Weiseth
#>

param(
    [CmdletBinding()]
    [Parameter(Mandatory=$false,Position=0)][string]$ComputerName,
    [string]$time,
    [string]$newest,
    [string]$before,
    [string]$after,
    [Parameter()]

    [string]$date,
    [string]$source,
    [switch]$o,
    [switch]$help,
    [Parameter(Mandatory=$false,ParameterSetName="LogName")]
    [ValidateSet("system","application","security")]
    [string]$logname
    )

    if ($date -imatch 'day' -or $date -imatch'today' -or $date -imatch 'current' -or $date -imatch 'now') {
        $date = $(get-date -Format MM/dd)
    }

    $arglst = @("$newest","$time","$logname","$date","$before","$after")

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

function help() {

    Write-Host -ForegroundColor Green "###################################################################################################################################"
    Write-Host -ForegroundColor Yellow " Syntax: log <host> [-newest <number>] [-time <time>] [-logname <logname>] [-date <MM/dd/yyyy>] [-before <time>] [-after <time>]"
    Write-Host -ForegroundColor Green "---------------------"
    Write-Host -ForegroundColor Yellow " Example:"
    Write-Host ""    
    Write-Host -ForegroundColor Yellow "     log -ComputerName $env:COMPUTERNAME -newest 1000 -time 10:10 -logname system -date 10/14/2020"
    Write-Host -ForegroundColor Yellow "     log $env:COMPUTERNAME -logname system -before 11:00 -after 10:00 -date current"
    Write-Host -ForegroundColor Green "###################################################################################################################################"
} 

function parser1() {

    param (
    $newest,
    $time,
    $logname,
    $date,
    $before,
    $after
    )
    
    if (!$newest) {$newest = "200"}
    if ($after -and $before) {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -gt $after -and $_.TimeGenerated -lt $before}
    } elseif ($after) {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -gt $after}
    } elseif ($before) {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -lt $before}
    } elseif ($date) {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch $date}
    } elseif ($date -and $before) {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before}
    } elseif ($date -and $before -and $after) {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before -and $_.TimeGenerated -gt $after}
    } else {
        Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch "$time"}
    }
}
 
function parser2() {

    param (
    $newest,
    $time,
    $logname,
    $date,
    $before,
    $after
    )
    
    if (!$newest) {$newest = "200"}
    $lognames="Application","Security","System"
    
    if ($after -and $before) {
        $lognames | ForEach-Object {
            Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -gt $after -and $_.TimeGenerated -lt $before}
            }
     } elseif ($after) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -gt $after}
                }
     } elseif ($before) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -lt $before}
                }
     } elseif ($date) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -imatch $date}
                }
     } elseif ($date -and $before) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before}
                }
     } elseif ($date -and $before -and $after) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before -and $_.TimeGenerated -gt $after}
                }
     } else {
            $lognames | ForEach-Object {
                Get-EventLog -LogName $_ -Newest $newest | where {$_.TimeGenerated -imatch "$time"}
                }
    }
}

function outpars() {

    if ($o) {
        $res | Format-Table -AutoSize -Wrap
        $res | Format-Table -AutoSize -Wrap | clip
    } else {
        $res | Out-GridView -PassThru |  Format-Table -AutoSize -Wrap | clip
    }
}

if ($help -or !$ComputerName) {
    help
} else {
    if ($logname) {
        $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList ${arglst} -ScriptBlock ${function:parser1}
    } else {
        $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList ${arglst} -ScriptBlock ${function:parser2}
    }
}
outpars
}

Function log-gui() {

<# .SYNOPSIS
     EventLog parser
.DESCRIPTION
     Gettng event logs on local or remote PC
.NOTES
     Author     : Trond Weiseth
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(405,252)
$Form.TopMost                    = $false

$Groupbox1                       = New-Object system.Windows.Forms.Groupbox
$Groupbox1.height                = 37
$Groupbox1.width                 = 409
$Groupbox1.location              = New-Object System.Drawing.Point(-3,-2)
$Groupbox1.BackColor             = [System.Drawing.ColorTranslator]::FromHtml("#b8e986")

$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Eventlog Parser"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(11,12)
$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$computername1                   = New-Object system.Windows.Forms.TextBox
$computername1.multiline         = $false
$computername1.width             = 145
$computername1.height            = 20
$computername1.location          = New-Object System.Drawing.Point(122,38)
$computername1.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$computername1.Add_Click( { $this.SelectAll(); $this.Focus() })
$computername1.Add_KeyDown({if ($_.KeyCode -eq "Enter") { log }})

$all                             = New-Object system.Windows.Forms.RadioButton
$all.text                        = "All"
$all.AutoSize                    = $true
$all.width                       = 82
$all.height                      = 26
$all.location                    = New-Object System.Drawing.Point(10,95)
$all.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$system                          = New-Object system.Windows.Forms.RadioButton
$system.text                     = "System"
$system.AutoSize                 = $true
$system.width                    = 82
$system.height                   = 26
$system.location                 = New-Object System.Drawing.Point(10,69)
$system.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$security                        = New-Object system.Windows.Forms.RadioButton
$security.text                   = "Security"
$security.AutoSize               = $true
$security.width                  = 82
$security.height                 = 26
$security.location               = New-Object System.Drawing.Point(10,43)
$security.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$application                     = New-Object system.Windows.Forms.RadioButton
$application.text                = "Application"
$application.AutoSize            = $true
$application.width               = 82
$application.height              = 26
$application.location            = New-Object System.Drawing.Point(10,17)
$application.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$newest1                         = New-Object system.Windows.Forms.TextBox
$newest1.multiline               = $false
$newest1.width                   = 145
$newest1.height                  = 20
$newest1.Text                    = "200"
$newest1.location                = New-Object System.Drawing.Point(122,65)
$newest1.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$newest1.Add_Click( { $this.SelectAll(); $this.Focus() })
$newest1.Add_KeyDown({if ($_.KeyCode -eq "Enter") { log }})

$Groupbox2                       = New-Object system.Windows.Forms.Groupbox
$Groupbox2.height                = 121
$Groupbox2.width                 = 112
$Groupbox2.text                  = "EventLogs"
$Groupbox2.location              = New-Object System.Drawing.Point(1,36)
$Groupbox2.BackColor             = [System.Drawing.ColorTranslator]::FromHtml("#9b9b9b")

$date1                           = New-Object system.Windows.Forms.TextBox
$date1.multiline                 = $false
$date1.width                     = 145
$date1.height                    = 20
$date1.Text                      = $(get-date -Format MM/dd)
$date1.location                  = New-Object System.Drawing.Point(122,92)
$date1.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$date1.Add_Click( { $this.SelectAll(); $this.Focus() })
$date1.Add_KeyDown({if ($_.KeyCode -eq "Enter") { log }})

$before1                         = New-Object system.Windows.Forms.TextBox
$before1.multiline               = $false
$before1.width                   = 145
$before1.height                  = 20
$before1.location                = New-Object System.Drawing.Point(122,119)
$before1.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$before1.Add_Click( { $this.SelectAll(); $this.Focus() })
$before1.Add_KeyDown({if ($_.KeyCode -eq "Enter") { log }})

$after1                          = New-Object system.Windows.Forms.TextBox
$after1.multiline                = $false
$after1.width                    = 145
$after1.height                   = 20
$after1.location                 = New-Object System.Drawing.Point(122,146)
$after1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$after1.Add_Click( { $this.SelectAll(); $this.Focus() })
$after1.Add_KeyDown({if ($_.KeyCode -eq "Enter") { log }})

$time1                           = New-Object system.Windows.Forms.TextBox
$time1.multiline                 = $false
$time1.width                     = 145
$time1.height                    = 20
$time1.location                  = New-Object System.Drawing.Point(122,173)
$time1.Font                      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$time1.Add_Click( { $this.SelectAll(); $this.Focus() })
$time1.Add_KeyDown({if ($_.KeyCode -eq "Enter") { log }})

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Run"
$Button1.width                   = 327
$Button1.height                  = 30
$Button1.location                = New-Object System.Drawing.Point(34,205)
$Button1.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$Button1.BackColor               = [System.Drawing.ColorTranslator]::FromHtml("#b8e986")

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "After <Time>"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(277,152)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "ComputerName"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(277,42)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label4                          = New-Object system.Windows.Forms.Label
$Label4.text                     = "Before <time>"
$Label4.AutoSize                 = $true
$Label4.width                    = 25
$Label4.height                   = 10
$Label4.location                 = New-Object System.Drawing.Point(277,124)
$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label5                          = New-Object system.Windows.Forms.Label
$Label5.text                     = "Time"
$Label5.AutoSize                 = $true
$Label5.width                    = 25
$Label5.height                   = 10
$Label5.location                 = New-Object System.Drawing.Point(277,178)
$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label6                          = New-Object system.Windows.Forms.Label
$Label6.text                     = "Newest"
$Label6.AutoSize                 = $true
$Label6.width                    = 25
$Label6.height                   = 10
$Label6.location                 = New-Object System.Drawing.Point(277,70)
$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Label7                          = New-Object system.Windows.Forms.Label
$Label7.text                     = "Date"
$Label7.AutoSize                 = $true
$Label7.width                    = 25
$Label7.height                   = 10
$Label7.location                 = New-Object System.Drawing.Point(277,97)
$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Form.controls.AddRange(@($Groupbox1,$computername1,$newest1,$Groupbox2,$date1,$before1,$after1,$time1,$Button1,$Label2,$Label3,$Label4,$Label5,$Label6,$Label7))
$Groupbox1.controls.AddRange(@($Label1))
$Groupbox2.controls.AddRange(@($all,$system,$security,$application))

$Button1.Add_Click({ log })

function log {
    if ($system.Checked -eq $true) {
        $logname = "system"
    } elseif ($security.Checked -eq $true) {
            $logname = "security"
    } elseif ($application.Checked -eq $true) {
            $logname = "application"
    }

    $ComputerName = $computername1.Text
    $newest = $newest1.Text
    $time = $time1.Text
    $newest = $newest1.Text
    $before = $before1.Text
    $after = $after1.Text
    $date = $date1.Text
    $arglst = @("$newest","$time","$logname","$date","$before","$after")

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }
    
    function parser1() {

        param (
        $newest,
        $time,
        $logname,
        $date,
        $before,
        $after
        )

        if (!$newest) {$newest = "200"}
        if ($after -and $before) {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -gt $after -and $_.TimeGenerated -lt $before}
        } elseif ($after) {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -gt $after}
        } elseif ($before) {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -lt $before}
        } elseif ($date) {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch $date}
        } elseif ($date -and $before) {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -lt $date -and $_.TimeGenerated -lt $before}
        } elseif ($date -and $before -and $after) {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before -and $_.TimeGenerated -gt $after}
        } else {
            Get-EventLog -Newest $newest -LogName $logname | where {$_.TimeGenerated -imatch "$time"}
        }
    }
    
    function parser2() {

        param (
        $newest,
        $time,
        $logname,
        $date,
        $before,
        $after
        )

        $lognames="Application","Security","System"
        if (!$newest) {$newest = "200"}
        if ($after -and $before) {
            $lognames | ForEach-Object {
                Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -gt $after -and $_.TimeGenerated -lt $before}
                }
        } elseif ($after) {
                $lognames | ForEach-Object {
                    Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -gt $after}
                    }
        } elseif ($before) {
                $lognames | ForEach-Object {
                    Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -lt $before}
                    }
        } elseif ($date) {
                $lognames | ForEach-Object {
                    Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -imatch $date}
                    }
        } elseif ($date -and $before) {
                $lognames | ForEach-Object {
                    Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before}
                    }
        } elseif ($date -and $before -and $after) {
                $lognames | ForEach-Object {
                    Get-EventLog -Newest $newest -LogName $_ | where {$_.TimeGenerated -imatch $date -and $_.TimeGenerated -lt $before -and $_.TimeGenerated -gt $after}
                    }
        } else {
                $lognames | ForEach-Object {
                    Get-EventLog -LogName $_ -Newest $newest | where {$_.TimeGenerated -imatch "$time"}
                    }
        }
    }
    
    function outpars() {
        $res | Out-GridView -PassThru |  Format-Table -AutoSize -Wrap | clip
    }

    if ($logname) {
        $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList ${arglst} -ScriptBlock ${function:parser1}
        }

    elseif ($all.Checked) {
        $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList ${arglst} -ScriptBlock ${function:parser2}
        }
    outpars
    }
[void]$Form.ShowDialog()
}

function Get-LoggedonUser ($computername){


    $regexa = '.+Domain="(.+)",Name="(.+)"$'
    $regexd = '.+LogonId="(\d+)"$'

    $logontype = @{
    "0"="Local System"
    "2"="Interactive" #(Local logon)
    "3"="Network" # (Remote logon)
    "4"="Batch" # (Scheduled task)
    "5"="Service" # (Service account logon)
    "7"="Unlock" #(Screen saver)
    "8"="NetworkCleartext" # (Cleartext network logon)
    "9"="NewCredentials" #(RunAs using alternate credentials)
    "10"="RemoteInteractive" #(RDP\TS\RemoteAssistance)
    "11"="CachedInteractive" #(Local w\cached credentials)
    }

    $logon_sessions = @(gwmi win32_logonsession -ComputerName $computername)
    $logon_users = @(gwmi win32_loggedonuser -ComputerName $computername)

    $session_user = @{}

    $logon_users |% {
    $_.antecedent -match $regexa > $nul
    $username = $matches[1] + "\" + $matches[2]
    $_.dependent -match $regexd > $nul
    $session = $matches[1]
    $session_user[$session] += $username
    }


    $logon_sessions |%{
    $starttime = [management.managementdatetimeconverter]::todatetime($_.starttime)

    $loggedonuser = New-Object -TypeName psobject
    $loggedonuser | Add-Member -MemberType NoteProperty -Name "Session" -Value $_.logonid
    $loggedonuser | Add-Member -MemberType NoteProperty -Name "User" -Value $session_user[$_.logonid]
    $loggedonuser | Add-Member -MemberType NoteProperty -Name "Type" -Value $logontype[$_.logontype.tostring()]
    $loggedonuser | Add-Member -MemberType NoteProperty -Name "Auth" -Value $_.authenticationpackage
    $loggedonuser | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $starttime
    
    $loggedonuser | Where {$_.StartTime -gt (Get-Date).AddDays(-1)} | ft -AutoSize
    }

}

Function remote {

# Opens a PSsession to remote computer
# Example: remote dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$True,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    Enter-PSSession $ComputerName -Credential $cred
}

Function Get-CloudOS {

# Getting CloudOS vm info
# Example: Get-CloudOS dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    Get-SCVirtualMachine $ComputerName | Select-Object ComputerName,VMHost,VirtualizationPlatform,Description,Virtualmachinestate,OperatingSystem,VMResourceStatus,Memory,CreationTime,ModifiedTime,Owner
}

Function Get-Tsk {
    
# Getting/staring task from task scheduler on remote computer
# Example: Get-Tsk dc01.contoso.test -start
   
    param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [parameter(Mandatory=$true,Position=1)][string]$TaskName,
    [switch]$start,
    [switch]$stop
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    if ($start) {Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $TaskName -ScriptBlock {Get-ScheduledTask $args[0] | Start-ScheduledTask}}
    if ($stop) {Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $TaskName -ScriptBlock {Get-ScheduledTask $args[0] | Stop-ScheduledTask}}
    Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $TaskName -ScriptBlock {Get-ScheduledTask $args[0] | ft -AutoSize}
}

Function rcurl {

# running curl on remote computer
# Example: rcurl dc01.contoso.test <url>

    param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [parameter(Mandatory=$true,Position=1)][string]$uri
    )

    Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $uri -ScriptBlock {Invoke-WebRequest -Uri $args[0] | Select-Object StatusCode,StatusDescription,Content | Format-List}
    }

Function Get-DiskUsage {

# Getting storage use for disks and mount points
# Example: Get-DiskUsage dc01.contoso.test

    param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    $Disks = Invoke-Command -ComputerName $ComputerName -Credential $cred {Get-WmiObject Win32_Volume -Filter "DriveType='3'"}
    foreach ($PSObject in $Disks) {
        New-Object PSObject -Property @{
            Name = $PSObject.Name
            Label = $PSObject.Label
            FreeSpace_GB = ([Math]::Round($PSObject.FreeSpace /1GB,2))
            TotalSize_GB = ([Math]::Round($PSObject.Capacity /1GB,2))
        }
    }

    $Disks = Invoke-Command -computername $ComputerName -Credential $cred {Get-wmiobject  Win32_LogicalDisk -ErrorAction SilentlyContinue -filter "DriveType= 3"}
    $Servername = Invoke-Command -ComputerName $ComputerName -Credential $cred {(Get-wmiobject  CIM_ComputerSystem).Name}
    foreach ($objdisk in $Disks) 
    {
    	$out=New-Object PSObject
	    $total=“{0:N0}” -f ($objDisk.Size/1GB) 
	    $free=[math]::Round($objDisk.FreeSpace/1GB,2)
	    $freePercent=“{0:P0}” -f ([double]$objDisk.FreeSpace/[double]$objDisk.Size) 
    	    $out | Add-Member -MemberType NoteProperty -Name "Servername" -Value $Servername
    	    $out | Add-Member -MemberType NoteProperty -Name "Drive" -Value $objDisk.DeviceID 
    	    $out | Add-Member -MemberType NoteProperty -Name "Total size (GB)" -Value $total
    	    $out | Add-Member -MemberType NoteProperty -Name “Free Space (GB)” -Value $free
    	    $out | Add-Member -MemberType NoteProperty -Name “Free Space (%)” -Value $freePercent
    	    $out | Add-Member -MemberType NoteProperty -Name "Name " -Value $objdisk.volumename
    	    $out | Add-Member -MemberType NoteProperty -Name "DriveType" -Value $objdisk.DriveType
	        $out | Format-Table
    }
}

Function snapshot {

# Getting/deleteing snapshots on vcenter for a vm
# Example: snapshot dc01.contoso.test -days 10 -del
    
    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$false,Position=0)][string]$ComputerName,
    [string]$days,
    [switch]$del
    )

    if ((Test-Path ".\hosts.txt") -eq $false) {
            New-Item -Path . -Name "hosts.txt" -ItemType "file" -Value "===== Paste host(s) here =======" -ErrorAction SilentlyContinue | Out-Null
    }

    
    function content {
        notepad.exe ./hosts.txt | Out-Null
        Get-Content ./hosts.txt | Get-Unique | Out-File .\hoststmp.txt
        Remove-Item ./hosts.txt
        Get-Content ./hoststmp.txt | Out-File .\hosts.txt
        Remove-Item ./hoststmp.txt
    }

    if (!$ComputerName) {content}
    else {$ComputerName | Out-File .\hosts.txt}

    $time = $days
    if (!$time) {$time = '7'}

    $list = Get-Content ".\hosts.txt"
    $vmone = Get-Content ".\hosts.txt" -First 1
   

       foreach ($vCenter in $vCenters){
            [void](Connect-VIServer $vcenter -ErrorAction SilentlyContinue)
            [void]($res = Get-VM $vmone*  -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })
        
            if ($res -ne $null) {
                $vCenterone = $vCenter
                break
                }
           }

   [void](Connect-VIServer $vcenterone -ErrorAction SilentlyContinue)

    Write-Host "Days back: " -f Cyan -NoNewline; Write-Host $time -f Green
    
    if ($del){
        $list | ForEach-Object {Get-VM $_ | Get-Snapshot | Where {$_.Created -lt (Get-Date).AddDays(-$time)} |  Remove-Snapshot -confirm:$false}
    }
    else {
        $list | ForEach-Object {Get-VM $_ | Get-Snapshot | Where {$_.Created -lt (Get-Date).AddDays(-$time)} | Select-Object VM, Name, Created, Description} | Format-Table -AutoSize -Wrap
    }
}

function Get-CustomerHosts(){

# Fetching a list over all hosts registered on a customer

    $prefixPreSan =  read-host 'Customer prefix: '

    if ($prefixPreSan -match '\*'){

        $mydocuments = [environment]::getfolderpath("mydocuments")

        write-host Saving files in: $mydocuments -ForegroundColor Yellow

        New-SCOMManagementGroupConnection -ComputerName ccwp0opsv00001

        $test = Get-SCOMMonitoringObject -class  (Get-SCOMClass -name "Microsoft.windows.computer")

        write-host Hosts found: $test.count  -ForegroundColor Yellow

        Out-File -filepath $mydocuments\HostsUnsorted.txt -InputObject $test.DisplayName

        Get-Content $mydocuments\HostsUnsorted.txt | sort | Get-Unique > $mydocuments\ALL-Hosts.txt

        del $mydocuments\HostsUnsorted.txt

        write-host Done! -ForegroundColor Green

        getdisks

    }else{

        $prefix = $prefixPreSan -replace '([^A-Z])',''

        $mydocuments = [environment]::getfolderpath("mydocuments")

        if(!(Test-Path -Path $mydocuments\$prefix ))

            { 

                mkdir $mydocuments\$prefix >$null

            }

        write-host Saving files in: $mydocuments\$prefix -ForegroundColor Yellow

        New-SCOMManagementGroupConnection -ComputerName ccwp0opsv00001

        $test = Get-SCOMMonitoringObject -class  (Get-SCOMClass -name "Microsoft.windows.computer") |  Select-String -Pattern "^$prefix-.*"

        write-host Hosts found: $test.count  -ForegroundColor Yellow

        Out-File -filepath $mydocuments\HostsUnsorted.txt -InputObject $test

        Get-Content $mydocuments\HostsUnsorted.txt | sort | Get-Unique > $mydocuments\$prefix\$prefix-Hosts.txt

        del $mydocuments\HostsUnsorted.txt

        write-host Done! -ForegroundColor Green

        getprefixdisks

    }

}

Function Open-VMRC {

# Opens vmrc console for vCenter vm
# Example: Open-VMRC dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$True,Position=0)][string]$ComputerName
    )

    if (!$ComputerName){
        echo "Missing hostname."
        echo "Example: Open-VMRC hostname.test.net"
        }
    else {
      foreach ($vm in $ComputerName){
            foreach ($vCenter in $vCenters) 
                {
                [void](Connect-VIServer $vcenter -ErrorAction SilentlyContinue)
                [void]($res = Get-VM $vm*  -ErrorAction SilentlyContinue| Select-Object name | foreach { $_.Name })

                if ($res -ne $null)
                    {
                    $vc = $vcenter
                    $vm = $res
                    break
                    }
                }
        [void](Connect-VIServer $vc)
        Get-VM $vm | Open-VMConsoleWindow
        }
    }
}

Function Get-proc {

# Getting processes on remote computer
# Example: Get-proc dc01.contoso.test

    param(
    [CmdletBinding()]
    [parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [parameter(Mandatory=$true,Position=1)][string]$process
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $process -ScriptBlock {
        $process = $args[0]
        Get-Process | where {$_.ProcessName -imatch "$process"} | Format-Table -AutoSize -Wrap
        }
}

Function ClusterResource {

# Getting cluster resource on remote computer
# Example: ClusterResouce dc01.contoso.test

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    Invoke-Command -ComputerName $ComputerName -Credential $cred {
    Get-ClusterResource | Select-Object Name,State,OwnerGroup,ResourceType,Cluster | Format-Table -AutoSize -Wrap
    }

}

Function rmt {

# running ps command on remote computer
# Example: rmt dc01.contoso.test get-service *rdp*

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName,
    [Parameter(Mandatory=$true,Position=1)][string]$command
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

        $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $command -ScriptBlock {
            $command = $args[0]
            Invoke-Expression $command
            }
        $res | Format-Table -AutoSize -Wrap | Tee-Object -Variable out
        $out | clip
}

Function SCCMCache-clean {

# Flushing SCCM cache on remote computer
# Example: SCCMCache-clean dc01.contoso.test get-service

    param(
    [CmdletBinding()]
    [Parameter(Mandatory=$true,Position=0)][string]$ComputerName
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock {

        ## Initialize the CCM resource manager com object
        [__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'## Get the CacheElementIDs to delete
        $CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()## Remove cache items
        ForEach ($CacheItem in $CacheInfo) {
            $null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($CacheItem.CacheElementID))
            }
        }
}

Function CPU-Usage {


param(
    [CmdletBinding()]
    [Parameter(Mandatory=$false,Position=0)][string]$ComputerName,
    [Parameter(Mandatory=$false,Position=1)][string]$count
    )

    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    if (!$count) {
            $count = "10"
            }
    if (!$ComputerName){$ComputerName = Get-Clipboard}
    Invoke-Command -ComputerName $ComputerName -Credential $cred -ArgumentList $count -ScriptBlock {
        $count = $args[0]
        $CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors
        (Get-Counter "\Process(*)\% Processor Time").CounterSamples | Select InstanceName, @{Name="CPU %";Expression={[Decimal]::Round(($_.CookedValue / $CpuCores), 2)}} | sort-Object "CPU %" -Descending | Select-Object -First $count |Select-Object InstanceName,"CPU %" | ft
        }
}

Function health-service_cache_clean {
# This is a simple script for clearing the SCOM agent cache on a agent-managed computer.
# The script works both locally and remotely.
#

$Server = Read-Host "Please enter your server name"
$Service = Get-Service -Name HealthService -ComputerName $Server
Write-Host "`n1. Stopping the Monitoring Agent service...`n"
Stop-Service $Service
Write-Host "2. Checking the Monitoring Agent service status:"
Write-Host "`nMonitoring Agent service status: "-nonewline; Write-Host $Service.Status -Fore Red
Start-Sleep -s 3
Write-Host "`n3. Renaming the existing 'Health Service State' folder to 'Health Service State Old' `n"
Rename-Item -Path "\\$Server\C$\Program Files\Microsoft Monitoring Agent\Agent\Health Service State" -NewName "Health Service State Old"
Write-Host "4. Starting the Monitoring Agent service...`n"
Start-Service $Service
Start-Sleep -s 3
Write-Host "5. Checking the Monitoring Agent service status:"
Write-Host "`nMonitoring Agent service status: "-nonewline; Write-Host $Service.Status -Fore Green
Write-Host "`n6. Removing the 'Health Service State Old' folder."
Remove-Item -Path "\\$Server\C$\Program Files\Microsoft Monitoring Agent\Agent\Health Service State Old" -Recurse
Write-Host "`n7. Done!"
}

Function Get-FSMOStatus {
    [CmdletBinding()]    param(
    [Parameter(Mandatory=$True,Position=0)][string]$ComputerName
    )    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }    $res = Invoke-Command -ComputerName $ComputerName -Credential $cred -scriptblock {
        repadmin /showrepl
        repadmin /replsummary
        netdom /query fsmo
        }
    echo $res
    $res | clip
}

Function Port-Test {
[CmdletBinding()]
param(
[Parameter(Position=0,Mandatory=$true)][string]$ip,
[Parameter(Position=1,Mandatory=$true)][string]$port,
[string]$remote,
[switch]$h
)
    if ($ComputerName -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }

    if ($remote) {
         Invoke-Command -ComputerName $remote -Credential $cred -ArgumentList $ip,$port -ScriptBlock {
             $ip = $args[0]
             $port = $args[1]
             $ErrorActionPreference = "SilentlyContinue"
             $CN = $(env:COMPUTERNAME)
             $RA = Resolve-DnsName $ip | foreach {$_.IPAddress}
             $socket = new-object System.Net.Sockets.TcpClient($ip, $port)  
         If($socket.Connected)
           {
            "CumputerName     : $CN"
            "RemoteAddress    : $RA"
            "RemotePort       : $port"
            “TcpTestSucceeded : True”
            $socket.Close() }

         else {
            "CumputerName     : $host"
            "RemoteAddress    : $RA"
            "RemotePort       : $port"
            “TcpTestSucceeded : False” }
            }
         } else {
             $ErrorActionPreference = "SilentlyContinue"
             $CN = $(env:COMPUTERNAME) 
             $RA = $(Resolve-DnsName $ip | foreach {$_.IPAddress})
             $socket = new-object System.Net.Sockets.TcpClient($ip, $port)    
             If($socket.Connected)
               {
                "CumputerName     : $CN"
                "RemoteAddress    : $RA"
                "RemotePort       : $port"
                “TcpTestSucceeded : True”
                $socket.Close() }

             else {
                "CumputerName     : $host"
                "RemoteAddress    : $RA"
                "RemotePort       : $port"
                “TcpTestSucceeded : False” }
            }
}

Function Get-OSVersion {
notepad .\hosts.txt | Out-Null
Get-Content .\hosts.txt | foreach {
    if ($_ -imatch "domain") {
        $uname=("domain\$env:USERNAME")
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $uname,$cred.Password
    }
    Write-Host -NoNewline -ForegroundColor Cyan "ComputerName: " ; write-host -NoNewline -ForegroundColor Yellow $_.ToUpper() ; Write-Host -NoNewline -ForegroundColor Green "`nOS Version: "; invoke-command -ComputerName $_ -Credential $cred {(Get-WmiObject -class Win32_OperatingSystem).Caption}
    }
}

cls
