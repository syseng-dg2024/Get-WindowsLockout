# DISCLAIMER: This script was written in part by AI. Please review before executing.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ==============================================================================
#  Configuration
# ==============================================================================
$HoursBack    = 12
$HoursForward = 12
$TempPath     = 'C:\Temp'

[int[]]$EventIdsGroup1 = @(4625,4740,4776,4771,5816,5817,4724,<#4688,#>4648,4723,4767,4768,4770,4777,4779,4769)
[int[]]$EventIdsGroup2 = @(4624,4634,4647,4672,4722,4725,4738,4778,4800,4801)

# ==============================================================================
#  NPS Lookup Tables
# ==============================================================================
$PacketTypeTable = @{
    '1'='Access-Request';     '2'='Access-Accept'
    '3'='Access-Reject';      '4'='Accounting-Request'
    '5'='Accounting-Response';'11'='Access-Challenge'
}
$ReasonCodeTable = @{
    '0'='The specified reason code is not defined.'
    '1'='The user has provided an incorrect password.'
    '2'='The user has provided an incorrect user name.'
    '3'='The user has provided an incorrect user name and password.'
}
$NpsAuthTypeTable     = @{ '1'='EAP';'2'='MS-CHAP-v2';'3'='MS-CHAP';'4'='PAP';'5'='CHAP';'8'='Custom' }
$NpsProviderTypeTable = @{ '1'='Windows';'2'='NetWare';'3'='RADIUS' }
$NpsClientVendorTable = @{ '0'='Unknown';'1'='Microsoft';'2'='Cisco' }
$NasPortTypeTable     = @{ '5'='Ethernet';'15'='Wireless - IEEE 802.11';'19'='Wireless - IEEE 802.11' }
$NpsServiceTypeTable  = @{ '2'='Framed' }

$CsvHeaders = @(
    'ComputerName','ServiceName','Record-Date','Record-Time','Packet-Type','User-Name',
    'Fully-Qualified-Distinguished-Name','Called-Station-ID','Calling-Station-ID','Callback-Number',
    'Framed-IP-Address','NAS-Identifier','NAS-IP-Address','NAS-Port','Client-Vendor',
    'Client-IP-Address','Client-Friendly-Name','Event-Timestamp','Port-Limit','NAS-Port-Type',
    'Connect-Info','Framed-Protocol','Service-Type','Authentication-Type','Policy-Name','Reason-Code',
    'Class','Session-Timeout','Idle-Timeout','Termination-Action','EAP-Friendly-Name','Acct-Status-Type',
    'Acct-Delay-Time','Acct-Input-Octets','Acct-Output-Octets','Acct-Session-Id','Acct-Authentic',
    'Acct-Session-Time','Acct-Input-Packets','Acct-Output-Packets','Acct-Terminate-Cause',
    'Acct-Multi-Ssn-ID','Acct-Link-Count','Acct-Interim-Interval','Tunnel-Type','Tunnel-Medium-Type',
    'Tunnel-Client-Endpt','Tunnel-Server-Endpt','Acct-Tunnel-Conn','Tunnel-Pvt-Group-ID',
    'Tunnel-Assignment-ID','Tunnel-Preference','MS-Acct-Auth-Type','MS-Acct-EAP-Type','MS-RAS-Version',
    'MS-RAS-Vendor','MS-CHAP-Error','MS-CHAP-Domain','MS-MPPE-Encryption-Types',
    'MS-MPPE-Encryption-Policy','Proxy-Policy-Name','Provider-Type','Provider-Name',
    'Remote-Server-Address','MS-RAS-Client-Name','MS-RAS-Client-Version'
)

# ==============================================================================
#  Security Event Translations
# ==============================================================================
$EventDescriptions = @{
    4624='An account was successfully logged on.'
    4625='An account failed to log on.'
    4634='An account was logged off.'
    4647='User initiated logoff.'
    4648='A logon was attempted using explicit credentials.'
    4672='Special privileges assigned to new logon.'
    4688='A new process has been created.'
    4722='A user account was enabled.'
    4723='An attempt was made to change an account password.'
    4724='An attempt was made to reset an account password.'
    4725='A user account was disabled.'
    4738='A user account was changed.'
    4740='A user account was locked out.'
    4767='A user account was unlocked.'
    4768='A Kerberos authentication ticket (TGT) was requested.'
    4769='A Kerberos service ticket was requested.'
    4770='A Kerberos service ticket was renewed.'
    4771='Kerberos pre-authentication failed.'
    4776='The computer attempted to validate the credentials for an account.'
    4777='The domain controller failed to validate the credentials for an account.'
    4778='A session was reconnected to a Window Station.'
    4779='A session was disconnected from a Window Station.'
    4800='The workstation was locked.'
    4801='The workstation was unlocked.'
    5379='Credential Manager credentials were read.'
    5816='Netlogon has failed an authentication. Request timed out.'
    5817='Netlogon has failed an authentication. Request timed out.'
    5823='User or Computer password has been changed.'
    6273='Network Policy Server denied access to a user.'
    5156='The Windows Filtering Platform has permitted a connection.'
    5158='The Windows Filtering Platform has permitted a bind to a local port.'
}

$LogonTypes = @{
    '2'='Interactive';'3'='Network';'4'='Batch';'5'='Service'
    '8'='Plain Text';'9'='RunAs';'10'='Remote Interactive';'11'='Cached Interactive'
}

$StatusDescriptions = @{
    '0xC0000064'='User not found. Bad username.'
    '0xC000006A'='Wrong password (NTLM / interactive).'
    '0xC000006D'='Generic logon failure (bad username or password).'
    '0xC000006F'='Account logon outside authorized hours.'
    '0xC0000070'='Account logon from unauthorized workstation.'
    '0xC0000071'='Password expired. Apps/services retrying with stale creds WILL loop and lock the account.'
    '0xC0000072'='Account disabled by administrator.'
    '0xC0000133'='Clocks out of sync (>5 min). Kerberos will fail; may cause lockout loops via NTLM fallback.'
    '0xC000015B'='User not granted requested logon type (logon right missing).'
    '0xC0000193'='Account expired.'
    '0xC0000224'='Password change required at next logon.'
    '0xC0000234'='Account locked out.'
    '0xC0000371'='No credential material for the specified account.'
    '0xC0000413'='Authentication firewall policy prevents this logon.'
    '0x0'       ='No error / Success.'
    '0x12'      ='Credentials revoked (Kerberos: account disabled, expired, or locked).'
    '0x17'      ='Password expired (Kerberos pre-auth).'
    '0x18'      ='Wrong password (Kerberos pre-auth). PRIMARY lockout cause - bad credential source.'
    '0x25'      ='Clock skew too great (>5 min). Fix time sync to resolve Kerberos failures.'
}

# 4776 NTLM error codes (ErrorCode field on DCs)
$NtlmErrorTable = @{
    '0x0'        ='Success.'
    '0xC0000064' ='User not found.'
    '0xC000006A' ='Wrong password.'
    '0xC000006D' ='Generic failure (bad user or password).'
    '0xC000006F' ='Outside logon hours.'
    '0xC0000070' ='Workstation restriction.'
    '0xC0000071' ='Password expired - primary cause of repeated lockouts from stale app or service creds.'
    '0xC0000072' ='Account disabled.'
    '0xC0000193' ='Account expired.'
    '0xC0000224' ='Must change password at next logon.'
    '0xC0000234' ='Account locked out.'
}

# 4771 Kerberos pre-authentication failure codes (FailureCode field)
$KerberosFailureTable = @{
    '0x1' ='Client not found in Kerberos database.'
    '0x2' ='Server not found in Kerberos database.'
    '0x6' ='Client not found in database (username typo or missing account).'
    '0x12'='Account disabled, expired, or locked. Check account status immediately.'
    '0x17'='Password expired - service or app retrying with old credentials will lock the account.'
    '0x18'='Pre-authentication failed (wrong password). Primary lockout cause - find the credential source.'
    '0x19'='Pre-authentication integrity check failed.'
    '0x20'='Ticket expired (clock skew or very long operation).'
    '0x25'='Clock skew too great (>5 min). Fix time sync to resolve Kerberos failures.'
    '0x3F'='Generic error - check other events for detail.'
}

$FailureReasons = @{
    '%%2305'='The specified user account has expired.'
    '%%2307'='Account locked out.'
    '%%2309'='Password expired.'
    '%%2310'='Account disabled.'
    '%%2311'='Logon time restriction violation.'
    '%%2312'='User not allowed to logon at this computer.'
    '%%2313'='Unknown user name or bad password.'
    '%%2304'='Error occurred during Logon.'
}

$PreAuthTypes = @{
    '0'  ='0 = Logon without Pre-Authentication.'
    '2'  ='2 = PA-ENC-TIMESTAMP - Normal type for standard password authentication.'
    '11' ='11 = PA-ETYPE-INFO - Requirement for additional pre-authentication.'
    '15' ='15 = PA-PK-AS-REP_OLD - Used for Smart Card logon authentication.'
    '16' ='16 = PA-PK-AS-REQ - Request sent to KDC in Smart Card authentication scenarios.'
    '17' ='17 = PA-PK-AS-REP - Smart Card authentication.'
    '19' ='19 = PA-ETYPE-INFO2 - Sent by the KDC in a KRB-ERROR.'
    '20' ='20 = PA-SVR-REFERRAL-INFO - Used in KDC Referrals tickets.'
    '138'='138 = PA-ENCRYPTED-CHALLENGE - Logon using Kerberos Armoring (FAST).'
}

# ==============================================================================
#  GUI
# ==============================================================================
$Form                 = New-Object System.Windows.Forms.Form
$Form.Text            = 'Lockout Source Analyzer v150'
$Form.Size            = New-Object System.Drawing.Size(440,230)
$Form.StartPosition   = 'CenterScreen'
$Form.FormBorderStyle = 'FixedDialog'
$Form.MaximizeBox     = $false

$LabelUser          = New-Object System.Windows.Forms.Label
$LabelUser.Text     = 'Username:'
$LabelUser.Location = New-Object System.Drawing.Point(20,20)
$LabelUser.Size     = New-Object System.Drawing.Size(130,20)

$TextBox          = New-Object System.Windows.Forms.TextBox
$TextBox.Location = New-Object System.Drawing.Point(160,17)
$TextBox.Size     = New-Object System.Drawing.Size(250,20)

$LabelStart              = New-Object System.Windows.Forms.Label
$LabelStart.Text         = 'Start Date / Time:'
$LabelStart.Location     = New-Object System.Drawing.Point(20,57)
$LabelStart.Size         = New-Object System.Drawing.Size(130,20)

$DatePickerStart              = New-Object System.Windows.Forms.DateTimePicker
$DatePickerStart.Format       = [System.Windows.Forms.DateTimePickerFormat]::Custom
$DatePickerStart.CustomFormat = 'MM/dd/yyyy hh:mm:ss tt'
$DatePickerStart.ShowUpDown   = $true
$DatePickerStart.Location     = New-Object System.Drawing.Point(160,54)
$DatePickerStart.Size         = New-Object System.Drawing.Size(250,22)
$DatePickerStart.Value        = (Get-Date).AddHours(-$HoursBack)

$LabelEnd              = New-Object System.Windows.Forms.Label
$LabelEnd.Text         = 'End Date / Time:'
$LabelEnd.Location     = New-Object System.Drawing.Point(20,95)
$LabelEnd.Size         = New-Object System.Drawing.Size(130,20)

$DatePickerEnd              = New-Object System.Windows.Forms.DateTimePicker
$DatePickerEnd.Format       = [System.Windows.Forms.DateTimePickerFormat]::Custom
$DatePickerEnd.CustomFormat = 'MM/dd/yyyy hh:mm:ss tt'
$DatePickerEnd.ShowUpDown   = $true
$DatePickerEnd.Location     = New-Object System.Drawing.Point(160,92)
$DatePickerEnd.Size         = New-Object System.Drawing.Size(250,22)
$DatePickerEnd.Value        = (Get-Date).AddHours($HoursForward)

$OKButton              = New-Object System.Windows.Forms.Button
$OKButton.Text         = 'OK'
$OKButton.Location     = New-Object System.Drawing.Point(170,135)
$OKButton.Size         = New-Object System.Drawing.Size(80,28)
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$Form.AcceptButton     = $OKButton
$Form.Controls.AddRange(@($LabelUser,$TextBox,$LabelStart,$DatePickerStart,$LabelEnd,$DatePickerEnd,$OKButton))

if ($Form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($TextBox.Text)) {
    Write-Warning 'Cancelled or no username entered. Exiting.'
    exit
}

$UserName  = $TextBox.Text.Trim()
$StartDate = $DatePickerStart.Value
$EndDate   = $DatePickerEnd.Value
$DateStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not (Test-Path $TempPath)) { New-Item -ItemType Directory -Path $TempPath | Out-Null }
#Export a CSV
#$UnifiedOutputPath = Join-Path $TempPath "LockoutAnalysis_${UserName}_${DateStamp}.csv"
$DeviceOutputPath  = Join-Path $TempPath "LockoutReport_${UserName}_${DateStamp}.html"

$ScriptStart = Get-Date
Write-Host "Script Started:  $($ScriptStart.ToString('MM/dd/yyyy hh:mm:ss tt'))"
Write-Host "Username:        $UserName"
Write-Host "Start:           $($StartDate.ToString('MM/dd/yyyy hh:mm:ss tt'))"
Write-Host "End:             $($EndDate.ToString('MM/dd/yyyy hh:mm:ss tt'))"
#Write-Host "Unified CSV:     $UnifiedOutputPath"
Write-Host "Device Report:   $DeviceOutputPath"

# ==============================================================================
#  AD Query
# ==============================================================================
try {
    $ADDomain          = Get-ADDomain
    $DNSZone           = $ADDomain.DNSRoot
    $DomainDNSServer   = $ADDomain.PDCEmulator   # Used for PTR lookups
    $DomainControllers = (Get-ADDomainController -Filter *).HostName
    $AllServers        = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Windows Server*' } |
                             Select-Object -ExpandProperty Name
    Write-Host "DNS Zone:         $DNSZone"
    Write-Host "PTR DNS Server:   $DomainDNSServer"
    Write-Host "DCs:              $($DomainControllers -join ', ')"
    Write-Host "Server count:     $($AllServers.Count)"
} catch {
    Write-Warning "AD query failed: $($_.Exception.Message)"
    exit
}

# ==============================================================================
#  Helper: Normalize-HexStatus
# ==============================================================================
function Normalize-HexStatus {
    param([string]$h)
    if (-not $h -or $h -in @('','-')) { return $h }
    $h = $h.Trim()
    if ($h -match '^0[xX]([0-9a-fA-F]+)$') { return ('0x' + $Matches[1].ToUpper()) }
    if ($h -match '^[0-9a-fA-F]{4,}$')     { return ('0x' + $h.ToUpper()) }
    return $h
}

# ==============================================================================
#  Helper: New-UnifiedRow  (hashtable-based, all fields defaulted to '')
# ==============================================================================
function New-UnifiedRow {
    param([hashtable]$F)
    $d = [ordered]@{
        # == Core ==============================================================
        Source='';Timestamp=$null;EventId='';EventDescription='';SourceServer=''
        # == User ==============================================================
        UserName='';FQDN='';SubjectUser=''
        # == Location ==========================================================
        WorkstationName='';CallerComputer='';IpAddress=''
        # == Authentication ====================================================
        LogonType='';LogonTypeName='';AuthMethod='';PacketType=''
        # == Status / Result ===================================================
        Result='';Status='';StatusDesc='';SubStatus='';SubStatusDesc=''
        FailureReasonDesc=''
        # == Process ===========================================================
        ProcessName='';LogonProcessName=''
        # == Logon Session IDs =================================================
        SubjectLogonId='';TargetLogonId=''
        # == Kerberos ==========================================================
        TargetDomainName='';ServiceName='';TicketOptions='';TicketEncryptType=''
        PreAuthType='';PreAuthDescription='';TransmittedServices=''
        # == NPS Policy ========================================================
        PolicyName='';ProxyPolicyName='';ServiceType='';ProviderType='';ProviderName=''
        # == NPS NAS ===========================================================
        NASIdentifier='';NASIPAddress='';NASPort='';NASPortType=''
        # == NPS Client ========================================================
        ClientFriendlyName='';ClientVendor='';RemoteServerAddress=''
        # == NPS Station IDs ===================================================
        CalledStationID='';CallingStationID='';CallbackNumber=''
        # == NPS Framing =======================================================
        FramedIPAddress='';FramedProtocol='';ConnectInfo='';PortLimit=''
        # == NPS MS Extensions =================================================
        MSRASClientName='';MSRASClientVersion='';MSRASVersion='';MSRASVendor=''
        MSCHAPError='';MSCHAPDomain='';MSMPPEEncryptTypes='';MSMPPEEncryptPolicy=''
        MSAcctAuthType='';MSAcctEAPType='';EAPFriendlyName=''
        # == NPS Session Control ===============================================
        SessionTimeout='';IdleTimeout='';TerminationAction='';EventTimestamp=''
        # == NPS Accounting ====================================================
        AcctStatusType='';AcctSessionId='';AcctSessionTime='';AcctDelay=''
        AcctInputOctets='';AcctOutputOctets='';AcctInputPackets='';AcctOutputPackets=''
        AcctTerminateCause='';AcctLinkCount='';AcctInterimInterval='';MSMultiSsnID=''
        # == NPS Tunnel ========================================================
        TunnelType='';TunnelMediumType='';TunnelClientEndpt='';TunnelServerEndpt=''
        TunnelPvtGroupID='';TunnelAssignmentID='';TunnelPreference='';AcctTunnelConn=''
    }
    foreach ($k in $F.Keys) { $d[$k] = $F[$k] }
    [PSCustomObject]$d
}

# ==============================================================================
#  Phase 1: DC Scan
# ==============================================================================
Write-Host "`n[Phase 1] Scanning Domain Controllers..."
$DCJobs = @()
foreach ($DC in $DomainControllers) {
    Write-Host "  Queuing: $DC"
    try {
        $Job = Invoke-Command -ComputerName $DC -AsJob -JobName "DC_$DC" -ErrorAction Stop -ScriptBlock {
            $LocalUser  = $Using:UserName
            $LocalZone  = $Using:DNSZone
            $LocalGrp1  = $Using:EventIdsGroup1
            $LocalGrp2  = $Using:EventIdsGroup2
            $LocalStart = $Using:StartDate
            $LocalEnd   = $Using:EndDate

            if ($LocalGrp1.Count -eq 0 -or $LocalGrp2.Count -eq 0) {
                Write-Warning "$env:COMPUTERNAME: EventId arrays did not deserialize."; return @()
            }

            $s   = $LocalStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
            $e   = $LocalEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
            $id1 = ($LocalGrp1 | ForEach-Object { "EventID=$([int]$_)" }) -join ' or '
            $id2 = ($LocalGrp2 | ForEach-Object { "EventID=$([int]$_)" }) -join ' or '

            $uf = ''
            if ($LocalUser) {
                $uf = " and (EventData[Data[@Name='TargetUserName']='$LocalUser'] or " +
                      "EventData[Data[@Name='TargetUserName']='${LocalUser}@${LocalZone}'])"
            }

            $xp1 = "*[System[($id1) and TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]$uf]"
            $xp2 = "*[System[($id2) and TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]$uf]"

            $doc = New-Object System.Xml.XmlDocument
            $doc.LoadXml(
                "<QueryList><Query Id='0' Path='Security'>" +
                "<Select Path='Security'>P1</Select>" +
                "<Select Path='Security'>P2</Select>" +
                "</Query></QueryList>"
            )
            $sel = $doc.SelectNodes('//Select')
            $sel[0].InnerText = $xp1
            $sel[1].InnerText = $xp2

            try {
                $Events = Get-WinEvent -FilterXml $doc -ErrorAction Stop
                Write-Host "Got $($Events.Count) events from $env:COMPUTERNAME"
            } catch {
                if ($_.Exception.Message -like '*No events*') { Write-Host "No events on $env:COMPUTERNAME"; return @() }
                Write-Warning "$env:COMPUTERNAME: $($_.Exception.Message)"; return @()
            }

            foreach ($Ev in $Events) {
                try {
                    $x = [xml]$Ev.ToXml(); $d = @{}
                    foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
                    [PSCustomObject]@{
                        TimeCreated         = $Ev.TimeCreated
                        EventId             = $Ev.Id
                        SourceDC            = $env:COMPUTERNAME
                        TargetUserName      = $d['TargetUserName']
                        SubjectUserName     = $d['SubjectUserName']
                        WorkstationName     = $d['WorkstationName']
                        CallerComputer      = $d['CallerComputerName']
                        IpAddress           = $d['IpAddress']
                        IpPort              = $d['IpPort']
                        LogonType           = $d['LogonType']
                        AuthPackage         = $d['AuthenticationPackageName']
                        LogonProcessName    = $d['LogonProcessName']
                        FailureReason       = $d['FailureReason']
                        Status              = $d['Status']
                        SubStatus           = $d['SubStatus']
                        ProcessName         = $d['ProcessName']
                        TargetDomainName    = $d['TargetDomainName']
                        ServiceName         = $d['ServiceName']
                        SubjectLogonId      = $d['SubjectLogonId']
                        TargetLogonId       = $d['TargetLogonId']
                        TransmittedServices = $d['TransmittedServices']
                        TicketOptions       = $d['TicketOptions']
                        TicketEncryptType   = $d['TicketEncryptionType']
                        PreAuthType         = $d['PreAuthType']
                    }
                } catch {}
            }
        }
        $DCJobs += [PSCustomObject]@{ DCName=$DC; Job=$Job }
    } catch { Write-Warning "  Could not queue $DC : $($_.Exception.Message)" }
}

Write-Host '  Waiting for DC jobs...'
$AllDCEvents = [System.Collections.Generic.List[object]]::new()
foreach ($Entry in $DCJobs) {
    try {
        $R = $Entry.Job | Wait-Job -Timeout 300 | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
    } catch { Write-Warning "  Failed collecting from $($Entry.DCName)"; continue }
    $R | Where-Object { $_ -is [string] } | ForEach-Object { Write-Host "  [DC] $_" }
    foreach ($O in @($R | Where-Object { $_ -isnot [string] -and $_ -ne $null })) { $AllDCEvents.Add($O) }
}
Write-Host "  DC scan complete: $($AllDCEvents.Count) events."

# ==============================================================================
#  Phase 2: Build Target Computer List (PTR first, DNS Server A-record fallback)
# ==============================================================================
Write-Host "`n[Phase 2] Building target computer list..."

$DCShortNames    = @($DomainControllers | ForEach-Object { $_.Split('.')[0].ToUpper() })

#$TargetComputers = [System.Collections.Generic.List[string]]::new()
$TargetComputers = [System.Collections.Generic.List[string]]::new()

$SkipIPs         = [System.Collections.Generic.HashSet[string]]@('127.0.0.1','0.0.0.0','::1','-','')
$SeenIPs         = [System.Collections.Generic.HashSet[string]]::new()

# Fallback cache (only built if needed)
$IPtoHostname     = @{}
$ARecordCacheBuilt = $false

function Resolve-IpToShortName {
    param(
        [Parameter(Mandatory)] [string] $Ip,
        [Parameter(Mandatory)] [string] $DnsServer,
        [Parameter(Mandatory)] [string] $ZoneName
    )

    # 1) Regular DNS PTR lookup first
    try {
        # Note: some environments require the DNS server to be specified (you already have $DomainDNSServer)
        $ptr = Resolve-DnsName -Name $Ip -Type PTR -Server $DnsServer -ErrorAction Stop |
               Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1

        if ($ptr -and $ptr.NameHost) {
            return ($ptr.NameHost.TrimEnd('.').Split('.')[0].ToUpper())
        }
    } catch {
        # ignore and fall back
    }

    # 2) Fallback: build A-record cache once via Get-DnsServerResourceRecord (only if needed)
    if (-not $script:ARecordCacheBuilt) {
        Write-Host "  PTR lookup failed for at least one IP; fetching A records from $DnsServer zone: $ZoneName ..."
        try {
            $ARecords = Invoke-Command -ComputerName $DnsServer -ErrorAction Stop -ScriptBlock {
                Get-DnsServerResourceRecord -ZoneName $Using:ZoneName -RRType A -ErrorAction Stop
            }

            foreach ($rec in $ARecords) {
                $ipAddr = $rec.RecordData.IPv4Address.ToString()
                if ($ipAddr -and -not $script:IPtoHostname.ContainsKey($ipAddr)) {
                    $script:IPtoHostname[$ipAddr] = $rec.HostName
                }
            }

            $script:ARecordCacheBuilt = $true
            Write-Host "  A record cache built: $($script:IPtoHostname.Count) entries."
        } catch {
            $script:ARecordCacheBuilt = $true  # prevent repeated attempts
            Write-Warning "  Could not fetch A records from $DnsServer : $($_.Exception.Message)"
        }
    }

    if ($script:IPtoHostname.ContainsKey($Ip)) {
        return ($script:IPtoHostname[$Ip].ToUpper())
    }

    return $null
}

foreach ($Ev in $AllDCEvents) {

    # CallerComputer from 4740
    if ($Ev.EventId -eq 4740 -and $Ev.CallerComputer) {
        $c = $Ev.CallerComputer.TrimEnd('$').ToUpper().Trim()
        if ($c -and $c -ne '-' -and $c -notin $DCShortNames -and -not $TargetComputers.Contains($c)) {
            Write-Host "  + (4740 CallerComputer) $c"
            $TargetComputers.Add($c)
        }
    }

    # WorkstationName from 4625 / 4771 / 4776
    if ($Ev.EventId -in @(4625,4771,4776) -and $Ev.WorkstationName) {
        $c = $Ev.WorkstationName.TrimEnd('$').ToUpper().Trim()
        if ($c -and $c -ne '-' -and $c -notin $DCShortNames -and -not $TargetComputers.Contains($c)) {
            Write-Host "  + (WorkstationName) $c"
            $TargetComputers.Add($c)
        }
    }

    # IpAddress -> PTR first, fallback to A-record zone cache only if PTR fails
    $ip          = $Ev.IpAddress
    $isValidIPv4 = ($ip -match '^\d{1,3}(\.\d{1,3}){3}$')

    if ($ip -and
        $isValidIPv4 -and
        -not $SkipIPs.Contains($ip) -and
        $ip -notmatch '^::' -and
        $ip -notmatch '^fe80' -and
        $ip -notmatch '^169\.254' -and
        -not $SeenIPs.Contains($ip)) {

        $null = $SeenIPs.Add($ip)

        $resolved = Resolve-IpToShortName -Ip $ip -DnsServer $DomainDNSServer -ZoneName $DNSZone

        if ($resolved) {
            if ($resolved -notin $DCShortNames -and -not $TargetComputers.Contains($resolved)) {
                Write-Host "  + (DNS: $ip -> $resolved)"
                $TargetComputers.Add($resolved)
            }
        } else {
            Write-Warning "  IP $ip could not be resolved (PTR/A). Using raw IP."
            if (-not $TargetComputers.Contains($ip)) {
                $TargetComputers.Add($ip)
            }
        }
    }
}

if ($TargetComputers.Count -gt 0) {
    Write-Host "  Target computers ($($TargetComputers.Count)): $($TargetComputers -join ', ')"
} else {
    Write-Host "  No target computers found for analysis."
}

# ==============================================================================
#  Phase 3: NPS Service Discovery
# ==============================================================================
Write-Host "`n[Phase 3] Checking $($AllServers.Count) servers for NPS (IAS) service..."
$SvcJobs = @()
foreach ($Server in $AllServers) {
    try {
        $Job = Invoke-Command -ComputerName $Server -AsJob -JobName "NPSSVC_$Server" -ErrorAction Stop -ScriptBlock {
            $svc = Get-Service -Name 'IAS' -ErrorAction SilentlyContinue
            [PSCustomObject]@{ ComputerName=$env:COMPUTERNAME; IsNPS=($svc -and $svc.Status -eq 'Running') }
        }
        $SvcJobs += [PSCustomObject]@{ ServerName=$Server; Job=$Job }
    } catch {}
}

$ConfirmedNPSServers = @()
foreach ($Entry in $SvcJobs) {
    try {
        $R = $Entry.Job | Wait-Job -Timeout 30 | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
        if ($R.IsNPS) { Write-Host "  NPS found: $($R.ComputerName)"; $ConfirmedNPSServers += $R.ComputerName }
    } catch {}
}


# ==============================================================================
# Safety init: Phase 3 (NPS service discovery via WinRM) is commented out.
# $ConfirmedNPSServers will be empty; Phase 4 will skip gracefully.
if (-not (Get-Variable -Name ConfirmedNPSServers -ErrorAction SilentlyContinue)) {
    $ConfirmedNPSServers = @()
}
#  Phase 4: NPS Log Parse
# ==============================================================================
$AllNPSRaw = [System.Collections.Generic.List[object]]::new()

if ($ConfirmedNPSServers.Count -eq 0) {
    Write-Warning 'No NPS servers found or running. Skipping NPS parse.'
} else {
    Write-Host "`n[Phase 4] Parsing NPS logs on $($ConfirmedNPSServers.Count) server(s)..."
    $NPSJobs = @()

    foreach ($Server in $ConfirmedNPSServers) {
        try {
            $Job = Invoke-Command -ComputerName $Server -AsJob -JobName "NPSLOG_$Server" -ErrorAction Stop -ScriptBlock {

                $LocalUser    = $Using:UserName
                $LocalStart   = $Using:StartDate
                $LocalEnd     = $Using:EndDate
                $LocalHeaders = $Using:CsvHeaders

                # Locate log directory from ias.xml
                $iasXmlPath = 'C:\Windows\System32\ias\ias.xml'
                if (-not (Test-Path $iasXmlPath)) {
                    Write-Warning "$env:COMPUTERNAME: ias.xml not found"
                    return @()
                }

                $logPath = $null
                try {
                    [xml]$iasConfig = Get-Content $iasXmlPath -Raw
                    $logDirNode = $iasConfig.SelectSingleNode('//Log_File_Directory//DefaultValue')
                    if (-not $logDirNode) {
                        foreach ($n in $iasConfig.SelectNodes('//*[local-name()="DefaultValue"]')) {
                            if ($n.ParentNode.Name -like '*Log*') {
                                $logDirNode = $n
                                break
                            }
                        }
                    }
                    if ($logDirNode) {
                        $logPath = [System.Environment]::ExpandEnvironmentVariables(
                            ($logDirNode.InnerText -replace '%windir%', 'C:\Windows\System32'))
                    }
                } catch {
                    Write-Warning "$env:COMPUTERNAME: ias.xml parse error - $($_.Exception.Message)"
                    return @()
                }

                if (-not $logPath -or -not (Test-Path $logPath)) {
                    Write-Warning "$env:COMPUTERNAME: Log path not found: $logPath"
                    return @()
                }

                $LogFiles = Get-ChildItem -Path $logPath -Filter '*.log' -ErrorAction SilentlyContinue
                Write-Output "$env:COMPUTERNAME: $($LogFiles.Count) log file(s) in $logPath"
                $Results = @()

                foreach ($file in $LogFiles) {

                    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
                    if (-not $content) { continue }

                    foreach ($line in $content) {

                        $t = $line.Trim()
                        if (-not $t) { continue }

                        $parsed = $null

                        # IAS CSV format
                        if ($t.StartsWith('"')) {
                            try {
                                $row  = ($t | ConvertFrom-Csv -Header $LocalHeaders)[0]
                                $user = $row.'User-Name'

                                $matchesUser = (-not $LocalUser) -or
                                              ($user -like "*$LocalUser*") -or
                                              ($row.'Fully-Qualified-Distinguished-Name' -like "*$LocalUser*")

                                if ($matchesUser) {
                                    $ts = $null
                                    try {
                                        $ts = [datetime]::ParseExact(
                                            "$($row.'Record-Date') $($row.'Record-Time')",
                                            'MM/dd/yyyy HH:mm:ss', $null)
                                    } catch {
                                        $ts = $null
                                    }

                                    $inRange = (-not $ts) -or ($ts -ge $LocalStart -and $ts -le $LocalEnd)

                                    if ($inRange) {
                                        $clientIpOverride = ''
                                        if ($row.Class -and ($row.Class -split ' ').Count -ge 3) {
                                            $maybe = ($row.Class -split ' ')[2]
                                            if ($maybe -match '^\d{1,3}(\.\d{1,3}){3}$') {
                                                $clientIpOverride = $maybe
                                            }
                                        }

                                        $obj = [ordered]@{
                                            SourceServer     = $env:COMPUTERNAME
                                            Timestamp        = $ts
                                            ClientIPOverride = $clientIpOverride
                                        }
                                        foreach ($h in $LocalHeaders) {
                                            $obj[$h] = $row.$h
                                        }
                                        $parsed = [PSCustomObject]$obj
                                    }
                                }
                            } catch {
                                $parsed = $null
                            }

                        # IAS XML format
                        } elseif ($t.StartsWith('<')) {
                            try {
                                [xml]$xmlObj = $t
                                $en = $xmlObj.SelectSingleNode('//Event')

                                if ($en) {
                                    $user = ''
                                    if ($en.'User-Name') { $user = $en.'User-Name'.InnerText }

                                    $matchesUser = (-not $LocalUser) -or ($user -like "*$LocalUser*")

                                    if ($matchesUser) {
                                        $tsXml = $null
                                        if ($en.Timestamp) {
                                            try {
                                                $tsXml = [datetime]::ParseExact(
                                                    $en.Timestamp.InnerText,
                                                    'MM/dd/yyyy HH:mm:ss.fff', $null)
                                            } catch {
                                                $tsXml = $null
                                            }
                                        }

                                        $inRange = (-not $tsXml) -or ($tsXml -ge $LocalStart -and $tsXml -le $LocalEnd)

                                        if ($inRange) {
                                            $obj = [ordered]@{
                                                SourceServer     = $env:COMPUTERNAME
                                                Timestamp        = $tsXml
                                                ClientIPOverride = ''
                                            }
                                            foreach ($h in $LocalHeaders) {
                                                $node = $en.SelectSingleNode("*[local-name()='$h']")
                                                if ($node) {
                                                    $obj[$h] = $node.InnerText
                                                } else {
                                                    $obj[$h] = ''
                                                }
                                            }
                                            $parsed = [PSCustomObject]$obj
                                        }
                                    }
                                }
                            } catch {
                                $parsed = $null
                            }
                        }

                        if ($parsed) { $Results += $parsed }

                    } # end foreach line
                } # end foreach file

                Write-Output "$env:COMPUTERNAME: $($Results.Count) matching NPS entries"
                return $Results

            } # end scriptblock
            $NPSJobs += [PSCustomObject]@{ ServerName = $Server; Job = $Job }

        } catch {
            Write-Warning "  Could not queue NPS job for $Server : $($_.Exception.Message)"
        }
    } # end foreach Server

    foreach ($Entry in $NPSJobs) {
        try {
            $R = $Entry.Job | Wait-Job -Timeout 300 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "  Failed NPS job $($Entry.ServerName)"
            continue
        }
        $R | Where-Object { $_ -is [string] } | ForEach-Object { Write-Host "  [NPS] $_" }
        foreach ($O in @($R | Where-Object { $_ -isnot [string] -and $_ -ne $null })) {
            $AllNPSRaw.Add($O)
        }
    }
}

Write-Host "  NPS parse complete: $($AllNPSRaw.Count) raw entries."

# ==============================================================================
#  Phase 5: Merge DC Events + NPS Entries Unified CSV (all translations here)
# ==============================================================================
Write-Host "`n[Phase 5] Building unified dataset..."
$UnifiedRows = [System.Collections.Generic.List[object]]::new()

# == DC Events â†’ Unified =====================================================
foreach ($Ev in $AllDCEvents) {
    $eid = [int]$Ev.EventId
    $lt  = "$($Ev.LogonType)"
    $st  = Normalize-HexStatus "$($Ev.Status)"
    $sst = Normalize-HexStatus "$($Ev.SubStatus)"
    $fr  = "$($Ev.FailureReason)"
    $pat = "$($Ev.PreAuthType)"

    $UnifiedRows.Add((New-UnifiedRow @{
        Source             = 'SecurityEvent'
        Timestamp          = $Ev.TimeCreated
        EventId            = $eid
        EventDescription   = if ($EventDescriptions[$eid])        { $EventDescriptions[$eid] }        else { '' }
        SourceServer       = $Ev.SourceDC
        UserName           = $Ev.TargetUserName
        SubjectUser        = $Ev.SubjectUserName
        WorkstationName    = $Ev.WorkstationName
        CallerComputer     = $Ev.CallerComputer
        IpAddress          = $Ev.IpAddress
        LogonType          = $lt
        LogonTypeName      = if ($LogonTypes[$lt])                 { $LogonTypes[$lt] }                else { '' }
        AuthMethod         = $Ev.AuthPackage
        Result             = $fr
        FailureReasonDesc  = if ($FailureReasons[$fr])             { $FailureReasons[$fr] }            else { $fr }
        Status             = $st
        StatusDesc         = if ($StatusDescriptions[$st])         { $StatusDescriptions[$st] }        else { '' }
        SubStatus          = $sst
        SubStatusDesc      = if ($StatusDescriptions[$sst])        { $StatusDescriptions[$sst] }       else { '' }
        ProcessName        = $Ev.ProcessName
        LogonProcessName   = $Ev.LogonProcessName
        SubjectLogonId     = $Ev.SubjectLogonId
        TargetLogonId      = $Ev.TargetLogonId
        TargetDomainName   = $Ev.TargetDomainName
        ServiceName        = $Ev.ServiceName
        TicketOptions      = $Ev.TicketOptions
        TicketEncryptType  = $Ev.TicketEncryptType
        PreAuthType        = $pat
        PreAuthDescription = if ($PreAuthTypes[$pat])              { $PreAuthTypes[$pat] }             else { '' }
        TransmittedServices= $Ev.TransmittedServices
    }))
}

# == NPS Entries Unified ===================================================
foreach ($NPS in $AllNPSRaw) {
    $pt  = "$($NPS.'Packet-Type')"
    $rc  = "$($NPS.'Reason-Code')"
    $at  = "$($NPS.'Authentication-Type')"
    $pvt = "$($NPS.'Provider-Type')"
    $cv  = "$($NPS.'Client-Vendor')"
    $npt = "$($NPS.'NAS-Port-Type')"
    $st  = "$($NPS.'Service-Type')"

    # Best-effort IP: Class-embedded override > Client-IP-Address > Framed-IP-Address
    $clientIp = $NPS.ClientIPOverride
    if (-not $clientIp) { $clientIp = $NPS.'Client-IP-Address' }
    if (-not $clientIp) { $clientIp = $NPS.'Framed-IP-Address' }

    $UnifiedRows.Add((New-UnifiedRow @{
        Source              = 'NPSLog'
        Timestamp           = $NPS.Timestamp
        SourceServer        = $NPS.SourceServer
        UserName            = $NPS.'User-Name'
        FQDN                = $NPS.'Fully-Qualified-Distinguished-Name'
        IpAddress           = $clientIp
        PacketType          = if ($PacketTypeTable[$pt])           { $PacketTypeTable[$pt] }           else { $pt }
        Result              = if ($ReasonCodeTable[$rc])           { $ReasonCodeTable[$rc] }           else { $rc }
        AuthMethod          = if ($NpsAuthTypeTable[$at])          { $NpsAuthTypeTable[$at] }          else { $at }
        ProviderType        = if ($NpsProviderTypeTable[$pvt])     { $NpsProviderTypeTable[$pvt] }     else { $pvt }
        ClientVendor        = if ($NpsClientVendorTable[$cv])      { $NpsClientVendorTable[$cv] }      else { $cv }
        NASPortType         = if ($NasPortTypeTable[$npt])         { $NasPortTypeTable[$npt] }         else { $npt }
        ServiceType         = if ($NpsServiceTypeTable[$st])       { $NpsServiceTypeTable[$st] }       else { $st }
        PolicyName          = $NPS.'Policy-Name'
        ProxyPolicyName     = $NPS.'Proxy-Policy-Name'
        ProviderName        = $NPS.'Provider-Name'
        NASIdentifier       = $NPS.'NAS-Identifier'
        NASIPAddress        = $NPS.'NAS-IP-Address'
        NASPort             = $NPS.'NAS-Port'
        ClientFriendlyName  = $NPS.'Client-Friendly-Name'
        RemoteServerAddress = $NPS.'Remote-Server-Address'
        CalledStationID     = $NPS.'Called-Station-ID'
        CallingStationID    = $NPS.'Calling-Station-ID'
        CallbackNumber      = $NPS.'Callback-Number'
        FramedIPAddress     = $NPS.'Framed-IP-Address'
        FramedProtocol      = $NPS.'Framed-Protocol'
        ConnectInfo         = $NPS.'Connect-Info'
        PortLimit           = $NPS.'Port-Limit'
        MSRASClientName     = $NPS.'MS-RAS-Client-Name'
        MSRASClientVersion  = $NPS.'MS-RAS-Client-Version'
        MSRASVersion        = $NPS.'MS-RAS-Version'
        MSRASVendor         = $NPS.'MS-RAS-Vendor'
        MSCHAPError         = $NPS.'MS-CHAP-Error'
        MSCHAPDomain        = $NPS.'MS-CHAP-Domain'
        MSMPPEEncryptTypes  = $NPS.'MS-MPPE-Encryption-Types'
        MSMPPEEncryptPolicy = $NPS.'MS-MPPE-Encryption-Policy'
        MSAcctAuthType      = $NPS.'MS-Acct-Auth-Type'
        MSAcctEAPType       = $NPS.'MS-Acct-EAP-Type'
        EAPFriendlyName     = $NPS.'EAP-Friendly-Name'
        SessionTimeout      = $NPS.'Session-Timeout'
        IdleTimeout         = $NPS.'Idle-Timeout'
        TerminationAction   = $NPS.'Termination-Action'
        EventTimestamp      = $NPS.'Event-Timestamp'
        AcctStatusType      = $NPS.'Acct-Status-Type'
        AcctSessionId       = $NPS.'Acct-Session-Id'
        AcctSessionTime     = $NPS.'Acct-Session-Time'
        AcctDelay           = $NPS.'Acct-Delay-Time'
        AcctInputOctets     = $NPS.'Acct-Input-Octets'
        AcctOutputOctets    = $NPS.'Acct-Output-Octets'
        AcctInputPackets    = $NPS.'Acct-Input-Packets'
        AcctOutputPackets   = $NPS.'Acct-Output-Packets'
        AcctTerminateCause  = $NPS.'Acct-Terminate-Cause'
        AcctLinkCount       = $NPS.'Acct-Link-Count'
        AcctInterimInterval = $NPS.'Acct-Interim-Interval'
        MSMultiSsnID        = $NPS.'Acct-Multi-Ssn-ID'
        TunnelType          = $NPS.'Tunnel-Type'
        TunnelMediumType    = $NPS.'Tunnel-Medium-Type'
        TunnelClientEndpt   = $NPS.'Tunnel-Client-Endpt'
        TunnelServerEndpt   = $NPS.'Tunnel-Server-Endpt'
        TunnelPvtGroupID    = $NPS.'Tunnel-Pvt-Group-ID'
        TunnelAssignmentID  = $NPS.'Tunnel-Assignment-ID'
        TunnelPreference    = $NPS.'Tunnel-Preference'
        AcctTunnelConn      = $NPS.'Acct-Tunnel-Conn'
    }))
}

<# Export a CSV
$UnifiedRows | Sort-Object Timestamp -Descending |
    Export-Csv -Path $UnifiedOutputPath -NoTypeInformation -Force

Write-Host "  Unified CSV: $($UnifiedRows.Count) rows ($($AllDCEvents.Count) DC + $($AllNPSRaw.Count) NPS) -> $UnifiedOutputPath"
#>

# ==============================================================================
#  Phase 6: Device Analysis
# ==============================================================================

Write-Host ("`n[Phase 6] Device analysis on {0} target(s)..." -f $TargetComputers.Count)

# --- Optional: path to PsExec (put it on the DC running the script) ---
# Recommended: store in same folder as script
$PsExecPath = Join-Path $PSScriptRoot 'PsExec.exe'
$UsePsExec  = (Test-Path $PsExecPath)
Import-Module ActiveDirectory -ErrorAction Stop

function Invoke-RemoteCmdWmi {
    param(
        [Parameter(Mandatory=$true)] [string] $ComputerName,
        [Parameter(Mandatory=$true)] [string] $CommandLine,
        [int] $TimeoutSec = 60
    )

    $guid = [guid]::NewGuid().ToString('N')
    $outRemote = "C:\Windows\Temp\wmi_{0}.txt" -f $guid
    $uncOut    = "\\{0}\admin$\Temp\wmi_{1}.txt" -f $ComputerName, $guid

    $wrapped = "cmd.exe /c $CommandLine 1>`"$outRemote`" 2>&1"
    $r = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $wrapped -ErrorAction Stop
    if ($r.ReturnValue -ne 0) { throw ("WMI Win32_Process.Create failed (ReturnValue={0})" -f $r.ReturnValue) }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (Test-Path $uncOut) { break }
        Start-Sleep -Milliseconds 300
    }
    $sw.Stop()

    if (-not (Test-Path $uncOut)) { throw ("Timed out waiting for output file: {0}" -f $uncOut) }

    $text = (Get-Content -Path $uncOut -ErrorAction Stop) -join [Environment]::NewLine
    Remove-Item -Path $uncOut -Force -ErrorAction SilentlyContinue | Out-Null
    return $text
}

function Invoke-RemotePSWmi {
    param(
        [Parameter(Mandatory=$true)] [string] $ComputerName,
        [Parameter(Mandatory=$true)] [string] $PsCode,
        [int] $TimeoutSec = 90
    )
    $guid      = [guid]::NewGuid().ToString('N')
    $remoteOut = "C:\Windows\Temp\wmi_{0}.txt" -f $guid
    $uncOut    = "\\{0}\admin$\Temp\wmi_{1}.txt" -f $ComputerName, $guid
    $bytes     = [Text.Encoding]::Unicode.GetBytes($PsCode)
    $enc       = [Convert]::ToBase64String($bytes)
    $cmd       = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc 1>`"$remoteOut`" 2>&1"
    try {
        $r = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $cmd -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw ("WMI process create failed (ReturnValue={0})" -f $r.ReturnValue) }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
            if (Test-Path $uncOut) { break }
            Start-Sleep -Milliseconds 350
        }
        $sw.Stop()
        if (-not (Test-Path $uncOut)) { throw ("Timed out waiting for output: {0}" -f $uncOut) }
        return (Get-Content -Path $uncOut -ErrorAction Stop) -join [Environment]::NewLine
    } finally {
        Remove-Item -Path $uncOut -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Get-LoadedUserRunKeysTextWmi {
    param([Parameter(Mandatory=$true)] [string] $ComputerName)

    $sidListRaw = Invoke-RemoteCmdWmi -ComputerName $ComputerName `
        -CommandLine 'reg query "HKU" | findstr /r /c:"HKEY_USERS\\S-1-5-21-"' -TimeoutSec 45

    $sids = $sidListRaw -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^HKEY_USERS\\S-1-5-21-' }

    if (-not $sids -or $sids.Count -eq 0) {
        return "No loaded user hives found under HKU (no interactive users loaded)."
    }

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($sid in $sids) {
        $out.Add("============================================================")
        $out.Add($sid)
        $out.Add("---- Run ----")
        $out.Add((Invoke-RemoteCmdWmi -ComputerName $ComputerName -CommandLine ('reg query "{0}\Software\Microsoft\Windows\CurrentVersion\Run"' -f $sid) -TimeoutSec 30))
        $out.Add("---- RunOnce ----")
        $out.Add((Invoke-RemoteCmdWmi -ComputerName $ComputerName -CommandLine ('reg query "{0}\Software\Microsoft\Windows\CurrentVersion\RunOnce"' -f $sid) -TimeoutSec 30))
    }

    return ($out -join [Environment]::NewLine)
}

function Get-InteractiveSessionsTextWmi {
    param([Parameter(Mandatory=$true)] [string] $ComputerName)

    # query user output example:
    # USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
    # username              console             1  Active      none   4/17/2026 8:01 AM
    return Invoke-RemoteCmdWmi -ComputerName $ComputerName -CommandLine 'query user' -TimeoutSec 30
}

function Get-SessionIdsForUser {
    param(
        [Parameter(Mandatory=$true)] [string] $QueryUserText,
        [Parameter(Mandatory=$true)] [string] $UserName
    )

    $ids = New-Object System.Collections.Generic.List[int]
    $lines = $QueryUserText -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($ln in $lines) {
        # Normalize whitespace and split
        $parts = ($ln -replace '\s{2,}', ' ') -split ' '
        if ($parts.Count -lt 3) { continue }

        $u = $parts[0].Trim()
        # sometimes query user prepends ">" to current session
        $u = $u.TrimStart('>')

        if ($u -ieq $UserName -or $u -ilike "*\$UserName") {
            # ID is usually the 3rd column (index 2) after USERNAME SESSIONNAME ID ...
            # But SESSIONNAME may be missing; try to find the first int token in the row
            $idToken = ($parts | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
            if ($idToken) {
                [void]$ids.Add([int]$idToken)
            }
        }
    }

    return ($ids | Select-Object -Unique)
}

function Invoke-PsExecInteractiveNetUse {
    param(
        [Parameter(Mandatory=$true)] [string] $ComputerName,
        [Parameter(Mandatory=$true)] [int] $SessionId
    )

    # -accepteula: avoid prompt
    # -nobanner: cleaner output
    # -i <id>: interactive session
    # -s: run as SYSTEM *in that session* so it can see that session's mapped drives
    $args = @(
        '-accepteula','-nobanner',
        "\\$ComputerName",
        '-i', $SessionId.ToString(),
        '-s',
        'cmd.exe','/c','net use'
    )

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $p.StartInfo.FileName = $PsExecPath
    $p.StartInfo.Arguments = ($args -join ' ')
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError  = $true
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.CreateNoWindow  = $true

    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    return ($stdout + [Environment]::NewLine + $stderr).Trim()
}

$DeviceDetails = New-Object 'System.Collections.Generic.List[object]'

foreach ($Computer in $TargetComputers) {

    Write-Host ("  [{0}] Starting checks..." -f $Computer)

    $Detail = [PSCustomObject]@{
        ComputerName      = $Computer
        ADUserDetails  = ''
        Services          = ''
        MappedDrives      = ''
        CachedCredentials = ''
        SavedWifi         = ''
        ScheduledTasks    = ''
        StartupItems      = ''
        #Sessions          = ''
    }

    # ======= AD User Details (runs locally on DC; no remote execution) =======
    Write-Host ("  [{0}] AD User Details..." -f $Computer)
    try {
        $adUser = Get-ADUser $UserName -Properties `
            HomeDrive, HomeDirectory, ProfilePath, ScriptPath,
            LockedOut, BadLogonCount, LastBadPasswordAttempt,
            PasswordLastSet, LastLogonDate, LogonWorkstations,
            'msDS-SupportedEncryptionTypes' -ErrorAction Stop

        $adInfo = [PSCustomObject]@{
            LockedOut                    = $adUser.LockedOut
            BadLogonCount                = $adUser.BadLogonCount
            LastBadPasswordAttempt       = $adUser.LastBadPasswordAttempt
            PasswordLastSet              = $adUser.PasswordLastSet
            LastLogonDate                = $adUser.LastLogonDate
            HomeDrive                    = $adUser.HomeDrive
            HomeDirectory                = $adUser.HomeDirectory
            ProfilePath                  = $adUser.ProfilePath
            LogonScript                  = $adUser.ScriptPath
            AllowedWorkstations          = if ($adUser.LogonWorkstations) { $adUser.LogonWorkstations } else { 'All' }
            msDSSupportedEncryptionTypes = $adUser.'msDS-SupportedEncryptionTypes'
        }
        $Detail.ADUserDetails = $adInfo | ConvertTo-Html -Fragment | Out-String
    } catch {
        $Detail.ADUserDetails = "<p>Unable to query AD user: $($_.Exception.Message)</p>"
    }

    # ======= Services (WMI query) =======
    Write-Host ("  [{0}] Services..." -f $Computer)
    try {
        $svc = Get-WmiObject -ComputerName $Computer -Class Win32_Service -ErrorAction Stop |
               Where-Object { $_.StartName -like ("*{0}*" -f $UserName) } |
               Select-Object Name, DisplayName, StartName, State, StartMode
        $Detail.Services = $svc | ConvertTo-Html -Fragment | Out-String
    } catch {
        $Detail.Services = "<p>Unable to query services: $($_.Exception.Message)</p>"
    }

   # ======= Mapped Drives (HKU\<SID>\Network; loaded hives only) =======
    Write-Host ("  [{0}] MappedDrives (HKU\<SID>\Network)..." -f $Computer)
    try {
        $psMapped = @'
$ErrorActionPreference = 'SilentlyContinue'
$sids = Get-ChildItem 'Registry::HKEY_USERS' |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
        Select-Object -ExpandProperty PSChildName

if (-not $sids -or $sids.Count -eq 0) {
    'No loaded user hives found under HKU (no interactive users loaded).'
} else {
    foreach ($sid in $sids) {
        '============================================================'
        "SID: $sid"
        $netPath = "Registry::HKEY_USERS\$sid\Network"
        if (-not (Test-Path $netPath)) {
            '  (No Network subkey - no mapped drives for this hive)'
            continue
        }
        $drives = Get-ChildItem $netPath -ErrorAction SilentlyContinue
        if (-not $drives -or $drives.Count -eq 0) {
            '  (Network key exists but no drive subkeys)'
        } else {
            foreach ($d in $drives) {
                $letter     = $d.PSChildName
                $remotePath = (Get-ItemProperty -Path $d.PSPath -Name RemotePath -ErrorAction SilentlyContinue).RemotePath
                $userName   = (Get-ItemProperty -Path $d.PSPath -Name UserName   -ErrorAction SilentlyContinue).UserName
                "  Drive : $letter"
                "  Path  : $remotePath"
                if ($userName) { "  As    : $userName" }
                ''
            }
        }
    }
}
'@
        $txt = Invoke-RemotePSWmi -ComputerName $Computer -PsCode $psMapped -TimeoutSec 60
        $Detail.MappedDrives = "<pre>$txt</pre>"
    } catch {
        $Detail.MappedDrives = "<p>Unable to query mapped drives: $($_.Exception.Message)</p>"
    }


    # ======= Cached Credentials (cmdkey) =======
    Write-Host ("  [{0}] CachedCredentials..." -f $Computer)
    try {
        $txt = Invoke-RemoteCmdWmi -ComputerName $Computer -CommandLine "cmdkey /list" -TimeoutSec 30
        $Detail.CachedCredentials = "<pre>$txt</pre>"
    } catch {
        $Detail.CachedCredentials = "<p>Unable to run cmdkey: $($_.Exception.Message)</p>"
    }

    # ======= Saved WiFi Profiles (netsh wlan) =======
    Write-Host ("  [{0}] SavedWifi..." -f $Computer)
    try {
        $txt = Invoke-RemoteCmdWmi -ComputerName $Computer -CommandLine "netsh wlan show profiles" -TimeoutSec 45
        $Detail.SavedWifi = "<pre>$txt</pre>"
    } catch {
        $Detail.SavedWifi = "<p>Unable to run netsh wlan (common on servers/no WLAN): $($_.Exception.Message)</p>"
    }

    # ======= Scheduled Tasks (only Run As User matches; optional TaskName exclusions) =======
    Write-Host ("  [{0}] ScheduledTasks..." -f $Computer)
    $TaskNameExcludeRegex = ''  # set to regex to exclude tasks by TaskName, or leave blank
    try {
        $raw = Invoke-RemoteCmdWmi -ComputerName $Computer -CommandLine "schtasks /query /v /fo LIST" -TimeoutSec 150
        $blocks = $raw -split "(\r?\n){2,}" | Where-Object { $_.Trim() }

        $u = $UserName
        $fqdn = $DNSZone
        $domainNetbiosGuess = $env:USERDOMAIN

        $allowed = @(
            $u,
            "$domainNetbiosGuess\$u",
            "$fqdn\$u",
            "$u@$fqdn"
        ) | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.ToUpper() } | Select-Object -Unique

        $kept = @()
        foreach ($b in $blocks) {
            $taskName = ([regex]::Match($b, '(?im)^\s*TaskName:\s*(.+?)\s*$')).Groups[1].Value.Trim()
            $runAs    = ([regex]::Match($b, '(?im)^\s*Run As User:\s*(.+?)\s*$')).Groups[1].Value.Trim()

            if (-not $taskName -or -not $runAs) { continue }
            if ($TaskNameExcludeRegex -and ($taskName -match $TaskNameExcludeRegex)) { continue }

            if ($allowed -contains $runAs.ToUpper()) { $kept += $b }
        }

        if ($kept.Count -gt 0) {
            $sep = [Environment]::NewLine + [Environment]::NewLine
            $Detail.ScheduledTasks = "<pre>$([string]::Join($sep, $kept))</pre>"
        } else {
            $Detail.ScheduledTasks = "<p>No scheduled tasks found where <strong>Run As User</strong> matches <strong>$UserName</strong>.</p>"
        }
    } catch {
        $Detail.ScheduledTasks = "<p>Unable to query scheduled tasks: $($_.Exception.Message)</p>"
    }

    # ======= Startup Items (HKLM + loaded HKU SIDs; no NTUSER.DAT loads) =======
    Write-Host ("  [{0}] StartupItems (HKLM + loaded HKU)..." -f $Computer)
    try {
        $psStartup = @'
$ErrorActionPreference = 'SilentlyContinue'

'==================== HKLM Run ===================='
$r = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty)' }

'==================== HKLM RunOnce ===================='
$r = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty)' }

'==================== Loaded HKU User Hives ===================='
$sids = Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
if (-not $sids -or $sids.Count -eq 0) {
    'No loaded user hives found under HKU (no interactive users loaded).'
} else {
    foreach ($k in $sids) {
        $sid = $k.PSChildName
        '============================================================'
        "SID: $sid"
        '---- Run ----'
        $r = Get-ItemProperty ("Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Run" -f $sid) -ErrorAction SilentlyContinue
        if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty or key does not exist)' }
        '---- RunOnce ----'
        $r = Get-ItemProperty ("Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\RunOnce" -f $sid) -ErrorAction SilentlyContinue
        if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty or key does not exist)' }
    }
}
'@
        $txt = Invoke-RemotePSWmi -ComputerName $Computer -PsCode $psStartup -TimeoutSec 90
        $Detail.StartupItems = "<pre>$txt</pre>"
    } catch {
        $Detail.StartupItems = "<p>Unable to query startup items: $($_.Exception.Message)</p>"
    }

    $DeviceDetails.Add($Detail)
}


# ─────────────────────────────────────────────────────────────────────────────
# Device Security Event Scan (WMI/DCOM + wevtutil export + admin$ pull)
# ─────────────────────────────────────────────────────────────────────────────

Write-Host '  Scanning Security Events on target devices (RPC, server-side user filter)...'

$AllDeviceEvents = [System.Collections.Generic.List[object]]::new()
$MaxDeviceEvents = 2000   # safety cap per computer; raise if needed

# Device scan uses ONLY failure/lockout/change IDs (Group1)
# Group2 success events (4624,4634,4672,etc) are very high volume on workstations
# and are not useful for lockout source analysis on the endpoint.
$DeviceEventIds = $EventIdsGroup1 | Sort-Object -Unique

foreach ($Computer in $TargetComputers) {
    Write-Host ("  [{0}] Querying Security log (server-side filter)..." -f $Computer)
    try {
        $effectiveEnd = $EndDate
        if ($effectiveEnd -gt (Get-Date)) { $effectiveEnd = Get-Date }

        $s = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $e = $effectiveEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')

        $idFilter  = ($DeviceEventIds | ForEach-Object { "EventID=$([int]$_)" }) -join ' or '

        $userFilter = ''
        if ($UserName) {
            $userFilter = " and (EventData[Data[@Name='TargetUserName']='$UserName'] or " +
                          "EventData[Data[@Name='TargetUserName']='$UserName@$DNSZone'])"
        }

        $xPath = "*[System[($idFilter) and TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]$userFilter]"

        $filterXml = "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>$xPath</Select></Query></QueryList>"

        # Primary: FilterXml with server-side user filter (fastest)
        $Events = $null
        try {
            $Events = Get-WinEvent -ComputerName $Computer -FilterXml $filterXml `
                -MaxEvents $MaxDeviceEvents -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -like '*No events were found*') {
                Write-Host ("  [{0}] No matching events in window." -f $Computer)
                continue
            }
            # Fallback: FilterHashtable without user filter (filter user client-side)
            Write-Warning ("  [{0}] FilterXml failed ({1}), falling back..." -f $Computer, $_.Exception.Message)
            try {
                $Events = Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = $DeviceEventIds
                    StartTime = $StartDate
                } -MaxEvents $MaxDeviceEvents -ErrorAction Stop |
                Where-Object { $_.TimeCreated -le $effectiveEnd }
            } catch {
                if ($_.Exception.Message -like '*No events were found*') {
                    Write-Host ("  [{0}] No matching events in window (fallback)." -f $Computer)
                    continue
                }
                throw
            }
        }

        $matched = 0
        foreach ($Ev in $Events) {
            try {
                $x = [xml]$Ev.ToXml()
                $d = @{}
                foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }

                $tu = $d['TargetUserName']
                if ($tu -ne $UserName -and $tu -ne "$UserName@$DNSZone") { continue }

                $AllDeviceEvents.Add([PSCustomObject]@{
                    TimeCreated      = $Ev.TimeCreated
                    EventId          = $Ev.Id
                    SourceComputer   = $Computer
                    TargetUserName   = $tu
                    SubjectUserName  = $d['SubjectUserName']
                    WorkstationName  = $d['WorkstationName']
                    CallerComputer   = $d['CallerComputerName']
                    IpAddress        = $d['IpAddress']
                    LogonType        = $d['LogonType']
                    AuthPackage      = $d['AuthenticationPackageName']
                    FailureReason    = $d['FailureReason']
                    Status           = $d['Status']
                    SubStatus        = $d['SubStatus']
                    ProcessName      = $d['ProcessName']
                    LogonProcessName = $d['LogonProcessName']
                })
                $matched++
            } catch {}
        }

        $capped = if ($Events.Count -ge $MaxDeviceEvents) { " (CAPPED at $MaxDeviceEvents)" } else { '' }
        Write-Host ("  [{0}] Done. Raw: {1}{2}  Matched user: {3}" -f $Computer, $Events.Count, $capped, $matched)

    } catch {
        Write-Warning ("  [{0}] RPC event query failed: {1}" -f $Computer, $_.Exception.Message)
    }
}

Write-Host "  Device event scan: $($AllDeviceEvents.Count) events."

# ==============================================================================
#  Phase 7: Combined HTML Report
#  TOP:    Unified activity table (DC Security Events + NPS entries)
#  BOTTOM: Per-device scan (AD user details, services, tasks, startup, etc.)
# ==============================================================================
Write-Host "`n[Phase 7] Generating HTML report..."
$ReportDate = Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt'

$HtmlHeader = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Lockout Report - $UserName</title>
<style>
  body       { font-family:Segoe UI,Arial,sans-serif; margin:20px; background:#f4f4f4; color:#222; }
  h1         { background:#003366; color:white; padding:15px; border-radius:5px; }
  h2         { background:#0066cc; color:white; padding:8px 12px; border-radius:4px; margin-top:30px; }
  h3         { color:#003366; border-bottom:2px solid #0066cc; padding-bottom:5px; }
  table      { border-collapse:collapse; width:100%; margin-bottom:15px; background:white; }
  th         { background:#003366; color:white; padding:8px; text-align:left; font-size:12px; }
  td         { padding:5px 8px; border:1px solid #ddd; font-size:12px; }
  tr:nth-child(even) { background:#f0f0f0; }
  .section   { background:white; padding:15px; margin-bottom:20px; border-radius:5px; box-shadow:0 1px 3px rgba(0,0,0,.1); }
  pre        { background:#eee; padding:10px; border-radius:4px; overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }
  .fail      { background:#cc0000; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .ok        { background:#006600; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .nps       { background:#b36200; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .warn      { background:#cc7700; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .divider   { border:none; border-top:4px solid #003366; margin:40px 0; }
  .hint      { font-style:italic; color:#555; font-size:12px; margin-bottom:8px; }
</style></head><body>
<h1>Lockout Report - $UserName</h1>
<div class='section'>
  <p><strong>Username:</strong> $UserName</p>
  <p><strong>Generated:</strong> $ReportDate</p>
  <p><strong>Window:</strong> $($StartDate.ToString('MM/dd/yyyy hh:mm:ss tt')) to $($EndDate.ToString('MM/dd/yyyy hh:mm:ss tt'))</p>
  <p><strong>Target Computers:</strong> $($TargetComputers -join ', ')</p>
  <p><strong>DC Events:</strong> $($AllDCEvents.Count) |
     <strong>NPS Entries:</strong> $($AllNPSRaw.Count) |
     <strong>Device Events:</strong> $($AllDeviceEvents.Count) |
     <strong>Unified Rows:</strong> $($UnifiedRows.Count)</p>
  <p class='hint'>Event activity tables are at the top. Device scan results are below the divider.</p>
</div>
"@

$HtmlBody = ''

# ── UNIFIED ACTIVITY TABLE ────────────────────────────────────────────────────
$HtmlBody += "<h2>Unified Event Activity ($($UnifiedRows.Count) rows)</h2>`n<div class='section'>`n"

if ($UnifiedRows.Count -gt 0) {
    $HtmlBody += "<table>`n"
    $HtmlBody += "<tr><th>Time</th><th>Source</th><th>EventId / Packet</th><th>Description</th>"
    $HtmlBody += "<th>Server</th><th>User</th><th>Workstation / Caller</th><th>IP Address</th>"
    $HtmlBody += "<th>Logon Type</th><th>Auth Method</th><th>Result</th>"
    $HtmlBody += "<th>Status</th><th>SubStatus</th><th>Failure Reason</th><th>AP / Policy</th></tr>`n"

    foreach ($Row in ($UnifiedRows | Sort-Object Timestamp -Descending)) {
        $eid  = "$($Row.EventId)"
        $src  = "$($Row.Source)"
        $lt   = "$($Row.LogonType)"
        $pt   = "$($Row.PacketType)"
        $ts   = if ($Row.Timestamp)         { ([datetime]$Row.Timestamp).ToString('MM/dd/yyyy hh:mm:ss tt') } else { '' }
        $desc = if ($Row.EventDescription)  { $Row.EventDescription } elseif ($pt) { $pt } else { '' }
        $ltn  = if ($Row.LogonTypeName)     { $Row.LogonTypeName }    elseif ($lt) { $lt } else { '' }
        $sts  = if ($Row.StatusDesc)        { $Row.StatusDesc }       elseif ($Row.Status) { $Row.Status } else { '' }
        $ssts = if ($Row.SubStatusDesc)     { $Row.SubStatusDesc }    elseif ($Row.SubStatus) { $Row.SubStatus } else { '' }
        $frd  = if ($Row.FailureReasonDesc) { $Row.FailureReasonDesc } elseif ($Row.FailureReason) { $Row.FailureReason } else { '' }
        $wkst = if ($Row.WorkstationName)   { $Row.WorkstationName }  elseif ($Row.CallerComputer) { $Row.CallerComputer } else { '' }
        $ap   = if ($Row.PolicyName)        { $Row.PolicyName }       else { '' }

        $badge = if ($src -eq 'NPS') {
            "<span class='nps'>NPS</span>"
        } elseif ($eid -in @('4740','4625','4771','4776','5816','5817')) {
            "<span class='fail'>$eid</span>"
        } elseif ($eid -in @('4624','4634','4647','4672','4778','4800','4801')) {
            "<span class='ok'>$eid</span>"
        } else {
            "<span class='warn'>$eid</span>"
        }

        $HtmlBody += "<tr>"
        $HtmlBody += "<td>$ts</td><td>$src</td><td>$badge</td><td>$desc</td>"
        $HtmlBody += "<td>$($Row.SourceServer)</td><td>$($Row.UserName)</td><td>$wkst</td><td>$($Row.IpAddress)</td>"
        $HtmlBody += "<td>$ltn</td><td>$($Row.AuthMethod)</td><td>$($Row.Result)</td>"
        $HtmlBody += "<td>$sts</td><td>$ssts</td><td>$frd</td><td>$ap</td>"
        $HtmlBody += "</tr>`n"
    }
    $HtmlBody += "</table>`n"
} else {
    $HtmlBody += "<p>No unified rows found. Verify Phase 1 DC scan ran and events exist in the time window.</p>`n"
}
$HtmlBody += "</div>`n"

# ── DEVICE SECURITY EVENTS ────────────────────────────────────────────────────
if ($AllDeviceEvents.Count -gt 0) {
    $HtmlBody += "<h2>Security Events on Target Devices ($($AllDeviceEvents.Count))</h2>`n<div class='section'><table>`n"
    $HtmlBody += "<tr><th>Time</th><th>EventId</th><th>Description</th><th>Computer</th>"
    $HtmlBody += "<th>User</th><th>Workstation</th><th>IP</th><th>Logon Type</th>"
    $HtmlBody += "<th>Auth Package</th><th>Failure Reason</th><th>Status</th><th>SubStatus</th></tr>`n"

    foreach ($Ev in ($AllDeviceEvents | Sort-Object TimeCreated -Descending)) {
        $eid  = [int]$Ev.EventId
        $lt   = "$($Ev.LogonType)"
        $fr   = "$($Ev.FailureReason)"
        $st   = Normalize-HexStatus "$($Ev.Status)"
        $sst  = Normalize-HexStatus "$($Ev.SubStatus)"
        $bc   = if ($eid -in @(4625,4740,4771,4776)) { 'fail' } else { 'ok' }
        $sts  = if ($StatusDescriptions[$st])  { $StatusDescriptions[$st] }  else { $st }
        $ssts = if ($StatusDescriptions[$sst]) { $StatusDescriptions[$sst] } else { $sst }
        $frd  = if ($FailureReasons[$fr])      { $FailureReasons[$fr] }      else { $fr }
        $ltn  = if ($LogonTypes[$lt])          { $LogonTypes[$lt] }          else { $lt }

        $HtmlBody += "<tr>"
        $HtmlBody += "<td>$($Ev.TimeCreated.ToString('MM/dd/yyyy hh:mm:ss tt'))</td>"
        $HtmlBody += "<td><span class='$bc'>$eid</span></td>"
        $HtmlBody += "<td>$(if ($EventDescriptions[$eid]) { $EventDescriptions[$eid] })</td>"
        $HtmlBody += "<td>$($Ev.SourceComputer)</td><td>$($Ev.TargetUserName)</td>"
        $HtmlBody += "<td>$($Ev.WorkstationName)</td><td>$($Ev.IpAddress)</td>"
        $HtmlBody += "<td>$ltn</td><td>$($Ev.AuthPackage)</td>"
        $HtmlBody += "<td>$frd</td><td>$sts</td><td>$ssts</td>"
        $HtmlBody += "</tr>`n"
    }
    $HtmlBody += "</table></div>`n"
} else {
    $HtmlBody += "<h2>Security Events on Target Devices</h2><div class='section'><p>No device security events found.</p></div>`n"
}

# ── DIVIDER + DEVICE SCAN RESULTS ────────────────────────────────────────────
$HtmlBody += "<hr class='divider'>`n"
$HtmlBody += "<h2>Device Scan Results</h2>`n"

if ($DeviceDetails -and $DeviceDetails.Count -gt 0) {
    foreach ($Detail in $DeviceDetails) {
        $HtmlBody += "<h2>$($Detail.ComputerName)</h2>`n"

        foreach ($Sec in @(
            [PSCustomObject]@{ Title='AD User Details';          Content=$Detail.ADUserDetails }
            [PSCustomObject]@{ Title='Services Running as User'; Content=$Detail.Services }
            [PSCustomObject]@{ Title='Mapped Network Drives';    Content=$Detail.MappedDrives }
            [PSCustomObject]@{ Title='Cached Credentials';       Content=$Detail.CachedCredentials }
            [PSCustomObject]@{ Title='Saved WiFi Profiles';      Content=$Detail.SavedWifi }
            [PSCustomObject]@{ Title='Scheduled Tasks';          Content=$Detail.ScheduledTasks }
            [PSCustomObject]@{ Title='Startup Items';            Content=$Detail.StartupItems }
        )) {
            $body = if ($Sec.Content) { $Sec.Content } else { "<p class='hint'>No data returned.</p>" }
            $HtmlBody += "<div class='section'><h3>$($Sec.Title)</h3>$body</div>`n"
        }
    }
} else {
    $HtmlBody += "<div class='section'><p>No device details collected.</p></div>`n"
}

($HtmlHeader + $HtmlBody + '</body></html>') |
    Out-File -FilePath $DeviceOutputPath -Encoding UTF8 -Force
Write-Host "  HTML report: $DeviceOutputPath"

$ScriptEnd = Get-Date
Write-Host "`nDone: $($ScriptEnd.ToString('MM/dd/yyyy hh:mm:ss tt'))  |  Elapsed: $($ScriptEnd - $ScriptStart)"
#Write-Host "Unified CSV:   $UnifiedOutputPath"
Write-Host "HTML Report:   $DeviceOutputPath"
