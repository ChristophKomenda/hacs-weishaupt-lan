#requires -Version 5.1
<#
.SYNOPSIS
  Read-only targeted CanApiJson correlation scan for Weishaupt Systemgeraet.

.DESCRIPTION
  This script performs only read-only numeric GET queries (CMD 0x01) against:
    MI = 0x09
    MX = 0x00, 0x01, 0x02, 0x03

  Expected module context inferred from the real systable.csv:
    09/00 -> Systemgeraet or HK1-near dynamic values
    09/01 -> WTC boiler dynamic values
    09/02 -> HK2-near dynamic values
    09/03 -> HK3-near dynamic values

  It never sends SET (0x03), SETS (0x13), ACK, or write requests.
  The script negotiates the working request source identifier using a
  read-only preflight: SYS first, then DDC as a controlled fallback.
  A conservative delay between batches reduces load on the embedded controller.
  Results are saved after every batch, so interrupted scans can be resumed.

  Output is written to:
    Desktop\Weishaupt_Targeted_Correlation

  Default credentials:
    Username: admin
    Password: Admin123
  The password is used automatically unless overridden with -Password.

  Profiles:
    Quick   -> known curated addresses across MX 00..03
    Focused -> selected adjacent blocks for targeted discovery and correlation

.NOTES
  Use only on your own installation. The script is intentionally read-only.
#>

[CmdletBinding()]
param(
    [string]$SystemDevice = "10.100.1.230",
    [string]$Username = "admin",
    [string]$Password = "",
    [ValidateSet("Quick", "Focused", "HeatingCircuit", "HeatingCircuitV2")]
    [string]$Profile,
    [string]$Label,
    [int[]]$Modules = @(0, 1, 2, 3),
    [int]$BatchSize = 6,
    [int]$RepeatCount = 1,
    [int]$DelayMilliseconds = 300,
    [switch]$Resume,
    [switch]$NoExplorer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# This affects only the current PowerShell process.
try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
}
catch {
    # Not required when the launcher already used -ExecutionPolicy Bypass.
}

if ($DelayMilliseconds -lt 300) {
    throw "DelayMilliseconds must be at least 300 ms."
}

if ($BatchSize -lt 1 -or $BatchSize -gt 6) {
    throw "BatchSize must be between 1 and 6. The script intentionally limits CanApiJson batches to six frames."
}

if ($RepeatCount -lt 1) {
    throw "RepeatCount must be at least 1."
}

$ApiUrl = "http://$SystemDevice/ajax/CanApiJson.json"
$RootOutput = Join-Path ([Environment]::GetFolderPath("Desktop")) "Weishaupt_Targeted_Correlation"
$ActiveRunPath = Join-Path $RootOutput "_active-run.json"

# The real Systemgeraet is first probed with SRC=SYS. A controlled DDC fallback
# is retained for installations or firmware variants that require it.
$script:ActiveSrc = "SYS"

New-Item -ItemType Directory -Path $RootOutput -Force | Out-Null

function ConvertTo-SafeFileName {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "snapshot"
    }

    $safe = $Value.Trim() -replace '[\\/:*?"<>|]', "_"
    $safe = $safe -replace '\s+', "_"
    if ($safe.Length -gt 80) {
        $safe = $safe.Substring(0, 80)
    }
    return $safe
}

function Read-PlainPassword {
    param([string]$ProvidedPassword)

    if (-not [string]::IsNullOrWhiteSpace($ProvidedPassword)) {
        return $ProvidedPassword
    }

    $securePassword = Read-Host "System device password" -AsSecureString
    $plain = [System.Net.NetworkCredential]::new(
        "", $securePassword
    ).Password

    if ([string]::IsNullOrWhiteSpace($plain)) {
        throw "A password is required."
    }

    return $plain
}

function New-AuthorizationHeader {
    param(
        [string]$User,
        [string]$PlainPassword
    )

    $pair = "$User`:$PlainPassword"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $token = [Convert]::ToBase64String($bytes)
    return @{ Authorization = "Basic $token" }
}

function New-RequestId {
    return (Get-Random -Minimum 10000000 -Maximum 99999999).ToString()
}

function New-GetFrame {
    param(
        [int]$Mi,
        [int]$Mx,
        [int]$Ox,
        [int]$Os,
        [int]$Vs,
        [string]$Source = ""
    )

    if ($Vs -notin @(1, 2, 4)) {
        throw "Unsupported VS=$Vs. This targeted scanner supports numeric lengths 1, 2, and 4 only."
    }

    $requestVg = ("01{0:X2}{1:X2}{2:X4}{3:X2}{4:X4}{5}" -f `
        $Mi, $Mx, $Ox, $Os, $Vs, ("00" * $Vs))

    [pscustomobject]@{
        Key            = ("{0:X2}/{1:X2}/{2:X4}/{3:X2}/VS={4}" -f $Mi, $Mx, $Ox, $Os, $Vs)
        Mi             = $Mi
        Mx             = $Mx
        Ox             = $Ox
        Os             = $Os
        Vs             = $Vs
        ModuleContext  = if ($Mi -eq 0x02) {
            "HK$($Mx + 1)"
        } else {
            Get-ModuleContext -Mx $Mx
        }
        Source         = $Source
        RequestVG      = $requestVg
    }
}

function Get-ModuleContext {
    param([int]$Mx)

    switch ($Mx) {
        0 { return "Systemgeraet_or_HK1_near" }
        1 { return "WTC_boiler_reference" }
        2 { return "HK2_near" }
        3 { return "HK3_near" }
        default { return "Unknown" }
    }
}

function Add-PlanFrame {
    param(
        [System.Collections.Generic.List[object]]$Plan,
        [hashtable]$Seen,
        [int]$Mi,
        [int]$Mx,
        [int]$Ox,
        [int]$Os,
        [int]$Vs,
        [string]$Source
    )

    $key = ("{0:X2}/{1:X2}/{2:X4}/{3:X2}/VS={4}" -f $Mi, $Mx, $Ox, $Os, $Vs)
    if (-not $Seen.ContainsKey($key)) {
        $Plan.Add((New-GetFrame -Mi $Mi -Mx $Mx -Ox $Ox -Os $Os -Vs $Vs -Source $Source))
        $Seen[$key] = $true
    }
}

function New-ProbePlan {
    param(
        [string]$SelectedProfile,
        [int[]]$SelectedModules
    )



    if ($SelectedProfile -eq "HeatingCircuitV2") {
        $plan = New-Object 'System.Collections.Generic.List[object]'
        $seen = @{}

        $references = @(
            @{ Ox = 0x2533; Vs = 1 },
            @{ Ox = 0x2582; Vs = 1 },
            @{ Ox = 0x2559; Vs = 2 },
            @{ Ox = 0x2507; Vs = 2 }
        )

        foreach ($r in $references) {
            Add-PlanFrame -Plan $plan -Seen $seen `
                -Mi 0x02 -Mx 0 -Ox $r.Ox -Os 0x02 `
                -Vs $r.Vs -Source "HK1-confirmed"
        }

        Add-PlanFrame -Plan $plan -Seen $seen `
            -Mi 0x09 -Mx 1 -Ox 0x2619 -Os 0x02 `
            -Vs 1 -Source "WTC-pump-unconfirmed"

        return $plan
    }

    if ($SelectedProfile -eq "HeatingCircuit") {
        $plan = New-Object 'System.Collections.Generic.List[object]'
        $seen = @{}

        $referenceRegisters = @(
            @{ Ox = 0x2533; Os = 0x02; Vs = 1 },
            @{ Ox = 0x2582; Os = 0x02; Vs = 1 },
            @{ Ox = 0x2559; Os = 0x02; Vs = 2 },
            @{ Ox = 0x2507; Os = 0x02; Vs = 2 }
        )

        foreach ($mx in @(0)) {
            foreach ($register in $referenceRegisters) {
                Add-PlanFrame -Plan $plan -Seen $seen -Mi 0x02 -Mx $mx `
                    -Ox $register.Ox -Os $register.Os `
                    -Vs $register.Vs -Source "heating-circuit-reference"
            }
        }

        return $plan
    }

    $plan = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}

    $curated = @(
        @{ Ox = 0x2610; Os = 0x02; Vs = 2 },
        @{ Ox = 0x2611; Os = 0x02; Vs = 2 },
        @{ Ox = 0x2612; Os = 0x02; Vs = 2 },
        @{ Ox = 0x2615; Os = 0x02; Vs = 2 },
        @{ Ox = 0x2619; Os = 0x02; Vs = 1 },
        @{ Ox = 0x263A; Os = 0x02; Vs = 2 },
        @{ Ox = 0x2679; Os = 0x00; Vs = 2 },
        @{ Ox = 0x268A; Os = 0x00; Vs = 4 },
        @{ Ox = 0x268B; Os = 0x00; Vs = 4 },
        @{ Ox = 0x268C; Os = 0x00; Vs = 4 },
        @{ Ox = 0x268D; Os = 0x00; Vs = 2 },
        @{ Ox = 0x268E; Os = 0x00; Vs = 2 },
        @{ Ox = 0x268F; Os = 0x00; Vs = 2 },
        @{ Ox = 0x2902; Os = 0x00; Vs = 2 },
        @{ Ox = 0x2903; Os = 0x00; Vs = 2 },
        @{ Ox = 0x2904; Os = 0x00; Vs = 1 },
        @{ Ox = 0x2905; Os = 0x00; Vs = 1 },
        @{ Ox = 0x2908; Os = 0x00; Vs = 2 },
        @{ Ox = 0x2922; Os = 0x00; Vs = 1 }
    )

    foreach ($mx in $SelectedModules) {
        foreach ($candidate in $curated) {
            Add-PlanFrame -Plan $plan -Seen $seen -Mi 0x09 -Mx $mx `
                -Ox $candidate.Ox -Os $candidate.Os -Vs $candidate.Vs -Source "curated"
        }
    }

    if ($SelectedProfile -eq "Focused") {
        $clusters = @(
            @{ Start = 0x2610; End = 0x261F; Subindices = @(0x00, 0x01, 0x02) },
            @{ Start = 0x2630; End = 0x263F; Subindices = @(0x00, 0x01, 0x02) },
            @{ Start = 0x2670; End = 0x267F; Subindices = @(0x00, 0x01, 0x02) },
            @{ Start = 0x2680; End = 0x268F; Subindices = @(0x00, 0x01, 0x02) },
            @{ Start = 0x2900; End = 0x290F; Subindices = @(0x00, 0x01, 0x02) },
            @{ Start = 0x2920; End = 0x292F; Subindices = @(0x00, 0x01, 0x02) }
        )

        foreach ($mx in $SelectedModules) {
            foreach ($cluster in $clusters) {
                for ($ox = $cluster.Start; $ox -le $cluster.End; $ox++) {
                    foreach ($os in $cluster.Subindices) {
                        foreach ($vs in @(1, 2, 4)) {
                            Add-PlanFrame -Plan $plan -Seen $seen -Mi 0x09 -Mx $mx `
                                -Ox $ox -Os $os -Vs $vs -Source "focused-adjacent"
                        }
                    }
                }
            }
        }
    }

    return $plan
}

function Split-IntoBatches {
    param(
        [object[]]$Items,
        [int]$Size
    )

    $batches = @()
    for ($offset = 0; $offset -lt $Items.Count; $offset += $Size) {
        $upper = [Math]::Min($offset + $Size - 1, $Items.Count - 1)
        $batches += ,@($Items[$offset..$upper])
    }
    return $batches
}

function Invoke-CanApiReadBatch {
    param(
        [object[]]$Batch,
        [hashtable]$Headers
    )

    $capi = [ordered]@{
        NN = $Batch.Count
    }

    for ($index = 0; $index -lt $Batch.Count; $index++) {
        $frameName = "N{0:D2}" -f ($index + 1)
        $capi[$frameName] = [ordered]@{
            VG = $Batch[$index].RequestVG
        }
    }

    $payload = [ordered]@{
        ID   = New-RequestId
        SRC  = $script:ActiveSrc
        CAPI = $capi
    }

    $json = $payload | ConvertTo-Json -Depth 8 -Compress

    return Invoke-RestMethod `
        -Uri $ApiUrl `
        -Method Post `
        -Headers $Headers `
        -ContentType "application/json" `
        -Body $json `
        -TimeoutSec 30
}

function ConvertTo-SignedValue {
    param(
        [UInt64]$Unsigned,
        [int]$Vs
    )

    # Use decimal thresholds deliberately. In Windows PowerShell 5.1 some large
    # hexadecimal literals are interpreted as signed Int32 values, which can
    # make positive 32-bit raw values appear as large negative numbers.
    switch ($Vs) {
        1 {
            if ($Unsigned -ge [UInt64]128) { return [Int64]$Unsigned - 256 }
            return [Int64]$Unsigned
        }
        2 {
            if ($Unsigned -ge [UInt64]32768) { return [Int64]$Unsigned - 65536 }
            return [Int64]$Unsigned
        }
        4 {
            if ($Unsigned -ge [UInt64]2147483648) { return [Int64]$Unsigned - 4294967296 }
            return [Int64]$Unsigned
        }
        default {
            return [Int64]$Unsigned
        }
    }
}

function Get-CommandName {
    param([string]$Cmd)

    switch ($Cmd.ToUpperInvariant()) {
        "02" { return "CMD_RESPONSE" }
        "05" { return "CMD_ERROR" }
        default { return "CMD_$Cmd" }
    }
}

function Convert-ResponseFrame {
    param(
        [string]$ResponseVG,
        [object]$Expected
    )

    $result = [ordered]@{
        Timestamp       = (Get-Date).ToString("s")
        Label           = $script:Label
        Profile         = $script:Profile
        ExpectedKey     = $Expected.Key
        ModuleContext   = $Expected.ModuleContext
        Source          = $Expected.Source
        RequestVG       = $Expected.RequestVG
        ResponseVG      = $ResponseVG
        Cmd             = ""
        CmdName         = ""
        Mi              = ("0x{0:X2}" -f $Expected.Mi)
        Mx              = ("0x{0:X2}" -f $Expected.Mx)
        Ox              = ("0x{0:X4}" -f $Expected.Ox)
        Os              = ("0x{0:X2}" -f $Expected.Os)
        Vs              = $Expected.Vs
        RawHex          = ""
        RawUnsigned     = ""
        RawSigned       = ""
        ScaledX0_1      = ""
        ScaledX0_01     = ""
        IsSentinel      = $false
        ParseStatus     = ""
    }

    if ([string]::IsNullOrWhiteSpace($ResponseVG)) {
        $result.ParseStatus = "missing-response"
        return [pscustomobject]$result
    }

    $vg = $ResponseVG.Trim().ToUpperInvariant()
    if ($vg.Length -lt 2) {
        $result.ParseStatus = "response-too-short"
        return [pscustomobject]$result
    }

    $cmd = $vg.Substring(0, 2)
    $result.Cmd = $cmd
    $result.CmdName = Get-CommandName -Cmd $cmd

    if ($vg.Length -lt 16) {
        $result.ParseStatus = "response-header-too-short"
        return [pscustomobject]$result
    }

    try {
        $result.Mi = "0x" + $vg.Substring(2, 2)
        $result.Mx = "0x" + $vg.Substring(4, 2)
        $result.Ox = "0x" + $vg.Substring(6, 4)
        $result.Os = "0x" + $vg.Substring(10, 2)
        $result.Vs = [Convert]::ToInt32($vg.Substring(12, 4), 16)

        if ($cmd -ne "02") {
            $result.ParseStatus = "non-response-command"
            return [pscustomobject]$result
        }

        $rawLength = $result.Vs * 2
        if ($vg.Length -lt (16 + $rawLength)) {
            $result.ParseStatus = "raw-value-too-short"
            return [pscustomobject]$result
        }

        $rawHex = $vg.Substring(16, $rawLength)
        $rawUnsigned = [Convert]::ToUInt64($rawHex, 16)
        $rawSigned = ConvertTo-SignedValue -Unsigned $rawUnsigned -Vs $result.Vs

        $result.RawHex = $rawHex
        $result.RawUnsigned = $rawUnsigned
        $result.RawSigned = $rawSigned
        $result.ScaledX0_1 = [Math]::Round(($rawSigned * 0.1), 4)
        $result.ScaledX0_01 = [Math]::Round(($rawSigned * 0.01), 4)
        $result.IsSentinel = $rawHex -in @("8000", "FFFF", "80000000", "FFFFFFFF")
        $result.ParseStatus = "ok"
    }
    catch {
        $result.ParseStatus = "parse-error: $($_.Exception.Message)"
    }

    return [pscustomobject]$result
}

function Get-ResponseVgList {
    param([object]$Response)

    $frames = @()

    if ($null -eq $Response -or $null -eq $Response.CAPI) {
        return $frames
    }

    $properties = $Response.CAPI.PSObject.Properties |
        Where-Object { $_.Name -match '^N\d{2}$' } |
        Sort-Object Name

    foreach ($property in $properties) {
        $frames += [string]$property.Value.VG
    }

    return $frames
}

function Add-ResultRows {
    param(
        [object[]]$Rows,
        [string]$CsvPath,
        [string]$JsonLinesPath
    )

    if ($Rows.Count -eq 0) {
        return
    }

    if (-not (Test-Path $CsvPath)) {
        $Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        $Rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Append
    }

    foreach ($row in $Rows) {
        ($row | ConvertTo-Json -Depth 8 -Compress) |
            Add-Content -Path $JsonLinesPath -Encoding UTF8
    }
}

function Save-Checkpoint {
    param(
        [string]$CheckpointPath,
        [int]$NextBatchIndex,
        [int]$TotalBatches,
        [string]$RunFolder
    )

    [ordered]@{
        RunFolder      = $RunFolder
        NextBatchIndex = $NextBatchIndex
        TotalBatches   = $TotalBatches
        Profile        = $script:Profile
        Label          = $script:Label
        SystemDevice   = $script:SystemDevice
        UpdatedAt      = (Get-Date).ToString("s")
    } |
        ConvertTo-Json -Depth 6 |
        Set-Content -Path $CheckpointPath -Encoding UTF8

    Copy-Item -Path $CheckpointPath -Destination $ActiveRunPath -Force
}

function Write-SummaryFiles {
    param(
        [string]$RunFolder,
        [string]$ResultsCsv
    )

    if (-not (Test-Path $ResultsCsv)) {
        return
    }

    $results = Import-Csv $ResultsCsv
    $supported = @($results | Where-Object { $_.Cmd -eq "02" -and $_.ParseStatus -eq "ok" })
    $errors = @($results | Where-Object { $_.Cmd -ne "02" -or $_.ParseStatus -ne "ok" })

    # A focused scan intentionally tests requested VS values 1, 2, and 4.
    # Some devices answer with their canonical response length regardless of
    # the requested VS. Keep every request in results.csv, but write one row per
    # actual returned address and response length to the summary exports.
    $supportedUnique = @(
        $supported |
            Group-Object Mi, Mx, Ox, Os, Vs |
            ForEach-Object { $_.Group | Select-Object -Last 1 }
    )

    $supportedUnique |
        Sort-Object Mx, Ox, Os, Vs |
        Export-Csv (Join-Path $RunFolder "supported-values.csv") -NoTypeInformation -Encoding UTF8

    $errors |
        Sort-Object Mx, Ox, Os, Vs |
        Export-Csv (Join-Path $RunFolder "unsupported-or-errors.csv") -NoTypeInformation -Encoding UTF8

    $stateLike = @(
        $supportedUnique |
            Where-Object { $_.RawUnsigned -in @("0", "1") } |
            Sort-Object Mx, Ox, Os, Vs
    )

    $stateLike |
        Export-Csv (Join-Path $RunFolder "state-like-raw-0-or-1.csv") -NoTypeInformation -Encoding UTF8

    $previousSupported = Get-ChildItem -Path $RootOutput -Directory |
        Where-Object { $_.FullName -ne $RunFolder } |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object {
            $candidate = Join-Path $_.FullName "supported-values.csv"
            if (Test-Path $candidate) {
                return $candidate
            }
        } |
        Select-Object -First 1

    if ($previousSupported) {
        $previous = Import-Csv $previousSupported
        $oldByKey = @{}
        foreach ($row in $previous) {
            $comparisonKey = "$($row.Mi)/$($row.Mx)/$($row.Ox)/$($row.Os)/VS=$($row.Vs)"
            $oldByKey[$comparisonKey] = $row
        }

        $changes = foreach ($row in $supportedUnique) {
            $comparisonKey = "$($row.Mi)/$($row.Mx)/$($row.Ox)/$($row.Os)/VS=$($row.Vs)"
            if ($oldByKey.ContainsKey($comparisonKey)) {
                $old = $oldByKey[$comparisonKey]
                if ($old.RawSigned -ne $row.RawSigned) {
                    [pscustomobject]@{
                        Key            = $comparisonKey
                        ModuleContext  = $row.ModuleContext
                        PreviousValue  = $old.RawSigned
                        CurrentValue   = $row.RawSigned
                        Delta          = ([double]$row.RawSigned - [double]$old.RawSigned)
                        PreviousLabel  = $old.Label
                        CurrentLabel   = $row.Label
                    }
                }
            }
        }

        @($changes) |
            Sort-Object ModuleContext, Key |
            Export-Csv (Join-Path $RunFolder "changed-values-vs-previous-run.csv") -NoTypeInformation -Encoding UTF8

        Set-Content `
            -Path (Join-Path $RunFolder "comparison-source.txt") `
            -Value $previousSupported `
            -Encoding UTF8
    }

    [ordered]@{
        RunFolder                  = $RunFolder
        Label                      = $script:Label
        Profile                    = $script:Profile
        SystemDevice               = $script:SystemDevice
        ReadOnly                   = $true
        CommandUsed                = "CMD_GET 0x01 only"
        ResultCount                = $results.Count
        SupportedNumericResponses  = $supported.Count
        SupportedUniqueAddresses   = $supportedUnique.Count
        UnsupportedOrErrors        = $errors.Count
        StateLikeRawZeroOrOne      = $stateLike.Count
        GeneratedAt                = (Get-Date).ToString("s")
    } |
        ConvertTo-Json -Depth 6 |
        Set-Content (Join-Path $RunFolder "summary.json") -Encoding UTF8
}

# Interactive defaults for double-click use.
if ([string]::IsNullOrWhiteSpace($Profile)) {
    Write-Host ""
    Write-Host "Choose scan profile:" -ForegroundColor Cyan
    Write-Host "  1 = Quick   (known curated addresses across 09/00..09/03)"
    Write-Host "  2 = Focused (selected adjacent blocks across 09/00..09/03)"
    Write-Host "  3 = HeatingCircuit (HK1-HK3 reference registers)"
    $selection = Read-Host "Profile [2]"
    if ($selection -eq "1") {
        $Profile = "Quick"
    }
    elseif ($selection -eq "3") {
        $Profile = "HeatingCircuit"
    }
    else {
        $Profile = "Focused"
    }
}

if ([string]::IsNullOrWhiteSpace($Label)) {
    $Label = Read-Host "Snapshot label, for example HK2_Pumpe_Ein or Heizbetrieb_Aktiv"
    if ([string]::IsNullOrWhiteSpace($Label)) {
        $Label = "snapshot"
    }
}

$plainPassword = Read-PlainPassword -ProvidedPassword $Password
$headers = New-AuthorizationHeader -User $Username -PlainPassword $plainPassword

# Read-only protocol preflight using the confirmed HK1 operating-mode register.
# The direct real-hardware PowerShell probes for this installation used SRC=SYS.
# A controlled DDC fallback is retained for compatibility with other variants.
Write-Host ""
Write-Host "Running read-only protocol preflight ..." -ForegroundColor Cyan

$preflightFrame = @(
    New-GetFrame `
        -Mi 0x02 `
        -Mx 0x00 `
        -Ox 0x2533 `
        -Os 0x02 `
        -Vs 1 `
        -Source "preflight"
)

$preflightErrors = New-Object 'System.Collections.Generic.List[string]'
$preflightSucceeded = $false

foreach ($candidateSrc in @("SYS", "DDC")) {
    $script:ActiveSrc = $candidateSrc
    Write-Host "  Trying SRC=$candidateSrc ..." -NoNewline

    try {
        $preflightResponse = Invoke-CanApiReadBatch -Batch $preflightFrame -Headers $headers
        $preflightVgs = @(Get-ResponseVgList -Response $preflightResponse)

        if ($preflightVgs.Count -lt 1) {
            throw "No VG response returned."
        }

        $preflightVg = [string]$preflightVgs[0]
        if ($preflightVg.Length -lt 2) {
            throw "VG response is too short: $preflightVg"
        }

        $preflightCmd = $preflightVg.Substring(0, 2).ToUpperInvariant()
        if ($preflightCmd -ne "02") {
            throw "Expected CMD_RESPONSE 0x02 but received 0x$preflightCmd. VG=$preflightVg"
        }

        Write-Host " OK" -ForegroundColor Green
        $preflightSucceeded = $true
        break
    }
    catch {
        Write-Host " failed" -ForegroundColor Yellow
        $preflightErrors.Add("SRC=$candidateSrc -> $($_.Exception.Message)")
    }
}

if (-not $preflightSucceeded) {
    $details = $preflightErrors -join " | "
    throw "Read-only preflight failed for SYS and DDC. Check that the cloud connection is disabled, the local JSON interface is enabled, and the credentials are correct. No discovery scan was started. Details: $details"
}

Write-Host "Preflight OK: confirmed read-only CMD_GET request answered normally with SRC=$script:ActiveSrc." -ForegroundColor Green

$runFolder = $null
$checkpointPath = $null
$resultsCsv = $null
$jsonLinesPath = $null
$plan = $null
$startBatchIndex = 0

if (Test-Path $ActiveRunPath) {
    $active = Get-Content $ActiveRunPath -Raw | ConvertFrom-Json
    $resumeExisting = $Resume.IsPresent

    if (-not $resumeExisting) {
        Write-Host ""
        Write-Host "An incomplete previous run was found:" -ForegroundColor Yellow
        Write-Host "  $($active.RunFolder)"
        $answer = Read-Host "Resume it? [Y/n]"
        $resumeExisting = [string]::IsNullOrWhiteSpace($answer) -or $answer.Trim().ToLowerInvariant() -eq "y"
    }

    if ($resumeExisting) {
        $runFolder = [string]$active.RunFolder
        $checkpointPath = Join-Path $runFolder "checkpoint.json"
        $planPath = Join-Path $runFolder "probe-plan.json"

        if (-not (Test-Path $checkpointPath) -or -not (Test-Path $planPath)) {
            throw "The active run checkpoint is incomplete. Remove $ActiveRunPath manually after inspecting the folder."
        }

        $checkpoint = Get-Content $checkpointPath -Raw | ConvertFrom-Json
        $plan = @(Get-Content $planPath -Raw | ConvertFrom-Json)
        $Profile = [string]$checkpoint.Profile
        $Label = [string]$checkpoint.Label
        $SystemDevice = [string]$checkpoint.SystemDevice
        $ApiUrl = "http://$SystemDevice/ajax/CanApiJson.json"
        $startBatchIndex = [int]$checkpoint.NextBatchIndex

        Write-Host ""
        Write-Host "Resuming previous scan at batch $startBatchIndex ..." -ForegroundColor Cyan
    }
    else {
        Remove-Item $ActiveRunPath -Force
    }
}

if ($null -eq $runFolder) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeLabel = ConvertTo-SafeFileName -Value $Label
    $runFolder = Join-Path $RootOutput "$timestamp-$safeLabel-$Profile"
    New-Item -ItemType Directory -Path $runFolder -Force | Out-Null

    $plan = @(New-ProbePlan -SelectedProfile $Profile -SelectedModules $Modules)
    $plan |
        ConvertTo-Json -Depth 8 |
        Set-Content (Join-Path $runFolder "probe-plan.json") -Encoding UTF8

    [ordered]@{
        SystemDevice  = $SystemDevice
        Profile       = $Profile
        Label         = $Label
        Modules       = $Modules
        BatchSize     = $BatchSize
        RepeatCount   = $RepeatCount
        DelayMilliseconds = $DelayMilliseconds
        ReadOnly      = $true
        RequestSrc    = $script:ActiveSrc
        CommandUsed   = "CMD_GET 0x01 only"
        CreatedAt     = (Get-Date).ToString("s")
    } |
        ConvertTo-Json -Depth 8 |
        Set-Content (Join-Path $runFolder "run-metadata.json") -Encoding UTF8
}

$checkpointPath = Join-Path $runFolder "checkpoint.json"
$resultsCsv = Join-Path $runFolder "results.csv"
$jsonLinesPath = Join-Path $runFolder "results.jsonl"

try {
    $batches = @(Split-IntoBatches -Items $plan -Size $BatchSize)
    $totalBatches = $batches.Count

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host "Weishaupt targeted correlation scan" -ForegroundColor Cyan
    Write-Host "System device : $SystemDevice"
    Write-Host "Profile       : $Profile"
    Write-Host "Label         : $Label"
    Write-Host "Frames        : $($plan.Count)"
    Write-Host "Batches       : $totalBatches"
    Write-Host "Output folder : $runFolder"
    Write-Host "Safety        : read-only CMD_GET 0x01 only"
    Write-Host "Request SRC   : $script:ActiveSrc"
    Write-Host "Throttle      : $DelayMilliseconds ms between batches"
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host ""

    for ($batchIndex = $startBatchIndex; $batchIndex -lt $totalBatches; $batchIndex++) {
        $batch = @($batches[$batchIndex])
        $progress = [Math]::Round((($batchIndex + 1) / $totalBatches) * 100, 1)

        Write-Progress `
            -Activity "Weishaupt targeted read-only scan" `
            -Status "Batch $($batchIndex + 1) of $totalBatches ($progress%)" `
            -PercentComplete $progress

        $response = $null
        $rows = @()

        try {
            $response = Invoke-CanApiReadBatch -Batch $batch -Headers $headers
            $responseVgs = @(Get-ResponseVgList -Response $response)

            for ($frameIndex = 0; $frameIndex -lt $batch.Count; $frameIndex++) {
                $responseVg = ""
                if ($frameIndex -lt $responseVgs.Count) {
                    $responseVg = $responseVgs[$frameIndex]
                }
                $rows += Convert-ResponseFrame -ResponseVG $responseVg -Expected $batch[$frameIndex]
            }
        }
        catch {
            foreach ($expected in $batch) {
                $rows += [pscustomobject][ordered]@{
                    Timestamp       = (Get-Date).ToString("s")
                    Label           = $Label
                    Profile         = $Profile
                    ExpectedKey     = $expected.Key
                    ModuleContext   = $expected.ModuleContext
                    Source          = $expected.Source
                    RequestVG       = $expected.RequestVG
                    ResponseVG      = ""
                    Cmd             = ""
                    CmdName         = ""
                    Mi              = ("0x{0:X2}" -f $expected.Mi)
                    Mx              = ("0x{0:X2}" -f $expected.Mx)
                    Ox              = ("0x{0:X4}" -f $expected.Ox)
                    Os              = ("0x{0:X2}" -f $expected.Os)
                    Vs              = $expected.Vs
                    RawHex          = ""
                    RawUnsigned     = ""
                    RawSigned       = ""
                    ScaledX0_1      = ""
                    ScaledX0_01     = ""
                    IsSentinel      = $false
                    ParseStatus     = "http-or-batch-error: $($_.Exception.Message)"
                }
            }
        }

        Add-ResultRows -Rows $rows -CsvPath $resultsCsv -JsonLinesPath $jsonLinesPath
        Save-Checkpoint `
            -CheckpointPath $checkpointPath `
            -NextBatchIndex ($batchIndex + 1) `
            -TotalBatches $totalBatches `
            -RunFolder $runFolder

        if ($DelayMilliseconds -gt 0 -and ($batchIndex + 1) -lt $totalBatches) {
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }

    Write-Progress -Activity "Weishaupt targeted read-only scan" -Completed

    Write-SummaryFiles -RunFolder $runFolder -ResultsCsv $resultsCsv

    if (Test-Path $checkpointPath) {
        Remove-Item $checkpointPath -Force
    }
    if (Test-Path $ActiveRunPath) {
        Remove-Item $ActiveRunPath -Force
    }

    Write-Host ""
    Write-Host "Finished successfully." -ForegroundColor Green
    Write-Host "All requests were read-only CanApiJson CMD_GET 0x01 queries."
    Write-Host ""
    Write-Host "Result folder:"
    Write-Host $runFolder -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Upload the complete result folder as ZIP for analysis."
}
finally {
    # Ensure secrets do not remain in reusable variables longer than needed.
    $plainPassword = $null
    $headers = $null

    if (-not $NoExplorer.IsPresent -and (Test-Path $runFolder)) {
        Start-Process explorer.exe $runFolder
    }
}
