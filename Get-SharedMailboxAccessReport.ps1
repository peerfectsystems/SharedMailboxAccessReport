<#
.SYNOPSIS
    Shows who has access to which shared mailbox in Exchange Online and flags risky entries.

.DESCRIPTION
    Read-only. The script changes nothing in your tenant.

    It lists Full Access, Read Permission, Send As and Send on Behalf permissions on all shared mailboxes
    and flags:
      - HIGH    orphaned entries (trustee no longer exists or is an unresolved SID)
      - HIGH    permissions held by disabled accounts
      - MEDIUM  permissions held by guest accounts
      - MEDIUM  permissions granted directly to users instead of groups

    Output:
      - CSV  with every permission entry
      - HTML with a summary and all findings

    Free tool by peerfect.systems Ltd - https://sharedconx.com

.PARAMETER OutputFolder
    Folder for the CSV and HTML report. Default: current folder.

.PARAMETER SkipConnect
    Do not call Connect-ExchangeOnline (use an existing session).

.EXAMPLE
    .\Get-SharedMailboxAccessReport.ps1

.EXAMPLE
    .\Get-SharedMailboxAccessReport.ps1 -OutputFolder C:\Reports

.NOTES
    Version  : 1.0.0
    Requires : ExchangeOnlineManagement module v3 or later
    Role     : read access to Exchange Online (e.g. Global Reader or View-Only Organization Management)
    Runs on  : Windows PowerShell 5.1 and PowerShell 7
    License  : MIT
#>
[CmdletBinding()]
param(
    [string]$OutputFolder = (Get-Location).Path,
    [switch]$SkipConnect
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    throw "Module 'ExchangeOnlineManagement' not found. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
}
Import-Module ExchangeOnlineManagement

if (-not $SkipConnect) {
    $isConnected = $false
    try {
        $isConnected = [bool](Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' })
    } catch { }
    if (-not $isConnected) {
        Connect-ExchangeOnline -ShowBanner:$false
    }
}

if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
}

# ---------------------------------------------------------------------------
# Trustee resolution (cached)
# ---------------------------------------------------------------------------
$script:TrusteeCache = @{}

function Resolve-Trustee {
    param([string]$Identity)

    if ($script:TrusteeCache.ContainsKey($Identity)) {
        return $script:TrusteeCache[$Identity]
    }

    $result = [pscustomobject]@{
        Name     = $Identity
        Address  = ''
        Type     = 'Unknown'
        IsGroup  = $false
        Status   = 'OK'
    }

    if ($Identity -match '^S-1-5-21-') {
        $result.Type   = 'Unresolved SID'
        $result.Status = 'Orphaned'
    }
    else {
        $recipient = $null
        try { $recipient = Get-EXORecipient -Identity $Identity -ErrorAction Stop } catch { }

        if (-not $recipient) {
            $result.Type   = 'Not found'
            $result.Status = 'Orphaned'
        }
        else {
            $result.Name    = [string]$recipient.DisplayName
            $result.Address = [string]$recipient.PrimarySmtpAddress
            $result.Type    = [string]$recipient.RecipientTypeDetails

            if ($result.Type -match 'Group') {
                $result.IsGroup = $true
            }
            elseif ($result.Type -match 'Guest') {
                $result.Status = 'Guest'
            }
            elseif ($result.Type -eq 'UserMailbox') {
                $user = $null
                foreach ($id in @($recipient.ExternalDirectoryObjectId, $recipient.PrimarySmtpAddress)) {
                    if ($user -or -not $id) { continue }
                    try { $user = Get-User -Identity ([string]$id) -ErrorAction Stop } catch { }
                }
                if ($user -and $user.AccountDisabled) {
                    $result.Status = 'Disabled'
                }
            }
        }
    }

    $script:TrusteeCache[$Identity] = $result
    return $result
}

function Get-Finding {
    param($Trustee)

    switch ($Trustee.Status) {
        'Orphaned' { return @('High',   'Orphaned entry: trustee no longer exists') }
        'Disabled' { return @('High',   'Account is disabled but still has access') }
        'Guest'    { return @('Medium', 'Guest account has access') }
    }
    if (-not $Trustee.IsGroup) {
        return @('Medium', 'Granted directly to a user instead of a group')
    }
    return @('None', '')
}

# ---------------------------------------------------------------------------
# Collect permissions
# ---------------------------------------------------------------------------
Write-Host 'Reading shared mailboxes ...'
$mailboxes = @(Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties GrantSendOnBehalfTo)

$rows       = New-Object System.Collections.Generic.List[object]
$noAccess   = New-Object System.Collections.Generic.List[object]
$failed     = New-Object System.Collections.Generic.List[object]
$counter    = 0

foreach ($mb in $mailboxes) {
    $counter++
    $address = [string]$mb.PrimarySmtpAddress
    Write-Progress -Activity 'Analysing shared mailboxes' -Status $address -PercentComplete (($counter / [math]::Max($mailboxes.Count, 1)) * 100)

    $entries = New-Object System.Collections.Generic.List[object]

    try {
        # Full Access and Read Permission
        Get-EXOMailboxPermission -Identity $address -ErrorAction Stop |
            Where-Object {
                -not $_.IsInherited -and
                ($_.User -notlike 'NT AUTHORITY\*')
            } |
            ForEach-Object {
                $rights = $_.AccessRights -join ','
                if ($rights -match 'FullAccess') {
                    $entries.Add([pscustomobject]@{ Right = 'Full Access'; Trustee = [string]$_.User })
                }
                if ($rights -match 'ReadPermission') {
                    $entries.Add([pscustomobject]@{ Right = 'Read Permission'; Trustee = [string]$_.User })
                }
            }

        # Send As
        Get-EXORecipientPermission -Identity $address -AccessRights SendAs -ResultSize Unlimited -ErrorAction Stop |
            Where-Object {
                -not $_.IsInherited -and
                ($_.Trustee -notlike 'NT AUTHORITY\*')
            } |
            ForEach-Object { $entries.Add([pscustomobject]@{ Right = 'Send As'; Trustee = [string]$_.Trustee }) }

        # Send on Behalf
        foreach ($delegate in @($mb.GrantSendOnBehalfTo)) {
            if ($delegate) {
                $entries.Add([pscustomobject]@{ Right = 'Send on Behalf'; Trustee = [string]$delegate })
            }
        }
    }
    catch {
        $failed.Add([pscustomobject]@{ Mailbox = $address; Error = $_.Exception.Message })
        continue
    }

    if ($entries.Count -eq 0) {
        $noAccess.Add([pscustomobject]@{ Mailbox = $address; DisplayName = [string]$mb.DisplayName })
        continue
    }

    foreach ($entry in $entries) {
        $trustee = Resolve-Trustee -Identity $entry.Trustee
        $finding = Get-Finding -Trustee $trustee

        $rows.Add([pscustomobject]@{
            Mailbox        = $address
            MailboxName    = [string]$mb.DisplayName
            Right          = $entry.Right
            Trustee        = $trustee.Name
            TrusteeAddress = $trustee.Address
            TrusteeType    = $trustee.Type
            ViaGroup       = $trustee.IsGroup
            Severity       = $finding[0]
            Finding        = $finding[1]
        })
    }
}
Write-Progress -Activity 'Analysing shared mailboxes' -Completed

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$total       = $rows.Count
$viaGroup    = @($rows | Where-Object { $_.ViaGroup }).Count
$orphaned    = @($rows | Where-Object { $_.Finding -like 'Orphaned*' }).Count
$disabled    = @($rows | Where-Object { $_.Finding -like 'Account is disabled*' }).Count
$guests      = @($rows | Where-Object { $_.Finding -like 'Guest*' }).Count
$directShare = 0
if ($total -gt 0) { $directShare = [math]::Round((($total - $viaGroup) / $total) * 100) }

$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmm'
$csvPath  = Join-Path $OutputFolder "SharedMailboxAccess_$stamp.csv"
$htmlPath = Join-Path $OutputFolder "SharedMailboxAccess_$stamp.html"

$rows | Sort-Object Mailbox, Right, Trustee |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
function Encode([string]$text) { [System.Net.WebUtility]::HtmlEncode($text) }

$findingRows = $rows |
    Where-Object { $_.Severity -ne 'None' } |
    Sort-Object @{ Expression = { if ($_.Severity -eq 'High') { 0 } else { 1 } } }, Mailbox, Trustee |
    ForEach-Object {
        $cls = if ($_.Severity -eq 'High') { 'high' } else { 'medium' }
        "<tr><td class='$cls'>$(Encode $_.Severity)</td><td>$(Encode $_.Mailbox)</td><td>$(Encode $_.Right)</td><td>$(Encode $_.Trustee)</td><td>$(Encode $_.TrusteeType)</td><td>$(Encode $_.Finding)</td></tr>"
    }

$noAccessRows = $noAccess | Sort-Object Mailbox | ForEach-Object {
    "<tr><td>$(Encode $_.Mailbox)</td><td>$(Encode $_.DisplayName)</td></tr>"
}

$failedRows = $failed | ForEach-Object {
    "<tr><td>$(Encode $_.Mailbox)</td><td>$(Encode $_.Error)</td></tr>"
}

$findingsTable = if ($findingRows) {
    "<table><tr><th>Severity</th><th>Shared mailbox</th><th>Right</th><th>Trustee</th><th>Type</th><th>Finding</th></tr>$($findingRows -join '')</table>"
} else { '<p>No findings.</p>' }

$noAccessTable = if ($noAccessRows) {
    "<h2>Shared mailboxes without any delegated access</h2><p>Possibly unused. Check whether they are still needed.</p><table><tr><th>Shared mailbox</th><th>Name</th></tr>$($noAccessRows -join '')</table>"
} else { '' }

$failedTable = if ($failedRows) {
    "<h2>Mailboxes that could not be read</h2><table><tr><th>Shared mailbox</th><th>Error</th></tr>$($failedRows -join '')</table>"
} else { '' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Shared Mailbox Access Report</title>
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; color: #1f2933; margin: 32px; }
  h1    { color: #2D5E7B; margin-bottom: 4px; }
  h2    { color: #2D5E7B; margin-top: 32px; }
  .meta { color: #6b7280; margin-top: 0; }
  .kpis { display: flex; flex-wrap: wrap; gap: 12px; margin: 24px 0; }
  .kpi  { background: #ECF3F5; border-radius: 6px; padding: 12px 16px; min-width: 150px; }
  .kpi b { display: block; font-size: 24px; color: #2D5E7B; }
  table { border-collapse: collapse; width: 100%; font-size: 14px; }
  th, td { border-bottom: 1px solid #e5e7eb; padding: 6px 8px; text-align: left; vertical-align: top; }
  th    { background: #2D5E7B; color: #fff; }
  .high   { color: #b91c1c; font-weight: 600; }
  .medium { color: #C17F3E; font-weight: 600; }
  footer { margin-top: 40px; color: #6b7280; font-size: 13px; }
</style>
</head>
<body>
<h1>Shared Mailbox Access Report</h1>
<p class="meta">Created $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; read-only analysis</p>

<div class="kpis">
  <div class="kpi"><b>$($mailboxes.Count)</b>shared mailboxes</div>
  <div class="kpi"><b>$total</b>permission entries</div>
  <div class="kpi"><b>$directShare %</b>not assigned via groups</div>
  <div class="kpi"><b>$orphaned</b>orphaned entries</div>
  <div class="kpi"><b>$disabled</b>held by disabled accounts</div>
  <div class="kpi"><b>$guests</b>held by guests</div>
  <div class="kpi"><b>$($noAccess.Count)</b>mailboxes without access</div>
</div>

<h2>Findings</h2>
$findingsTable
$noAccessTable
$failedTable

<footer>
  Full list of all entries: $(Encode (Split-Path $csvPath -Leaf))<br>
  Created with the free Shared Mailbox Access Report by peerfect.systems Ltd.
  Want shared mailbox permissions to follow group membership automatically? See <a href="https://sharedconx.com">sharedconx.com</a>.
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'Shared Mailbox Access Report' -ForegroundColor Cyan
Write-Host ('  Shared mailboxes            : {0}' -f $mailboxes.Count)
Write-Host ('  Permission entries          : {0}' -f $total)
Write-Host ('  Not assigned via groups     : {0} %' -f $directShare)
Write-Host ('  Orphaned entries            : {0}' -f $orphaned)
Write-Host ('  Held by disabled accounts   : {0}' -f $disabled)
Write-Host ('  Held by guests              : {0}' -f $guests)
Write-Host ('  Mailboxes without access    : {0}' -f $noAccess.Count)
if ($failed.Count -gt 0) {
    Write-Host ('  Mailboxes not readable      : {0}' -f $failed.Count) -ForegroundColor Yellow
}
Write-Host ''
Write-Host "  CSV : $csvPath"
Write-Host "  HTML: $htmlPath"
Write-Host ''
Write-Host '  Automate shared mailbox permissions via groups: https://sharedconx.com' -ForegroundColor DarkGray
