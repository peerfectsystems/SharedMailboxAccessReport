# Shared Mailbox Access Report

A free, read-only PowerShell script that shows **who has access to which shared mailbox** in Exchange Online and flags the entries that need attention.

It answers the questions auditors and admins ask most often:

- Who can open, read or send from this shared mailbox?
- Which permissions belong to people who have left the company?
- Which permissions were granted to individual users instead of groups?
- Which shared mailboxes nobody uses anymore?

The script **changes nothing** in your tenant. It only reads.

---

## What it checks

For every shared mailbox the script reads these permissions:

| Permission | Source cmdlet |
| --- | --- |
| Full Access | `Get-EXOMailboxPermission` |
| Read Permission | `Get-EXOMailboxPermission` |
| Send As | `Get-EXORecipientPermission` |
| Send on Behalf | `GrantSendOnBehalfTo` on the mailbox |

Inherited entries and `NT AUTHORITY\SELF` are ignored.

## What it flags

| Severity | Finding |
| --- | --- |
| High | Orphaned entry: the trustee no longer exists or is only an unresolved SID |
| High | The trustee account is disabled but still has access |
| Medium | A guest account has access |
| Medium | The permission was granted directly to a user instead of a group |
| Info | Shared mailbox without any delegated access (possibly unused) |

## Output

The script writes two files to the output folder:

- `SharedMailboxAccess_<date>.csv` – every permission entry, one row each
- `SharedMailboxAccess_<date>.html` – summary with key figures and all findings

The CSV columns:

| Column | Meaning |
| --- | --- |
| Mailbox | Primary SMTP address of the shared mailbox |
| MailboxName | Display name of the shared mailbox |
| Right | Full Access, Read Permission, Send As or Send on Behalf |
| Trustee | Display name of the user or group holding the right |
| TrusteeAddress | Primary SMTP address of the trustee |
| TrusteeType | Recipient type, e.g. UserMailbox, MailUniversalSecurityGroup, GuestMailUser |
| ViaGroup | `True` if the right is held by a group |
| Severity | High, Medium or None |
| Finding | Short explanation of the finding |

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Module **ExchangeOnlineManagement** v3 or later
- An account with read access to Exchange Online, for example **Global Reader** or **View-Only Organization Management**

Install the module if you don't have it yet:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Usage

1. Download `Get-SharedMailboxAccessReport.ps1`.
2. Open PowerShell in the download folder.
3. If Windows blocks the downloaded file, unblock it once:

   ```powershell
   Unblock-File .\Get-SharedMailboxAccessReport.ps1
   ```

4. Run the script:

   ```powershell
   .\Get-SharedMailboxAccessReport.ps1
   ```

   You will be asked to sign in to Exchange Online.

5. Open the HTML file shown at the end of the output.

### Parameters

| Parameter | Description |
| --- | --- |
| `-OutputFolder` | Folder for the CSV and HTML report. Default: current folder. |
| `-SkipConnect` | Use an existing Exchange Online session instead of connecting. |

### Examples

Write the reports to a specific folder:

```powershell
.\Get-SharedMailboxAccessReport.ps1 -OutputFolder C:\Reports
```

Use a session you have already opened:

```powershell
Connect-ExchangeOnline
.\Get-SharedMailboxAccessReport.ps1 -SkipConnect
```

---

## Runtime

The script queries each shared mailbox separately and resolves every trustee once (results are cached). In tenants with many shared mailboxes the run can take several minutes. A progress bar shows the current mailbox.

## Limitations

- Exchange Online only. Exchange Server on-premises is not supported.
- Folder-level permissions (e.g. Reviewer on the Inbox or Calendar) are not checked.
- Trustees are resolved with `Get-EXORecipient`. Permissions granted to security groups that are not mail-enabled may appear as "Not found".

## Privacy

The script runs entirely on your computer. It sends no data anywhere except to your own Exchange Online tenant through the official Microsoft module. The reports contain names and addresses from your tenant, so store them accordingly.

---

## Why this script exists

Microsoft does not provide a built-in way to keep shared mailbox permissions in sync with group membership. Over time, permissions are granted to individual users, people leave, and nobody cleans up. This report makes that visible.

If you want shared mailbox permissions to follow group membership automatically, have a look at [SharedConX](https://sharedconx.com).

## License

MIT – see [LICENSE](LICENSE).

© 2026 peerfect.systems Ltd
