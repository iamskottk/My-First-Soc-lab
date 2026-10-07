# SOC Lab: Windows Authentication Monitoring and Failed Logon Investigation

## Project Overview

This project documents a hands-on Security Operations Centre (SOC) investigation using Windows Security Event Logs and PowerShell.

The objective was to simulate a common SOC monitoring scenario involving repeated failed authentication attempts, identify the relevant Windows security events, investigate the activity, correlate failed and successful logons, and develop a PowerShell detection script.

The investigation was performed in a controlled Windows environment using deliberately generated failed logon activity.

The project demonstrates practical SOC activities including:

* Security event monitoring
* Authentication log analysis
* Event ID investigation
* User and source identification
* Failure reason analysis
* Process and service investigation
* Event correlation
* Basic detection engineering
* PowerShell automation
* Security incident assessment

---

## SOC Investigation Objective

The primary objective was to determine how a SOC analyst could detect and investigate repeated failed Windows logons.

The investigation focused on:

**Windows Security Event ID 4625 — An account failed to log on**

The investigation was designed to answer:

1. Which account was affected?
2. Where did the authentication attempt originate?
3. What type of logon was attempted?
4. Why did authentication fail?
5. Which Windows process was involved?
6. Which service was associated with that process?
7. Were successful logons observed afterwards?
8. Could the activity be detected automatically?

---

## Lab Environment

| Component         | Environment                |
| ----------------- | -------------------------- |
| Operating System  | Windows                    |
| Hostname          | DESKTOP-HIKEKDE            |
| User Account      | cathy                      |
| Log Source        | Windows Security Event Log |
| Analysis Tool     | PowerShell                 |
| Primary Event     | Event ID 4625              |
| Correlation Event | Event ID 4624              |
| Detection Window  | 10 minutes                 |

---

# 1. Generating Controlled Authentication Events

To create realistic SOC investigation data, several incorrect password attempts were deliberately generated against the local Windows account.

This produced multiple Windows Security Event ID 4625 events.

The activity was intentionally generated for testing and does not represent a real-world attack against an external system.

---

# 2. Detecting Failed Logons

The Windows Security log was queried for Event ID 4625.

```powershell
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 10 |
Select-Object TimeCreated, Id, Message
```

The resulting events contained the Windows message:

```text
An account failed to log on.
```

Five consecutive failed logons were observed during the controlled test.

The events occurred within a short period:

| Time     | Event ID |
| -------- | -------: |
| 14:02:22 |     4625 |
| 14:02:25 |     4625 |
| 14:02:28 |     4625 |
| 14:02:31 |     4625 |
| 14:02:33 |     4625 |

This demonstrated how repeated authentication failures can be identified from Windows Security logs.

---

# 3. Investigating the Authentication Events

The event XML was examined to extract useful investigation fields.

The following information was identified:

| Field                  | Finding                           |
| ---------------------- | --------------------------------- |
| User                   | `cathy`                           |
| Domain                 | `DESKTOP-HIKEKDE`                 |
| Source IP              | `127.0.0.1`                       |
| Logon Type             | `2`                               |
| Status                 | `0xc000006d`                      |
| SubStatus              | `0xc000006a`                      |
| Logon Process          | `User32`                          |
| Authentication Package | `Negotiate`                       |
| Workstation            | `DESKTOP-HIKEKDE`                 |
| Process                | `C:\Windows\System32\svchost.exe` |

The source address was `127.0.0.1`, indicating that the authentication activity originated locally from the same Windows system.

Logon Type `2` represents an interactive logon.

---

# 4. Analysing the Failure Reason

The event contained:

```text
Status:    0xc000006d
SubStatus: 0xc000006a
```

The important value for the investigation was:

```text
0xc000006a
```

This indicates an incorrect password condition.

Therefore, the failed authentication events were consistent with incorrect password attempts against the `cathy` account.

---

# 5. Investigating the Authentication Process

The event identified the following process:

```text
C:\Windows\System32\svchost.exe
```

The event's process ID was:

```text
0x678
```

The hexadecimal process ID was converted to decimal:

```text
1656
```

The running process was then checked:

```powershell
Get-Process -Id ([Convert]::ToInt32("678",16))
```

The process was identified as:

```text
svchost
```

This is a standard Windows host process and was not treated as malicious based solely on its presence.

---

# 6. Identifying the Associated Windows Service

The process ID was correlated with Windows services:

```powershell
Get-CimInstance Win32_Service |
Where-Object {$_.ProcessId -eq 1656} |
Select-Object Name, DisplayName, State, StartMode
```

The associated service was:

| Name        | Display Name | State   | Start Mode |
| ----------- | ------------ | ------- | ---------- |
| UserManager | User Manager | Running | Auto       |

This demonstrated an additional SOC investigation technique: tracing an event from the security log to the responsible process and then to the Windows service using that process.

---

# 7. Correlating Failed and Successful Logons

A SOC investigation should not stop after identifying a failed authentication event.

The Windows Security log was therefore also checked for Event ID 4624, which represents a successful logon.

```powershell
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 20 |
Select-Object TimeCreated, Id, Message
```

The successful authentication events were then analysed for user, source and logon type.

The investigation identified successful interactive logons for `cathy` shortly after the failed attempts.

The observed sequence was:

```text
14:02:22  Failed logon
14:02:25  Failed logon
14:02:28  Failed logon
14:02:31  Failed logon
14:02:33  Failed logon
14:02:36  Successful logon
```

The successful logon occurred approximately three seconds after the final observed failed attempt.

---

# 8. SOC Assessment

The activity was assessed using the available evidence rather than automatically classifying it as malicious.

### Observations

* Multiple failed authentication attempts were observed.
* The affected account was `cathy`.
* The source was `127.0.0.1`.
* Logon Type `2` indicated interactive authentication.
* The failure substatus `0xc000006a` indicated an incorrect password.
* The authentication process was `svchost.exe`.
* The associated service was Windows User Manager.
* Successful interactive authentication occurred shortly afterwards.

### Assessment

The activity demonstrated repeated authentication failures, which is an event pattern that a SOC analyst should investigate.

However, the evidence did **not** establish a remote brute-force attack.

The source address was the local loopback address:

```text
127.0.0.1
```

and the activity used interactive logon type `2`.

The events were deliberately generated as part of a controlled SOC lab.

Therefore, the activity was assessed as:

**Controlled local authentication activity involving incorrect password attempts.**

---

# 9. Building a PowerShell Detection

After manually investigating the events, a basic automated detection was created.

The detection searches the Windows Security log for Event ID 4625 within the previous 10 minutes.

It groups the events by username and generates an alert when three or more failures are detected.

```powershell
$StartTime=(Get-Date).AddMinutes(-10)

$events=Get-WinEvent -FilterHashtable @{
    LogName="Security"
    Id=4625
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if(-not $events){
    Write-Host "No failed logon events detected in the last 10 minutes." -ForegroundColor Green
    exit
}

$alerts=$events |
ForEach-Object {
    [xml]$xml=$_.ToXml()

    [PSCustomObject]@{
        Time=$_.TimeCreated
        User=($xml.Event.EventData.Data |
            Where-Object Name -eq "TargetUserName")."#text"
        IP=($xml.Event.EventData.Data |
            Where-Object Name -eq "IpAddress")."#text"
        LogonType=($xml.Event.EventData.Data |
            Where-Object Name -eq "LogonType")."#text"
    }
} |
Group-Object User |
Where-Object Count -ge 3

if($alerts){
    Write-Host "[ALERT] Repeated failed logons detected" -ForegroundColor Red
    $alerts |
    Select-Object Name,Count |
    Format-Table -AutoSize
}
else{
    Write-Host "No repeated failed logons detected." -ForegroundColor Green
}
```

---

# 10. Detection Testing

The detection script was executed using PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "$env:USERPROFILE\Desktop\Detect-FailedLogons.ps1"
```

During testing, the detection identified repeated failed authentication activity associated with:

```text
User: cathy
Count: 10
```

The count represented the failed logon events available within the detection window at the time the script was executed.

After the events moved outside the 10-minute detection window, the same script correctly returned:

```text
No failed logon events detected in the last 10 minutes.
```

This confirmed that the detection handled both conditions:

* Matching failed authentication activity
* No recent matching activity

---

# 11. SOC Workflow Demonstrated

This project followed a simplified SOC investigation workflow:

```text
MONITOR
   ↓
Windows Security Logs
   ↓
DETECT
   ↓
Event ID 4625
   ↓
INVESTIGATE
   ↓
User / IP / Logon Type / Failure Reason
   ↓
CORRELATE
   ↓
Event ID 4624
   ↓
PROCESS ANALYSIS
   ↓
svchost.exe → User Manager
   ↓
ASSESS
   ↓
Controlled local authentication activity
   ↓
AUTOMATE
   ↓
PowerShell detection rule
   ↓
DOCUMENT
```

---

# 12. Skills Demonstrated

This project provided practical experience with:

### Windows Security Monitoring

* Windows Security Event Logs
* Event ID 4625
* Event ID 4624
* Authentication event analysis

### Log Analysis

* Event XML analysis
* Username identification
* Source IP analysis
* Logon type analysis
* Status and substatus analysis

### Process Investigation

* Process ID analysis
* Hexadecimal to decimal PID conversion
* `svchost.exe` investigation
* Windows service correlation

### Detection Engineering

* PowerShell-based event filtering
* Time-based detection windows
* Threshold-based alerting
* Basic automated alert generation
* Handling empty event results

### SOC Investigation

* Detection
* Investigation
* Correlation
* Evidence-based assessment
* Incident classification

---


Only screenshots actually captured during the investigation should be placed in this directory.

No evidence should be fabricated or recreated after the investigation.

---

# 14. Lessons Learned

This lab demonstrated that a security event by itself does not necessarily indicate a confirmed attack.

Repeated failed logons can be an important detection signal, but the surrounding context is essential.

In this investigation, examining the source address and logon type changed the interpretation of the activity.

The investigation also demonstrated the value of correlating multiple Windows events rather than analysing a single event in isolation.

The process investigation provided another layer of context by connecting the authentication event to `svchost.exe` and the Windows User Manager service.

Finally, the PowerShell detection transformed the manual investigation into a repeatable monitoring process.

---

# 15. Future Improvements

The detection could be expanded into a more advanced SOC monitoring solution by adding:

* Source IP tracking
* Per-IP failure thresholds
* Multiple-account detection
* Account lockout detection
* Geographic or network context
* Event ID 4624 correlation
* Event ID 4740 monitoring
* CSV or JSON alert output
* Windows Event Forwarding
* SIEM integration
* Email or dashboard alerts
* Automated incident enrichment

---

# Conclusion

This project provided hands-on experience performing a basic SOC investigation using native Windows security telemetry.

Rather than relying only on theoretical cybersecurity concepts, the lab involved generating controlled authentication events, identifying suspicious event patterns, extracting relevant fields, investigating the underlying process and service, correlating successful and failed authentication events, and developing a PowerShell-based detection.

The investigation demonstrated the importance of **context, correlation and evidence-based assessment** when analysing security events.

The project represents practical exposure to the workflow of a SOC analyst:

**Detect → Investigate → Correlate → Assess → Automate → Document**

