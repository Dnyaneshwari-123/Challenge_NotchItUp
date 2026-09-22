# 🔎 DFIR Memory Forensics — Challenge_NotchItUp

A Digital Forensics and Incident Response (DFIR) memory forensics challenge involving the analysis of a Windows memory dump using the **Volatility 3 Framework**.

The objective was to investigate a captured memory image, identify a password-protected RAR archive associated with the suspect's activity, recover its password from volatile memory, extract the archive contents, and reconstruct the hidden CTF flag.

---

## 📌 Challenge Overview

**Challenge:** `Challenge_NotchItUp`

**Category:** Digital Forensics / Memory Forensics / CTF

**Analyst Tool:** Volatility 3 Framework 2.28.0

**Memory Image:** `Challenge.raw`

**Memory Image Size:** ~1.6 GB

**Operating System:** Windows 7 SP1 x64

**Profile:** `Win7SP1x64`

**Image Acquisition Time:** `2019-08-19 14:41:58 UTC`

The objective was to recover two hidden CTF flag fragments from a password-protected RAR archive discovered during memory analysis.

---

## 🎯 Objective

The investigation focused on:

1. Identifying the operating system and memory profile.
2. Enumerating processes present in the memory image.
3. Identifying suspicious or relevant processes.
4. Determining whether an archive had been opened.
5. Locating the archive in memory.
6. Extracting the archive from the memory image.
7. Recovering the archive password from volatile memory.
8. Extracting the hidden flag images.
9. Combining the recovered flag fragments.

---

## 🛠️ Tools Used

| Tool               | Purpose                                  |
| ------------------ | ---------------------------------------- |
| **Volatility 3**   | Memory forensics and artifact analysis   |
| **Volatility 2.6** | Initial process enumeration / comparison |
| **PowerShell**     | Running forensic commands                |
| **Python**         | Searching raw memory for strings         |
| **WinRAR**         | Extracting the recovered RAR archive     |

---

## 💻 Environment

The memory image was identified as:

```text
Windows 7 SP1 x64
```

The Volatility 3 `windows.info` plugin was used to verify the operating system and symbol information.

```powershell
..\vol.exe -f .\Challenge.raw windows.info
```

Important information recovered:

```text
Kernel Base: 0xf80002609000
DTB:         0x187000
NTBuildLab:  7601.17514.amd64fre.win7sp1_rtm
```

This confirmed the Windows 7 SP1 x64 environment.

---

# 🔍 Investigation Methodology

## 1. Process Enumeration

The following Volatility plugins were used:

```powershell
..\vol.exe -f .\Challenge.raw windows.pslist
```

```powershell
..\vol.exe -f .\Challenge.raw windows.psscan
```

```powershell
..\vol.exe -f .\Challenge.raw windows.pstree
```

These plugins were used to identify running processes, terminated processes, and parent-child process relationships.

A particularly relevant process was discovered:

```text
WinRAR.exe
PID: 3716
PPID: 1944
Created: 2019-08-19 14:41:43 UTC
```

The presence of `WinRAR.exe` provided an important lead because the investigation objective involved recovering a password-protected RAR archive.

---

## 2. Reviewing Process Command Lines

The `windows.cmdline` plugin was used to inspect process command-line arguments.

```powershell
..\vol.exe -f .\Challenge.raw windows.cmdline
```

The output was filtered for relevant keywords:

```powershell
..\vol.exe -f .\Challenge.raw windows.cmdline | findstr /i "rar flag password"
```

The investigation identified:

```text
3716 WinRAR.exe "C:\Program Files\WinRAR\WinRAR.exe"
"C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
```

This confirmed that `WinRAR.exe` had opened:

```text
C:\Users\Jaffa\Desktop\pr0t3ctd\flag.rar
```

This became the primary artifact for further investigation.

---

## 3. Locating `flag.rar` in Memory

The `windows.filescan` plugin was used to locate file objects referenced by the memory image.

```powershell
..\vol.exe -f .\Challenge.raw windows.filescan
```

The results were filtered for the target archive:

```powershell
..\vol.exe -f .\Challenge.raw windows.filescan | findstr /i "flag.rar"
```

The archive was located at:

```text
Virtual Address: 0x5fcfc4b0
```

---

## 4. Extracting the RAR Archive

After locating the file object, `windows.dumpfiles` was used to extract the archive directly from memory.

```powershell
..\vol.exe -f .\Challenge.raw windows.dumpfiles --virtaddr 0x5fcfc4b0
```

This allowed `flag.rar` to be carved from the memory image without accessing the original disk.

---

# 🔐 5. Recovering the RAR Password

The recovered archive was password protected.

Instead of brute-forcing the archive, the memory image was searched for strings that could contain the password.

The following string was discovered in memory:

```text
RAR password=easypeasyvirus
```

The password recovered from the WinRAR process environment data was:

```text
easypeasyvirus
```

This demonstrated how sensitive information such as passwords can remain available in volatile memory after being used by an application.

---

## 🐍 Memory String Search

Python was also used to search the raw memory image for relevant strings.

Example:

```python
from pathlib import Path
import re

b = Path(r'.\Challenge.raw').read_bytes()

m = re.search(
    b'Mega.{0,20}Drive.{0,20}Key',
    b,
    re.I
)

print('Offset:', m.start() if m else -1)

if m:
    print(
        b[m.start()-2000:m.start()+5000]
        .decode('utf-8', 'replace')
    )
```

The memory contained additional string data associated with the challenge.

---

# 📦 6. Extracting the Flags

Using the recovered password:

```text
easypeasyvirus
```

the RAR archive could be opened.

The archive contained two image files:

```text
flag1.png
flag2.png
```

### Flag 1

```text
inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_
```

### Flag 2

```text
aN_Am4zINg_!_i_gU3Ss???_}
```

The two fragments were combined in order to reconstruct the complete CTF flag.

---

# 🚩 Final Flag

```text
inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_aN_Am4zINg_!_i_gU3Ss???_}
```

---

# 📋 Investigation Summary

| Step | Plugin / Action           | Purpose                                   |
| ---- | ------------------------- | ----------------------------------------- |
| 1    | `windows.info`            | Identify OS build and memory profile      |
| 2    | `windows.pslist`          | Enumerate active processes                |
| 3    | `windows.psscan`          | Identify active/terminated processes      |
| 4    | `windows.pstree`          | Analyze process hierarchy                 |
| 5    | `windows.cmdline`         | Identify archive path and WinRAR activity |
| 6    | `windows.filescan`        | Locate `flag.rar` in memory               |
| 7    | `windows.dumpfiles`       | Extract `flag.rar`                        |
| 8    | Memory string search      | Recover the RAR password                  |
| 9    | Manual archive extraction | Extract `flag1.png` and `flag2.png`       |
| 10   | Visual inspection         | Recover and combine flag fragments        |

---

# 🧠 Key DFIR Concepts Demonstrated

This challenge provided practical experience with:

* Memory image analysis
* Windows process enumeration
* Process tree analysis
* Command-line artifact investigation
* File object discovery
* File carving from memory
* Volatile credential recovery
* Process environment analysis
* Raw memory string searching
* RAR archive extraction
* CTF flag reconstruction

---

# 🔎 Important Artifacts

### Memory Image

```text
Challenge.raw
```

### Relevant Process

```text
WinRAR.exe
PID: 3716
```

### Archive

```text
C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar
```

### Memory Address

```text
0x5fcfc4b0
```

### Recovered Password

```text
easypeasyvirus
```

### Extracted Files

```text
flag1.png
flag2.png
```

---

# 🛡️ DFIR Takeaways

This investigation demonstrates why volatile memory can be valuable during forensic investigations.

Even when sensitive information is not easily available from disk, applications may leave useful artifacts in memory, including:

* Process information
* Command-line arguments
* File references
* Passwords
* Environment variables
* Application artifacts
* User activity

In this case, the password for the protected archive was recovered from memory rather than through password brute-forcing.

The investigation therefore followed a memory-first forensic workflow:

```text
Memory Image
     │
     ▼
OS / Profile Identification
     │
     ▼
Process Enumeration
     │
     ▼
WinRAR.exe Identified
     │
     ▼
Command Line Analysis
     │
     ▼
flag.rar Located
     │
     ▼
File Object Located in Memory
     │
     ▼
flag.rar Carved
     │
     ▼
Password Recovered
     │
     ▼
Archive Extracted
     │
     ▼
flag1.png + flag2.png
     │
     ▼
Final CTF Flag
```

---

# 📚 Conclusion

The `Challenge_NotchItUp` investigation demonstrated a complete memory forensics workflow using a Windows 7 SP1 x64 memory capture.

Starting with OS identification and process enumeration, the investigation progressed to identifying `WinRAR.exe`, recovering the location of `flag.rar`, carving the archive from memory, recovering its password from volatile process data, and finally extracting and reconstructing the hidden CTF flag.

The entire investigation was performed using the volatile memory capture rather than interacting with a live disk image.

---

## 👩‍💻 Author

**Dnyaneshwari Kale**

DFIR | Memory Forensics | Cybersecurity | CTF

---

## ⚠️ Disclaimer

This project is intended for **educational, cybersecurity training, digital forensics, and CTF purposes**.

The commands and techniques demonstrated here should only be used on systems and memory images for which you have appropriate authorization.
