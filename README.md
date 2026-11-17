# SysPulse v1.0

**A "black box recorder" for Windows, written in C using the Win32 API.**

Task Manager shows what is happening *right now* and forgets everything the moment you close it. SysPulse keeps a record. It monitors the system continuously, detects abnormal behaviour, and when an incident happens it captures the evidence and names the likely culprit, so a slowdown can be diagnosed after it has already happened.

> Built for a hackathon as a hands-on project in core operating-system and process-management concepts.

---

## The problem

When a PC freezes, slows down, or runs out of memory, the usual questions are:

- What caused it?
- Was something slowly leaking memory for hours?
- Which process caused the CPU spike at 3 AM?

Task Manager cannot answer these, because it has no history. SysPulse is built to answer them.

## Features (v1.0)

| Feature | Description |
|---|---|
| Live dashboard | CPU, memory, all fixed drives, battery, and top processes with colour bars and history graphs |
| Per-process CPU % | Calculated from the change in kernel + user time between samples |
| System health score | A single 0-100 score with a grade (Excellent / Good / Degraded / Critical) |
| Anomaly detection | Rolling z-score flags unusual CPU spikes instead of relying only on fixed thresholds |
| Memory-leak detector | Flags a process whose working set keeps growing across consecutive samples |
| Memory forecast | Linear regression on recent samples gives a trend and a "full in ~N min" estimate |
| Incident recorder | On a trigger, saves the top 10 processes by CPU and memory and names the likely culprit |
| Interactive controls | Kill a process (with confirmation and protected PIDs), toggle sort, run built-in demo tools |
| Background mode | `--quiet` records with no dashboard, useful for overnight runs |
| Reports and logs | CSV metrics, event log, incident log, and an HTML report with graphs and root-cause analysis |

## How it works

| Task | Windows API | OS concept |
|---|---|---|
| System CPU % | `GetSystemTimes` | CPU time accounting |
| Per-process CPU % | `GetProcessTimes` | Process scheduling and CPU accounting |
| Memory usage | `GlobalMemoryStatusEx` | Physical and virtual memory |
| Per-process memory | `GetProcessMemoryInfo` (working set) | Memory management |
| Process list | `CreateToolhelp32Snapshot`, `Process32First/Next` | Process management |
| Disks | `GetLogicalDrives`, `GetDiskFreeSpaceExA` | File systems and storage |
| Kill a process | `OpenProcess`, `TerminateProcess` | Process control |
| Stress / leak demo | `CreateThread`, `VirtualAlloc` | Threads and virtual memory |
| Logging | `fopen`, `fprintf` | File I/O and diagnostics |

**Key formulas**

- System CPU % = (total time − idle time) ÷ total time, between two samples. Kernel time already includes idle time.
- Process CPU % = Δ(kernel + user time) ÷ (wall time × number of logical CPUs).
- Anomaly: flagged when the current CPU is at least 3 standard deviations above the recent average and at least 15 points higher.
- Leak suspect: working set grows for 10+ consecutive samples and by at least 20 MB in total.
- Health score = 100 minus penalties for high CPU, high memory, a nearly full disk, and suspected leaks.

Threshold alerts fire **once per episode** (not every second) so the logs stay readable.

## Build and run

Requirements: Windows 10/11 and a C compiler (MinGW-w64 / MSYS2 gcc, or Visual Studio `cl`).

```
gcc syspulse.c -o syspulse.exe -lpsapi
.\syspulse.exe
```

Background mode (no dashboard):

```
.\syspulse.exe --quiet
```

Press **Ctrl+C** to stop and generate the report. Use Windows Terminal or PowerShell for the colours and graph characters. Run as Administrator to read more system processes.

### Keys

| Key | Action |
|---|---|
| `Q` | Quit and write the report |
| `K` | Kill a process by PID (asks for confirmation) |
| `T` | Toggle process sorting between CPU and memory |
| `S` | 5-second CPU stress test (demo) |
| `M` | Memory-leak simulator, +4 MB per second (demo) |

## Quick demo

1. Run `.\syspulse.exe`.
2. Press `S` and watch the CPU graph spike and an anomaly event appear.
3. Press `M` and wait about 15 seconds until the leak is flagged.
4. Press `Q`, then open `syspulse_report.html` and `syspulse_incidents.log`.

## Output files

| File | Contents |
|---|---|
| `syspulse_metrics.csv` | One row per second: CPU, memory, worst disk, health score, process count |
| `syspulse_events.log` | Timestamped INFO / WARN / CRIT events |
| `syspulse_incidents.log` | Snapshot of top processes and likely culprit for each incident |
| `syspulse_report.html` | Session summary, graphs, incident root-cause table, event timeline |

## Screenshots

_Add screenshots here: dashboard, incident log, HTML report._

## Known limitations (v1.0)

- Windows only.
- Per-process memory is the **working set**, which is not the same as total committed memory.
- Some protected system processes cannot be opened without Administrator rights.
- The leak detector and anomaly detector are heuristics, so they can give false positives.
- Disk monitoring covers capacity only, not read/write activity.
- Thresholds are compile-time constants (no config file yet).

## Future scope

SysPulse v1.0 is intended as a foundation. Planned directions:

**Version 1.x (improvements to this tool)**
- Config file for thresholds, sample interval and log paths
- Log rotation and a retention policy
- Watchdog mode: restart a crashed process, or stop one that exceeds CPU/memory limits for N seconds
- Per-process disk and network I/O, and GPU usage
- Email or desktop notifications for critical incidents
- Run as a Windows service so it records from boot
- Unit tests for the statistics and scoring functions

**Version 2.0 (smarter diagnostics)**
- Learned per-process baselines instead of fixed thresholds
- Better forecasting (for example, exponential smoothing) for memory and disk exhaustion
- Event correlation, for example linking a CPU spike to a service restart or a new install
- Interactive HTML report with zoom and filtering

**Future projects built on this foundation**
- A **cross-platform monitor** with a Linux backend (`/proc`) behind the same interface
- A **lightweight monitoring agent** that sends metrics from many machines to a central dashboard
- A **resource-limit sandbox** that runs untrusted programs with enforced CPU/memory caps
- A **performance profiler** that records a program's resource usage across a test run
- Reusing the core (sampling, statistics, incident capture) as a **reusable C library** for other system tools

## What I learned

- How Windows exposes CPU, memory and process information through the Win32 API
- How CPU usage is derived from time counters, not read directly
- Process management, virtual memory and working sets
- Basic statistical anomaly detection and linear regression in C
- Diagnosing a real environment problem (Application Control blocking the compiler) and working around it

## Author

[Your Name] · Built for [Hackathon Name] · v1.0

## License

MIT (or your choice)