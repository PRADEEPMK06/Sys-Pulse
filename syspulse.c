#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include <time.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* ---------- configuration ---------- */
#define INTERVAL_MS   1000
#define HIST          120      /* samples kept for live graphs / statistics   */
#define SPARK_W       50
#define TOP_N         8
#define MAX_PROCS     2048
#define MAX_EV        500
#define MAX_SESS      43200    /* 12 hours of 1-second samples                */
#define MAX_DISKS     8

#define CPU_ALERT     85.0
#define MEM_ALERT     90.0
#define DISK_ALERT    90.0
#define LEAK_STREAK   10       /* consecutive growing samples                 */
#define LEAK_MB       20       /* minimum total growth in MB                  */

#define LOG_CSV       "syspulse_metrics.csv"
#define LOG_EVENTS    "syspulse_events.log"
#define REPORT_HTML   "syspulse_report.html"
#define LOG_INCIDENTS "syspulse_incidents.log"
#define MAX_INC       50
#define INC_COOLDOWN  15       /* seconds between automatic incident captures */

/* ---------- ANSI colours ---------- */
#define C_RST  "\x1b[0m"
#define C_DIM  "\x1b[90m"
#define C_RED  "\x1b[91m"
#define C_GRN  "\x1b[92m"
#define C_YEL  "\x1b[93m"
#define C_CYN  "\x1b[96m"
#define C_BLD  "\x1b[1m"
#define NL     "\x1b[K\n"

/* ---------- types ---------- */
typedef struct {
    DWORD  pid;
    char   name[64];
    double cpu;
    SIZE_T mem;
    DWORD  threads;
    int    leak;
} ProcInfo;

typedef struct {
    int       used, alive, fresh, flagged, streak;
    DWORD     pid;
    ULONGLONG created, cpuTime;
    SIZE_T    memPrev, streakStart;
    char      name[64];
} Track;

typedef struct { char root[4]; double pct, freeGB, totGB; } Disk;
typedef struct { char t[24]; char lvl[8]; char msg[120]; } Event;
typedef struct { char t[24]; char trigger[100]; char culprit[64]; DWORD pid; double cpu, memMB; char top3[200]; } Incident;

/* ---------- globals ---------- */
static volatile int running = 1;
static DWORD   ncpu = 1;
static int     sortByCpu = 0;
static FILE   *evf = NULL, *csvf = NULL, *incf = NULL;
static Incident incs[MAX_INC]; static int nInc = 0, incCool = 0;
static DWORD   leakNewPid = 0;
static ProcInfo tmpP[MAX_PROCS];

static Track   tr[MAX_PROCS];
static ProcInfo procs[MAX_PROCS];
static int     nProcs = 0;

static Event   allEv[MAX_EV];
static int     nEv = 0;

static double  cpuH[HIST], memH[HIST];
static int     nH = 0;

static float   sCpu[MAX_SESS], sMem[MAX_SESS], sScore[MAX_SESS];
static int     sN = 0;

static double  peakCpu = 0; static char peakCpuName[64] = "-";
static double  cpuSum = 0, memSum = 0, cpuMax = 0, memMax = 0; static int minScore = 100;
static ULONGLONG startTick;

static void *leakChunks[100]; static int nLeak = 0, leakOn = 0;

/* ---------- output buffer (one write per frame = no flicker) ---------- */
static char ob[32768]; static int ol = 0;
static void out(const char *f, ...) {
    va_list a; va_start(a, f);
    int n = vsnprintf(ob + ol, sizeof ob - ol, f, a);
    va_end(a);
    if (n > 0) { ol += n; if (ol >= (int)sizeof ob) ol = (int)sizeof ob - 1; }
}

/* ---------- helpers ---------- */
static ULONGLONG ft2u(FILETIME f) {
    ULARGE_INTEGER u; u.LowPart = f.dwLowDateTime; u.HighPart = f.dwHighDateTime; return u.QuadPart;
}
static void stamp(char *b, size_t n) {
    time_t t = time(NULL); struct tm *tm = localtime(&t);
    strftime(b, n, "%Y-%m-%d %H:%M:%S", tm);
}
static const char *pctColor(double p) { return p < 60 ? C_GRN : (p < 85 ? C_YEL : C_RED); }
static void fmtDur(ULONGLONG sec, char *b, size_t n) {
    unsigned long d = (unsigned long)(sec / 86400), h = (unsigned long)(sec % 86400 / 3600);
    unsigned long m = (unsigned long)(sec % 3600 / 60), s = (unsigned long)(sec % 60);
    if (d) snprintf(b, n, "%lud %luh %lum", d, h, m);
    else   snprintf(b, n, "%02lu:%02lu:%02lu", h, m, s);
}

static void addEvent(const char *lvl, const char *fmt, ...) {
    Event e; stamp(e.t, sizeof e.t);
    strncpy(e.lvl, lvl, 7); e.lvl[7] = 0;
    va_list a; va_start(a, fmt); vsnprintf(e.msg, sizeof e.msg, fmt, a); va_end(a);
    if (nEv < MAX_EV) allEv[nEv++] = e;
    else { memmove(allEv, allEv + 1, sizeof(Event) * (MAX_EV - 1)); allEv[MAX_EV - 1] = e; }
    if (evf) { fprintf(evf, "[%s] [%s] %s\n", e.t, e.lvl, e.msg); fflush(evf); }
}

static void push(double *h, int *n, double v) {
    if (*n == HIST) { memmove(h, h + 1, (HIST - 1) * sizeof *h); (*n)--; }
    h[(*n)++] = v;
}

/* ---------- metrics ---------- */
static double getCpu(void) {
    static ULONGLONG pI = 0, pK = 0, pU = 0;
    FILETIME i, k, u; GetSystemTimes(&i, &k, &u);
    ULONGLONG I = ft2u(i), K = ft2u(k), U = ft2u(u);
    ULONGLONG dI = I - pI, dT = (K - pK) + (U - pU);   /* kernel time includes idle */
    pI = I; pK = K; pU = U;
    return dT ? (double)(dT - dI) * 100.0 / (double)dT : 0.0;
}

static double getMem(double *usedMB, double *totMB) {
    MEMORYSTATUSEX m; m.dwLength = sizeof m; GlobalMemoryStatusEx(&m);
    *totMB  = m.ullTotalPhys / 1048576.0;
    *usedMB = (m.ullTotalPhys - m.ullAvailPhys) / 1048576.0;
    return (double)m.dwMemoryLoad;
}

static int getDisks(Disk *d) {
    int n = 0; DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26 && n < MAX_DISKS; i++) {
        if (!(mask & (1u << i))) continue;
        char root[4] = { (char)('A' + i), ':', '\\', 0 };
        if (GetDriveTypeA(root) != DRIVE_FIXED) continue;
        ULARGE_INTEGER fr, tot, tf;
        if (!GetDiskFreeSpaceExA(root, &fr, &tot, &tf) || tot.QuadPart == 0) continue;
        strcpy(d[n].root, root);
        d[n].freeGB = fr.QuadPart / 1073741824.0;
        d[n].totGB  = tot.QuadPart / 1073741824.0;
        d[n].pct    = 100.0 * (1.0 - (double)fr.QuadPart / (double)tot.QuadPart);
        n++;
    }
    return n;
}

/* least-squares slope of h[0..n-1], in units per sample */
static double slope(const double *h, int n) {
    if (n < 10) return 0;
    double sx = 0, sy = 0, sxy = 0, sxx = 0;
    for (int i = 0; i < n; i++) { sx += i; sy += h[i]; sxy += i * h[i]; sxx += (double)i * i; }
    double den = n * sxx - sx * sx;
    return den == 0 ? 0 : (n * sxy - sx * sy) / den;
}

/* ---------- process tracking (per-process CPU + leak detection) ---------- */
static Track *findTrack(DWORD pid, ULONGLONG created) {
    int freeIdx = -1;
    for (int i = 0; i < MAX_PROCS; i++) {
        if (tr[i].used) { if (tr[i].pid == pid && tr[i].created == created) return &tr[i]; }
        else if (freeIdx < 0) freeIdx = i;
    }
    if (freeIdx < 0) return NULL;
    memset(&tr[freeIdx], 0, sizeof(Track));
    tr[freeIdx].used = 1; tr[freeIdx].fresh = 1;
    tr[freeIdx].pid = pid; tr[freeIdx].created = created;
    return &tr[freeIdx];
}

static int sampleProcs(ULONGLONG dtMs) {
    for (int i = 0; i < MAX_PROCS; i++) tr[i].alive = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof pe; int n = 0;

    if (Process32First(s, &pe)) do {
        if (n >= MAX_PROCS) break;
        ProcInfo *p = &procs[n]; memset(p, 0, sizeof *p);
        p->pid = pe.th32ProcessID; p->threads = pe.cntThreads;
        strncpy(p->name, pe.szExeFile, sizeof p->name - 1);

        ULONGLONG created = 0, cpuT = 0; int ok = 0;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (h) {
            FILETIME c, e, k, u; PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessTimes(h, &c, &e, &k, &u)) { created = ft2u(c); cpuT = ft2u(k) + ft2u(u); ok = 1; }
            if (GetProcessMemoryInfo(h, &pmc, sizeof pmc)) p->mem = pmc.WorkingSetSize;
            CloseHandle(h);
        }

        Track *t = findTrack(p->pid, created);
        if (t) {
            t->alive = 1; strncpy(t->name, p->name, sizeof t->name - 1);
            if (!t->fresh) {
                if (ok && dtMs > 0 && cpuT >= t->cpuTime) {
                    p->cpu = (double)(cpuT - t->cpuTime) / ((double)dtMs * 10000.0 * ncpu) * 100.0;
                    if (p->cpu > 100) p->cpu = 100;
                }
                if (p->mem > 0) {                           /* leak heuristic */
                    if (p->mem > t->memPrev + 65536) {
                        if (t->streak == 0) t->streakStart = t->memPrev;
                        t->streak++;
                    } else if (p->mem + 65536 < t->memPrev) { t->streak = 0; t->flagged = 0; }
                    if (t->streak >= LEAK_STREAK && p->mem > t->streakStart &&
                        p->mem - t->streakStart >= (SIZE_T)LEAK_MB * 1048576) {
                        p->leak = 1;
                        if (!t->flagged) {
                            t->flagged = 1; leakNewPid = p->pid;
                            addEvent("WARN", "Possible memory leak: %s (PID %lu) grew +%.0f MB in %d s",
                                     p->name, p->pid, (p->mem - t->streakStart) / 1048576.0, t->streak);
                        }
                    }
                }
            }
            t->fresh = 0; t->cpuTime = cpuT; t->memPrev = p->mem;
        }
        if (p->pid != 0 && p->cpu > peakCpu) { peakCpu = p->cpu; strncpy(peakCpuName, p->name, 63); }
        n++;
    } while (Process32Next(s, &pe));
    CloseHandle(s);
    for (int i = 0; i < MAX_PROCS; i++) if (tr[i].used && !tr[i].alive) tr[i].used = 0;
    return n;
}

static int cmpProc(const void *a, const void *b) {
    const ProcInfo *x = a, *y = b;
    if (sortByCpu) return (y->cpu > x->cpu) - (y->cpu < x->cpu);
    return (y->mem > x->mem) - (y->mem < x->mem);
}

/* ---------- incident recorder ("black box") ---------- */
static int cmpCpuD(const void *a, const void *b) {
    const ProcInfo *x = a, *y = b; return (y->cpu > x->cpu) - (y->cpu < x->cpu);
}
static int cmpMemD(const void *a, const void *b) {
    const ProcInfo *x = a, *y = b; return (y->mem > x->mem) - (y->mem < x->mem);
}
/* mode 0 = CPU incident, 1 = memory incident, 2 = leak (culprit = leakPid) */
static void recordIncident(const char *trigger, int mode, DWORD leakPid) {
    if (nInc >= MAX_INC || (mode != 2 && incCool > 0)) return;
    int n = 0;
    for (int i = 0; i < nProcs; i++) if (procs[i].pid != 0) tmpP[n++] = procs[i];
    if (n == 0) return;

    qsort(tmpP, n, sizeof(ProcInfo), mode == 0 ? cmpCpuD : cmpMemD);
    ProcInfo c = tmpP[0];
    if (mode == 2) for (int i = 0; i < n; i++) if (tmpP[i].pid == leakPid) c = tmpP[i];

    Incident *in = &incs[nInc];
    stamp(in->t, sizeof in->t);
    snprintf(in->trigger, sizeof in->trigger, "%s", trigger);
    snprintf(in->culprit, sizeof in->culprit, "%s", c.name);
    in->pid = c.pid; in->cpu = c.cpu; in->memMB = c.mem / 1048576.0;
    in->top3[0] = 0;
    for (int i = 0; i < 3 && i < n; i++) {
        char part[64]; snprintf(part, sizeof part, "%s%s (%.0f%%, %.0f MB)", i ? "; " : "", tmpP[i].name,
                                tmpP[i].cpu, tmpP[i].mem / 1048576.0);
        strncat(in->top3, part, sizeof in->top3 - strlen(in->top3) - 1);
    }
    nInc++; if (mode != 2) incCool = INC_COOLDOWN;

    if (incf) {
        fprintf(incf, "==== INCIDENT #%d  %s ====\nTrigger     : %s\nLikely cause: %s (PID %lu)  CPU %.1f%%  MEM %.0f MB\n",
                nInc, in->t, trigger, c.name, c.pid, c.cpu, c.mem / 1048576.0);
        fputs("-- Top 10 by CPU --\n", incf);
        qsort(tmpP, n, sizeof(ProcInfo), cmpCpuD);
        for (int i = 0; i < 10 && i < n; i++)
            fprintf(incf, "  %-7lu %-28s %5.1f%%  %8.1f MB\n", tmpP[i].pid, tmpP[i].name, tmpP[i].cpu, tmpP[i].mem / 1048576.0);
        fputs("-- Top 10 by memory --\n", incf);
        qsort(tmpP, n, sizeof(ProcInfo), cmpMemD);
        for (int i = 0; i < 10 && i < n; i++)
            fprintf(incf, "  %-7lu %-28s %5.1f%%  %8.1f MB\n", tmpP[i].pid, tmpP[i].name, tmpP[i].cpu, tmpP[i].mem / 1048576.0);
        fputs("\n", incf); fflush(incf);
    }
    addEvent("INFO", "Incident #%d captured - likely cause: %s (PID %lu)", nInc, c.name, c.pid);
}

/* ---------- health score ---------- */
static int healthScore(double cpu, double mem, double worstDisk, int leaks) {
    double s = 100.0;
    if (cpu > 50)       s -= (cpu - 50) * 0.6;
    if (mem > 60)       s -= (mem - 60) * 1.0;
    if (worstDisk > 80) s -= (worstDisk - 80) * 1.5;
    s -= leaks * 5.0;
    if (s < 0) s = 0;
    return (int)(s + 0.5);
}
static const char *gradeText(int s, const char **col) {
    if (s >= 85) { *col = C_GRN; return "EXCELLENT"; }
    if (s >= 65) { *col = C_GRN; return "GOOD"; }
    if (s >= 40) { *col = C_YEL; return "DEGRADED"; }
    *col = C_RED; return "CRITICAL";
}

/* ---------- drawing ---------- */
static void bar(double p, int w) {
    int f = (int)(p / 100.0 * w + 0.5), i;
    if (f > w) f = w;
    if (f < 0) f = 0;
    out("%s", pctColor(p));
    for (i = 0; i < f; i++) out("\xe2\x96\x88");
    out("%s", C_DIM);
    for (; i < w; i++) out("\xe2\x96\x91");
    out("%s", C_RST);
}
static void spark(const double *h, int n, int w, double maxv) {
    static const char *SP[8] = { "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
                                 "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88" };
    int s = n > w ? n - w : 0;
    for (int i = s; i < n; i++) {
        int l = (int)(h[i] / maxv * 7.999);
        if (l < 0) l = 0;
        if (l > 7) l = 7;
        out("%s", SP[l]);
    }
}

static void render(double cpu, double mem, double usedMB, double totMB,
                   Disk *d, int nd, int score, double memSlopeMin) {
    char ses[32], up[32]; const char *gc;
    fmtDur((GetTickCount64() - startTick) / 1000, ses, sizeof ses);
    fmtDur(GetTickCount64() / 1000, up, sizeof up);
    const char *grade = gradeText(score, &gc);

    ol = 0; out("\x1b[H");
    out(C_BLD C_CYN " SysPulse v1.0" C_RST C_DIM "  Intelligent System Monitor      session %s  |  uptime %s  |  %lu CPUs" C_RST NL,
        ses, up, ncpu);
    out(C_DIM " ---------------------------------------------------------------------------------" C_RST NL);

    out(" HEALTH  "); bar(score, 30);
    out(" %s%s%3d/100  %s" C_RST, gc, C_BLD, score, grade);
    SYSTEM_POWER_STATUS ps;
    if (GetSystemPowerStatus(&ps) && ps.BatteryLifePercent != 255)
        out(C_DIM "     battery %d%% %s" C_RST, ps.BatteryLifePercent, ps.ACLineStatus == 1 ? "(AC)" : "");
    out(NL NL);

    out(" CPU     "); bar(cpu, 30); out(" %5.1f%%  ", cpu); spark(cpuH, nH, SPARK_W, 100); out(NL);
    out(" MEMORY  "); bar(mem, 30); out(" %5.1f%%  ", mem); spark(memH, nH, SPARK_W, 100); out(NL);
    out(C_DIM "         %.0f / %.0f MB used   trend: " C_RST, usedMB, totMB);
    if (fabs(memSlopeMin) < 0.05) out(C_GRN "stable" C_RST);
    else if (memSlopeMin > 0) {
        out(C_YEL "rising +%.2f %%/min" C_RST, memSlopeMin);
        double eta = (100.0 - mem) / memSlopeMin;
        if (eta < 600) out(C_RED "  (full in ~%.0f min)" C_RST, eta);
    } else out(C_GRN "falling %.2f %%/min" C_RST, memSlopeMin);
    out(NL);
    for (int i = 0; i < nd; i++) {
        out(" DISK %s  ", d[i].root); bar(d[i].pct, 30);
        out(" %5.1f%%  " C_DIM "%.1f GB free of %.1f GB" C_RST NL, d[i].pct, d[i].freeGB, d[i].totGB);
    }
    out(NL);

    out(C_BLD " PROCESSES (%d)" C_RST C_DIM "  sorted by %s" C_RST NL, nProcs, sortByCpu ? "CPU" : "MEMORY");
    out(C_DIM " %-7s %-26s %7s %10s %5s" C_RST NL, "PID", "NAME", "CPU%", "MEM (MB)", "THR");
    DWORD self = GetCurrentProcessId();
    for (int i = 0; i < TOP_N && i < nProcs; i++) {
        ProcInfo *p = &procs[i];
        out(" %-7lu %-26.26s %s%6.1f%%" C_RST " %10.1f %5lu", p->pid, p->name,
            p->cpu > 50 ? C_RED : (p->cpu > 15 ? C_YEL : C_GRN), p->cpu, p->mem / 1048576.0, p->threads);
        if (p->leak) out(C_RED "  << LEAK SUSPECT" C_RST);
        else if (p->pid == self) out(C_CYN "  (this program)" C_RST);
        out(NL);
    }
    out(NL);

    out(C_BLD " RECENT EVENTS" C_RST NL);
    int start = nEv > 6 ? nEv - 6 : 0;
    for (int i = start; i < nEv; i++) {
        const char *c = !strcmp(allEv[i].lvl, "WARN") ? C_YEL : (!strcmp(allEv[i].lvl, "CRIT") ? C_RED : C_CYN);
        out(" " C_DIM "%s" C_RST " %s%-4s" C_RST " %.90s" NL, allEv[i].t + 11, c, allEv[i].lvl, allEv[i].msg);
    }
    for (int i = nEv - start; i < 6; i++) out(NL);
    out(NL C_DIM " [Q] quit  [K] kill process  [T] toggle sort  [S] CPU stress test  [M] memory-leak simulator %s" C_RST NL,
        leakOn ? "(ON)" : "");
    out("\x1b[J");
    fwrite(ob, 1, ol, stdout); fflush(stdout);
}

/* ---------- demo tools: stress test + leak simulator ---------- */
static DWORD WINAPI burn(LPVOID p) {
    (void)p; ULONGLONG end = GetTickCount64() + 5000; volatile unsigned long x = 0;
    while (GetTickCount64() < end) x++;
    return 0;
}
static void startStress(void) {
    for (DWORD i = 0; i < ncpu; i++) { HANDLE h = CreateThread(NULL, 0, burn, NULL, 0, NULL); if (h) CloseHandle(h); }
    addEvent("INFO", "CPU stress test started (%lu threads, 5 s)", ncpu);
}
static void toggleLeak(void) {
    leakOn = !leakOn;
    if (!leakOn) {
        for (int i = 0; i < nLeak; i++) VirtualFree(leakChunks[i], 0, MEM_RELEASE);
        nLeak = 0; addEvent("INFO", "Leak simulator stopped, memory released");
    } else addEvent("INFO", "Leak simulator started (+4 MB per second)");
}
static void leakTick(void) {
    if (!leakOn || nLeak >= 100) return;
    void *m = VirtualAlloc(NULL, 4u << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (m) { memset(m, 0xAB, 4u << 20); leakChunks[nLeak++] = m; }
}

/* ---------- kill process ---------- */
static void killPrompt(void) {
    char line[64], name[64] = "?";
    printf("\x1b[?25h\x1b[2J\x1b[H\n Enter PID to terminate (blank to cancel): "); fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) goto done;
    DWORD pid = strtoul(line, NULL, 10);
    if (pid == 0) goto done;
    if (pid <= 4 || pid == GetCurrentProcessId()) { printf(" Refusing: protected PID.\n"); Sleep(1200); goto done; }
    for (int i = 0; i < nProcs; i++) if (procs[i].pid == pid) strncpy(name, procs[i].name, 63);
    printf(" Terminate %s (PID %lu)? [y/N]: ", name, pid); fflush(stdout);
    if (!fgets(line, sizeof line, stdin) || (line[0] != 'y' && line[0] != 'Y')) goto done;
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h && TerminateProcess(h, 1)) { addEvent("WARN", "User terminated %s (PID %lu)", name, pid); printf(" Terminated.\n"); }
    else { printf(" Failed (error %lu). Try running as Administrator.\n", GetLastError()); addEvent("INFO", "Kill failed for PID %lu", pid); }
    if (h) CloseHandle(h);
    Sleep(1200);
done:
    printf("\x1b[2J\x1b[?25l");
}

/* ---------- HTML diagnostic report ---------- */
static void poly(FILE *f, const float *v, int n, const char *color) {
    int step = n / 780 + 1;
    fprintf(f, "<polyline fill='none' stroke='%s' stroke-width='1.5' points='", color);
    for (int i = 0; i < n; i += step)
        fprintf(f, "%.1f,%.1f ", 10 + (n > 1 ? (double)i / (n - 1) * 780 : 0), 190 - v[i] * 1.8);
    fputs("'/>\n", f);
}

static void writeReport(void) {
    FILE *f = fopen(REPORT_HTML, "w"); if (!f) return;
    char ts[24], dur[32]; stamp(ts, sizeof ts);
    fmtDur((GetTickCount64() - startTick) / 1000, dur, sizeof dur);
    double avgC = sN ? cpuSum / sN : 0, avgM = sN ? memSum / sN : 0;

    fputs("<!doctype html><html><head><meta charset='utf-8'><title>SysPulse Report</title><style>"
          "body{font-family:Segoe UI,Arial,sans-serif;background:#0f1419;color:#e6e6e6;margin:0;padding:28px}"
          "h1{color:#4fd1c5;margin:0 0 4px}h2{color:#90cdf4;margin-top:28px}.sub{color:#8a94a0}"
          ".cards{display:flex;gap:14px;flex-wrap:wrap;margin-top:18px}"
          ".card{background:#1a2129;border-radius:10px;padding:14px 20px;min-width:140px}"
          ".card b{display:block;font-size:26px;color:#fff}.card span{color:#8a94a0;font-size:13px}"
          "svg{background:#1a2129;border-radius:10px}table{border-collapse:collapse;width:100%;background:#1a2129;border-radius:10px}"
          "td,th{padding:7px 12px;text-align:left;border-bottom:1px solid #252e38;font-size:14px}"
          ".WARN{color:#f6e05e}.INFO{color:#76e4f7}.CRIT{color:#fc8181}</style></head><body>", f);
    fprintf(f, "<h1>SysPulse Diagnostic Report</h1><div class='sub'>Generated %s &middot; session length %s &middot; %d samples &middot; %lu logical CPUs</div>",
            ts, dur, sN, ncpu);
    fputs("<div class='cards'>", f);
    fprintf(f, "<div class='card'><b>%.1f%%</b><span>avg CPU</span></div>", avgC);
    fprintf(f, "<div class='card'><b>%.1f%%</b><span>peak CPU</span></div>", cpuMax);
    fprintf(f, "<div class='card'><b>%.1f%%</b><span>avg memory</span></div>", avgM);
    fprintf(f, "<div class='card'><b>%.1f%%</b><span>peak memory</span></div>", memMax);
    fprintf(f, "<div class='card'><b>%d</b><span>lowest health score</span></div>", minScore);
    fprintf(f, "<div class='card'><b>%s</b><span>busiest process (%.0f%% CPU)</span></div>", peakCpuName, peakCpu);
    fputs("</div><h2>CPU (cyan) and Memory (orange) over the session</h2>"
          "<svg width='800' height='200' viewBox='0 0 800 200'>"
          "<line x1='10' y1='10' x2='790' y2='10' stroke='#333'/><line x1='10' y1='100' x2='790' y2='100' stroke='#333'/>"
          "<line x1='10' y1='190' x2='790' y2='190' stroke='#555'/>", f);
    if (sN > 1) { poly(f, sCpu, sN, "#4fd1c5"); poly(f, sMem, sN, "#f6ad55"); }
    fputs("</svg><div class='sub'>Gridlines: 100% / 50% / 0%</div>", f);

    fputs("<h2>Health score over the session</h2><svg width='800' height='200' viewBox='0 0 800 200'>"
          "<line x1='10' y1='190' x2='790' y2='190' stroke='#555'/>", f);
    if (sN > 1) poly(f, sScore, sN, "#9ae6b4");
    fputs("</svg>", f);

    fputs("<h2>Top processes by memory (at shutdown)</h2><table><tr><th>PID</th><th>Name</th><th>CPU %</th><th>Memory (MB)</th></tr>", f);
    sortByCpu = 0; qsort(procs, nProcs, sizeof(ProcInfo), cmpProc);
    for (int i = 0; i < 10 && i < nProcs; i++)
        fprintf(f, "<tr><td>%lu</td><td>%s</td><td>%.1f</td><td>%.1f</td></tr>", procs[i].pid, procs[i].name, procs[i].cpu, procs[i].mem / 1048576.0);
    fputs("</table><h2>Incidents &amp; root-cause analysis</h2>", f);
    if (nInc == 0) fputs("<p class='sub'>No incidents recorded. The system stayed healthy during this session.</p>", f);
    else {
        fputs("<table><tr><th>#</th><th>Time</th><th>Trigger</th><th>Likely cause</th><th>Top processes at that moment</th></tr>", f);
        for (int i = 0; i < nInc; i++)
            fprintf(f, "<tr><td>%d</td><td>%s</td><td>%s</td><td><b>%s</b> (PID %lu, %.0f%% CPU, %.0f MB)</td><td>%s</td></tr>",
                    i + 1, incs[i].t, incs[i].trigger, incs[i].culprit, incs[i].pid, incs[i].cpu, incs[i].memMB, incs[i].top3);
        fputs("</table>", f);
    }
    fputs("<h2>Event timeline</h2><table><tr><th>Time</th><th>Level</th><th>Message</th></tr>", f);
    for (int i = 0; i < nEv; i++)
        fprintf(f, "<tr><td>%s</td><td class='%s'>%s</td><td>%s</td></tr>", allEv[i].t, allEv[i].lvl, allEv[i].lvl, allEv[i].msg);
    fputs("</table><p class='sub'>Generated by SysPulse v1.0</p></body></html>", f);
    fclose(f);
}

/* ---------- control ---------- */
static BOOL WINAPI onExit(DWORD sig) { (void)sig; running = 0; return TRUE; }

static void handleKey(int c) {
    switch (c) {
        case 'q': case 'Q': running = 0; break;
        case 'k': case 'K': killPrompt(); break;
        case 't': case 'T': sortByCpu = !sortByCpu; break;
        case 's': case 'S': startStress(); break;
        case 'm': case 'M': toggleLeak(); break;
    }
}

int main(int argc, char **argv) {
    int quiet = (argc > 1 && !strcmp(argv[1], "--quiet"));
    SetConsoleOutputCP(CP_UTF8);
    HANDLE ho = GetStdHandle(STD_OUTPUT_HANDLE); DWORD mode = 0;
    if (GetConsoleMode(ho, &mode)) SetConsoleMode(ho, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleCtrlHandler(onExit, TRUE);

    SYSTEM_INFO si; GetSystemInfo(&si); ncpu = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;

    evf = fopen(LOG_EVENTS, "a");
    incf = fopen(LOG_INCIDENTS, "a");
    int newCsv = 1; { FILE *t = fopen(LOG_CSV, "r"); if (t) { newCsv = 0; fclose(t); } }
    csvf = fopen(LOG_CSV, "a");
    if (csvf && newCsv) { fputs("timestamp,cpu_pct,mem_pct,worst_disk_pct,health_score,processes\n", csvf); fflush(csvf); }

    startTick = GetTickCount64();
    addEvent("INFO", "SysPulse v1.0 started (%lu logical CPUs)", ncpu);
    getCpu(); ULONGLONG last = GetTickCount64(); Sleep(INTERVAL_MS);
    if (quiet) printf("SysPulse recording in background mode (no dashboard). Press Ctrl+C to stop and build the report.\n");
    else printf("\x1b[2J\x1b[?25l");

    int cpuHi = 0, memHi = 0, diskHi = 0, cooldown = 0;

    while (running) {
        ULONGLONG now = GetTickCount64(), dt = now - last; last = now;
        leakTick();
        if (incCool > 0) incCool--;

        double cpu = getCpu(), usedMB, totMB, mem = getMem(&usedMB, &totMB);
        Disk disks[MAX_DISKS]; int nd = getDisks(disks); double worst = 0;
        for (int i = 0; i < nd; i++) if (disks[i].pct > worst) worst = disks[i].pct;

        nProcs = sampleProcs(dt);
        qsort(procs, nProcs, sizeof(ProcInfo), cmpProc);
        int leaks = 0; for (int i = 0; i < nProcs; i++) leaks += procs[i].leak;
        if (leakNewPid) { recordIncident("Memory leak suspected", 2, leakNewPid); leakNewPid = 0; }

        /* anomaly detection: rolling z-score on prior CPU samples */
        if (cooldown > 0) cooldown--;
        if (nH >= 15 && cooldown == 0) {
            double m = 0, v = 0; for (int i = 0; i < nH; i++) m += cpuH[i]; m /= nH;
            for (int i = 0; i < nH; i++) v += (cpuH[i] - m) * (cpuH[i] - m);
            double sd = sqrt(v / nH); if (sd < 2.0) sd = 2.0;
            double z = (cpu - m) / sd;
            if (z >= 3.0 && cpu - m >= 15.0) {
                char tg[100]; snprintf(tg, sizeof tg, "CPU anomaly: %.1f%% vs avg %.1f%% (z=%.1f)", cpu, m, z);
                addEvent("WARN", "%s", tg); recordIncident(tg, 0, 0);
                cooldown = 10;
            }
        }

        /* threshold alerts fire once per episode, not every sample */
        if (cpu > CPU_ALERT && !cpuHi)  { cpuHi = 1;  addEvent("WARN", "High CPU usage: %.1f%%", cpu);
        { char tg[100]; snprintf(tg, sizeof tg, "High CPU usage: %.1f%%", cpu); recordIncident(tg, 0, 0); } }
        else if (cpu < CPU_ALERT - 10 && cpuHi) { cpuHi = 0; addEvent("INFO", "CPU back to normal (%.1f%%)", cpu); }
        if (mem > MEM_ALERT && !memHi)  { memHi = 1;  addEvent("CRIT", "High memory usage: %.1f%%", mem);
        { char tg[100]; snprintf(tg, sizeof tg, "High memory usage: %.1f%%", mem); recordIncident(tg, 1, 0); } }
        else if (mem < MEM_ALERT - 5 && memHi) { memHi = 0; addEvent("INFO", "Memory back to normal (%.1f%%)", mem); }
        if (worst > DISK_ALERT && !diskHi) { diskHi = 1; addEvent("WARN", "Disk almost full: %.1f%%", worst); }
        else if (worst < DISK_ALERT - 2 && diskHi) diskHi = 0;

        { int n2 = nH; push(memH, &n2, mem); push(cpuH, &nH, cpu); }   /* both arrays share one length */
        double memSlopeMin = slope(memH, nH) * 60.0 * 1000.0 / INTERVAL_MS;
        int score = healthScore(cpu, mem, worst, leaks);

        /* session statistics and CSV */
        if (sN < MAX_SESS) { sCpu[sN] = (float)cpu; sMem[sN] = (float)mem; sScore[sN] = (float)score; sN++; }
        cpuSum += cpu; memSum += mem;
        if (cpu > cpuMax) cpuMax = cpu;
        if (mem > memMax) memMax = mem;
        if (score < minScore) minScore = score;
        if (csvf) {
            char ts[24]; stamp(ts, sizeof ts);
            fprintf(csvf, "%s,%.1f,%.1f,%.1f,%d,%d\n", ts, cpu, mem, worst, score, nProcs); fflush(csvf);
        }

        if (!quiet) render(cpu, mem, usedMB, totMB, disks, nd, score, memSlopeMin);

        ULONGLONG next = GetTickCount64() + INTERVAL_MS;
        while (running && GetTickCount64() < next) {
            if (!quiet && _kbhit()) handleKey(_getch());
            Sleep(30);
        }
    }

    if (leakOn) toggleLeak();   /* release simulated leak if still on */
    addEvent("INFO", "SysPulse stopped after %d samples", sN);
    writeReport();
    if (!quiet) printf("\x1b[?25h\x1b[2J\x1b[H");
    printf("SysPulse stopped.\n  Samples : %d\n  Avg CPU : %.1f%%   Peak CPU : %.1f%%\n  Avg Mem : %.1f%%   Peak Mem : %.1f%%\n",
           sN, sN ? cpuSum / sN : 0, cpuMax, sN ? memSum / sN : 0, memMax);
    printf("  Incidents captured: %d\n  Files   : %s, %s, %s, %s\n", nInc, LOG_CSV, LOG_EVENTS, LOG_INCIDENTS, REPORT_HTML);
    if (evf) fclose(evf);
    if (incf) fclose(incf);
    if (csvf) fclose(csvf);
    return 0;
}