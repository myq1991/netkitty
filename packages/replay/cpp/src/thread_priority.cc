#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 // for cpu_set_t / sched_setaffinity on glibc (must precede any system header)
#endif
#include "thread_priority.h"

#if defined(_WIN32)
#include <windows.h>
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")

const char *NkBoostSendThread(bool realtime)
{
    // 1ms timer resolution makes short Sleep()/wait granularity accurate (default is ~15.6ms).
    timeBeginPeriod(1);
    SetThreadPriority(GetCurrentThread(),
                      realtime ? THREAD_PRIORITY_TIME_CRITICAL : THREAD_PRIORITY_HIGHEST);
    return realtime ? "win:time-critical+1ms" : "win:highest+1ms";
}
void NkUnboostSendThread() { timeEndPeriod(1); }
bool NkPinThread(int cpu)
{
    if (cpu == NK_CPU_NONE) return false;
    DWORD_PTR mask;
    if (cpu == NK_CPU_AUTO)
    {
        //Auto: highest allowed core in the process affinity mask (respects any prior limit, skips core 0).
        DWORD_PTR procMask = 0, sysMask = 0;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask) || procMask == 0) return false;
        int hi = -1;
        for (int i = (int)(sizeof(DWORD_PTR) * 8) - 1; i >= 0; i--)
        {
            if (procMask & ((DWORD_PTR)1 << i)) { hi = i; break; }
        }
        if (hi < 0) return false;
        mask = (DWORD_PTR)1 << hi;
    }
    else
    {
        mask = (DWORD_PTR)1 << cpu;
    }
    return SetThreadAffinityMask(GetCurrentThread(), mask) != 0;
}

#elif defined(__APPLE__)
#include <pthread/qos.h>

const char *NkBoostSendThread(bool realtime)
{
    // macOS has no unprivileged SCHED_FIFO; the highest QoS class is the practical ceiling and needs
    // no special rights. (A mach time-constraint policy could go further but is fragile.)
    (void)realtime;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    return "mac:qos-user-interactive";
}
void NkUnboostSendThread() {}
bool NkPinThread(int)
{
    //macOS has no real per-core pinning (THREAD_AFFINITY_POLICY is advisory and a no-op on Apple Silicon).
    return false;
}

#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>

const char *NkBoostSendThread(bool realtime)
{
    if (realtime)
    {
        // Real-time FIFO scheduling (needs CAP_SYS_NICE or root). Mid-range priority so we don't
        // outrank critical kernel threads.
        struct sched_param sp;
        sp.sched_priority = 10;
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) == 0) return "posix:sched-fifo";
    }
    // Safe fallback: a negative nice value (best-effort; may still need privileges below 0).
    if (setpriority(PRIO_PROCESS, 0, -10) == 0) return "posix:nice-minus10";
    return "posix:default";
}
void NkUnboostSendThread() {}
bool NkPinThread(int cpu)
{
#if defined(__linux__)
    if (cpu == NK_CPU_NONE) return false;
    int target = cpu;
    if (cpu == NK_CPU_AUTO)
    {
        //Auto: highest core in the CURRENT allowed set (respects any taskset/cgroup limit, and skips
        //core 0 which typically carries more kernel/IRQ work).
        cpu_set_t cur;
        CPU_ZERO(&cur);
        if (sched_getaffinity(0, sizeof(cur), &cur) != 0) return false;
        target = -1;
        for (int i = CPU_SETSIZE - 1; i >= 0; i--)
        {
            if (CPU_ISSET(i, &cur)) { target = i; break; }
        }
        if (target < 0) return false;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(target, &set);
    return sched_setaffinity(0, sizeof(set), &set) == 0;
#else
    (void)cpu; // BSD uses a different cpuset API; not wired up
    return false;
#endif
}

#else
const char *NkBoostSendThread(bool) { return "default"; }
void NkUnboostSendThread() {}
bool NkPinThread(int) { return false; }
#endif
