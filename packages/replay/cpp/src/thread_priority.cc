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

#else
const char *NkBoostSendThread(bool) { return "default"; }
void NkUnboostSendThread() {}
#endif
