#ifndef NETKITTY_REPLAY_THREAD_PRIORITY_H
#define NETKITTY_REPLAY_THREAD_PRIORITY_H

// Best-effort: raise the CURRENT thread's scheduling priority so packet pacing suffers less jitter
// from the OS scheduler. Called on the send thread itself (never the Node main thread). All failures
// are silently ignored (e.g. lacking CAP_SYS_NICE / admin rights). Never throws.
//   realtime=false : safe boost only (Win TIME_CRITICAL thread + 1ms timer, mac USER_INTERACTIVE QoS,
//                    POSIX negative nice) — cannot starve the system.
//   realtime=true  : also request real-time scheduling where available (POSIX SCHED_FIFO). Use with
//                    care: a busy-spin at RT priority can monopolise a core.
// Returns a short label of what was actually applied (for diagnostics).
const char *NkBoostSendThread(bool realtime);

// Undo process-global changes made by the boost (Windows timer resolution). Safe to always call.
void NkUnboostSendThread();

//Special cpu values for NkPinThread (any value >= 0 is an explicit core index).
#define NK_CPU_NONE (-1) // leave the thread unpinned
#define NK_CPU_AUTO (-2) // auto-select a core (highest in the allowed set)

// Best-effort: pin the CURRENT thread to one CPU core, so the scheduler stops migrating it between
// cores (migration trashes cache and adds pacing jitter). cpu < 0 is a no-op. Linux uses
// sched_setaffinity, Windows SetThreadAffinityMask; macOS has no real per-core pinning (its affinity
// API is only an advisory hint / a no-op on Apple Silicon), so it does nothing there. Returns true if
// a pin was actually applied.
bool NkPinThread(int cpu);

#endif
