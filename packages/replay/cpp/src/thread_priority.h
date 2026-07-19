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

#endif
