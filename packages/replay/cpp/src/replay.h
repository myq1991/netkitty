#ifndef NETKITTY_REPLAY_ENGINE_H
#define NETKITTY_REPLAY_ENGINE_H

#include <napi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>

enum class ReplayMode
{
    TopSpeed,
    Multiplier,
    Mbps,
    Pps
};

struct ReplayFrame
{
    std::vector<unsigned char> data;
    uint64_t ts_ns; // capture timestamp in ns (only used in Multiplier mode)
};

// Replays a preloaded set of frames to one interface on a dedicated std::thread (so the Node main
// thread is never blocked), paced per mode, sending via the fastest available ISendBackend for the
// platform. Progress/done/error are delivered to JS via a ThreadSafeFunction. The bytes are sent
// verbatim — no parsing or editing (that stays in JS with the codec).
class NetKittyReplay : public Napi::ObjectWrap<NetKittyReplay>
{
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    NetKittyReplay(const Napi::CallbackInfo &);
    ~NetKittyReplay();
    void AddFrames(const Napi::CallbackInfo &);
    void Start(const Napi::CallbackInfo &);
    void Stop(const Napi::CallbackInfo &);

private:
    std::string device_;
    ReplayMode mode_ = ReplayMode::Multiplier;
    double rate_ = 1.0;      // Multiplier: factor; Mbps: bits/s; Pps: packets/s
    uint32_t loop_ = 1;      // number of passes
    bool infinite_ = false;  // loop forever
    uint32_t loopDelayMs_ = 0;
    uint64_t limit_ = 0;     // stop after N sent (0 = no limit)
    uint64_t maxSleepNs_ = 0; // clamp per-wait (0 = no clamp)
    int precision_ = 0;      // 0 auto, 1 sleep, 2 spin
    bool realtime_ = false;  // request real-time scheduling for the send thread
    int cpu_ = -1;           // pin the send thread to this CPU core (-1 = no pin)
    std::vector<ReplayFrame> frames_;

    Napi::ThreadSafeFunction tsEmit_;
    std::thread worker_;
    std::atomic<bool> abort_;
    bool running_ = false;

    void run();
    void stopThread();
    void sleepUntil(std::chrono::steady_clock::time_point target);
    void emit(int type, uint64_t sent, uint64_t bytes, uint64_t failed, double elapsedMs, uint32_t loop, const std::string &backend, const std::string &error);
};

#endif
