#include <napi.h>
#include <stdlib.h>
#include "replay.h"
#include "send_backend.h"
#include "thread_priority.h"

using namespace Napi;

struct EmitMsg
{
    int type; // 0 progress, 1 done, 2 error
    uint64_t sent, bytes, failed;
    double elapsedMs;
    uint32_t loop;
    std::string backend;
    std::string error;
};

static void EmitCallback(Napi::Env env, Napi::Function jsEmit, EmitMsg *m)
{
    if (env != nullptr && jsEmit != nullptr)
    {
        if (m->type == 2)
        {
            jsEmit.Call({Napi::String::New(env, "error"), Napi::Error::New(env, m->error).Value()});
        }
        else
        {
            Napi::Object o = Napi::Object::New(env);
            o.Set("sent", Napi::Number::New(env, (double)m->sent));
            o.Set("bytes", Napi::Number::New(env, (double)m->bytes));
            o.Set("failed", Napi::Number::New(env, (double)m->failed));
            o.Set("elapsedMs", Napi::Number::New(env, m->elapsedMs));
            o.Set("loop", Napi::Number::New(env, (double)m->loop));
            double secs = m->elapsedMs / 1000.0;
            o.Set("pps", Napi::Number::New(env, secs > 0 ? (double)m->sent / secs : 0));
            o.Set("mbps", Napi::Number::New(env, secs > 0 ? ((double)m->bytes * 8.0 / 1e6) / secs : 0));
            o.Set("backend", Napi::String::New(env, m->backend));
            jsEmit.Call({Napi::String::New(env, m->type == 0 ? "progress" : "done"), o});
        }
    }
    delete m;
}

Napi::Object NetKittyReplay::Init(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(
        env,
        "NetKittyReplay",
        {
            InstanceMethod("addFrames", &NetKittyReplay::AddFrames),
            InstanceMethod("start", &NetKittyReplay::Start),
            InstanceMethod("stop", &NetKittyReplay::Stop),
        });
    exports.Set("NetKittyReplay", func);
    return exports;
}

static ReplayMode parseMode(const std::string &s)
{
    if (s == "topspeed") return ReplayMode::TopSpeed;
    if (s == "mbps") return ReplayMode::Mbps;
    if (s == "pps") return ReplayMode::Pps;
    return ReplayMode::Multiplier;
}

NetKittyReplay::NetKittyReplay(const Napi::CallbackInfo &info) : ObjectWrap(info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
    {
        Napi::TypeError::New(env, "Replay expects an options object").ThrowAsJavaScriptException();
        return;
    }
    Napi::Object o = info[0].As<Napi::Object>();
    if (o.Has("device")) this->device_ = o.Get("device").As<Napi::String>().Utf8Value();
    this->mode_ = o.Has("mode") ? parseMode(o.Get("mode").As<Napi::String>().Utf8Value()) : ReplayMode::Multiplier;
    this->rate_ = o.Has("rate") ? o.Get("rate").As<Napi::Number>().DoubleValue() : 1.0;
    this->loop_ = o.Has("loop") ? (uint32_t)o.Get("loop").As<Napi::Number>().Uint32Value() : 1;
    this->infinite_ = o.Has("infinite") && o.Get("infinite").As<Napi::Boolean>().Value();
    this->loopDelayMs_ = o.Has("loopDelayMs") ? (uint32_t)o.Get("loopDelayMs").As<Napi::Number>().Uint32Value() : 0;
    this->limit_ = o.Has("limit") ? (uint64_t)o.Get("limit").As<Napi::Number>().Int64Value() : 0;
    uint64_t maxSleepMs = o.Has("maxSleepMs") ? (uint64_t)o.Get("maxSleepMs").As<Napi::Number>().Int64Value() : 0;
    this->maxSleepNs_ = maxSleepMs * 1000000ull;
    if (o.Has("precision"))
    {
        std::string p = o.Get("precision").As<Napi::String>().Utf8Value();
        this->precision_ = (p == "sleep") ? 1 : (p == "spin") ? 2 : 0;
    }
    this->realtime_ = o.Has("realtime") && o.Get("realtime").As<Napi::Boolean>().Value();
    this->cpu_ = o.Has("cpu") ? (int)o.Get("cpu").As<Napi::Number>().Int32Value() : -1;
    if (this->loop_ < 1) this->loop_ = 1;
    this->abort_.store(false);
}

NetKittyReplay::~NetKittyReplay()
{
    this->stopThread();
}

void NetKittyReplay::AddFrames(const Napi::CallbackInfo &info)
{
    if (info.Length() < 1 || !info[0].IsArray()) return;
    Napi::Array arr = info[0].As<Napi::Array>();
    uint32_t n = arr.Length();
    this->frames_.reserve(this->frames_.size() + n);
    for (uint32_t i = 0; i < n; i++)
    {
        Napi::Object o = arr.Get(i).As<Napi::Object>();
        Napi::Buffer<unsigned char> buf = o.Get("data").As<Napi::Buffer<unsigned char>>();
        ReplayFrame f;
        f.data.assign(buf.Data(), buf.Data() + buf.Length());
        uint64_t secs = o.Has("seconds") ? (uint64_t)o.Get("seconds").As<Napi::Number>().Int64Value() : 0;
        uint64_t nanos = o.Has("nanoseconds") ? (uint64_t)o.Get("nanoseconds").As<Napi::Number>().Int64Value() : 0;
        f.ts_ns = secs * 1000000000ull + nanos;
        this->frames_.push_back(std::move(f));
    }
}

void NetKittyReplay::emit(int type, uint64_t sent, uint64_t bytes, uint64_t failed, double elapsedMs, uint32_t loop, const std::string &backend, const std::string &error)
{
    EmitMsg *m = new EmitMsg{type, sent, bytes, failed, elapsedMs, loop, backend, error};
    //All emits are non-blocking so the send thread never blocks on JS; done/error are low-frequency and
    //progress is throttled, so the (unbounded) queue never piles up.
    if (this->tsEmit_.NonBlockingCall(m, EmitCallback) != napi_ok) delete m;
}

void NetKittyReplay::sleepUntil(std::chrono::steady_clock::time_point target)
{
    for (;;)
    {
        if (this->abort_.load()) return;
        auto now = std::chrono::steady_clock::now();
        if (now >= target) return;
        int64_t remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(target - now).count();
        if (remaining > 20000000LL)
        {
            //>20ms: chunked sleep so stop() is responsive on long inter-frame gaps.
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        else if (this->precision_ == 1)
        {
            std::this_thread::sleep_for(std::chrono::nanoseconds(remaining));
        }
        else if (this->precision_ != 2 && remaining > 250000LL)
        {
            //auto: nanosleep the bulk, busy-spin the last ~250us for precision.
            std::this_thread::sleep_for(std::chrono::nanoseconds(remaining - 250000LL));
        }
        else
        {
            std::this_thread::yield();
        }
    }
}

void NetKittyReplay::run()
{
    // Raise this send thread's priority so pacing suffers less scheduler jitter. Best-effort; the Node
    // main thread is unaffected (this runs on the dedicated worker thread).
    NkBoostSendThread(this->realtime_);
    // Optionally pin the send thread to one core to stop the scheduler migrating it (best-effort).
    NkPinThread(this->cpu_);

    std::string openErr;
    ISendBackend *backend = OpenSendBackend(this->device_, openErr);
    if (backend == nullptr)
    {
        NkUnboostSendThread();
        this->emit(2, 0, 0, 0, 0, 0, "", openErr.empty() ? "failed to open device for sending" : openErr);
        return;
    }
    const std::string backendName = backend->name();

    auto startClock = std::chrono::steady_clock::now();
    uint64_t sent = 0, bytes = 0, failed = 0;
    uint64_t cumCapNs = 0, cumBytes = 0, cumPkts = 0;
    auto lastProgress = startClock;

    for (uint32_t iter = 0; (this->infinite_ || iter < this->loop_) && !this->abort_.load(); iter++)
    {
        if (iter > 0 && this->loopDelayMs_ > 0)
        {
            this->sleepUntil(std::chrono::steady_clock::now() + std::chrono::milliseconds(this->loopDelayMs_));
            if (this->abort_.load()) break;
        }
        uint64_t prevTs = 0;
        bool havePrev = false;
        for (size_t i = 0; i < this->frames_.size() && !this->abort_.load(); i++)
        {
            const ReplayFrame &f = this->frames_[i];

            bool paced = true;
            uint64_t deadlineNs = 0;
            switch (this->mode_)
            {
            case ReplayMode::TopSpeed:
                paced = false;
                break;
            case ReplayMode::Multiplier:
                if (havePrev && f.ts_ns > prevTs) cumCapNs += f.ts_ns - prevTs;
                havePrev = true;
                prevTs = f.ts_ns;
                deadlineNs = this->rate_ > 0 ? (uint64_t)((double)cumCapNs / this->rate_) : 0;
                break;
            case ReplayMode::Mbps:
                deadlineNs = this->rate_ > 0 ? (uint64_t)((double)cumBytes * 8.0 * 1e9 / this->rate_) : 0;
                break;
            case ReplayMode::Pps:
                deadlineNs = this->rate_ > 0 ? (uint64_t)((double)cumPkts * 1e9 / this->rate_) : 0;
                break;
            }

            if (paced)
            {
                auto target = startClock + std::chrono::nanoseconds(deadlineNs);
                auto now = std::chrono::steady_clock::now();
                if (target > now)
                {
                    if (this->maxSleepNs_)
                    {
                        auto maxT = now + std::chrono::nanoseconds(this->maxSleepNs_);
                        if (target > maxT) target = maxT;
                    }
                    this->sleepUntil(target);
                    if (this->abort_.load()) break;
                }
                //behind schedule (target <= now): send immediately, don't recompute.
            }

            int r = backend->send(f.data.data(), (int)f.data.size());
            if (r == 0)
            {
                sent++;
                bytes += f.data.size();
            }
            else
            {
                failed++;
            }
            cumBytes += f.data.size();
            cumPkts++;

            //Paced modes need each frame on the wire now; topspeed lets the backend batch (flushed
            //after the loop). No-op for non-batching backends.
            if (paced) backend->flush();

            if (this->limit_ && sent >= this->limit_)
            {
                this->abort_.store(true);
                break;
            }

            auto now2 = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now2 - lastProgress).count() >= 150)
            {
                lastProgress = now2;
                double elapsedMs = (double)std::chrono::duration_cast<std::chrono::milliseconds>(now2 - startClock).count();
                this->emit(0, sent, bytes, failed, elapsedMs, iter, backendName, "");
            }
        }
    }

    backend->flush(); // drain any frames a batching backend (topspeed) still holds
    delete backend;
    NkUnboostSendThread();
    double elapsedMs = (double)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startClock).count();
    this->emit(1, sent, bytes, failed, elapsedMs, 0, backendName, "");
}

void NetKittyReplay::Start(const Napi::CallbackInfo &info)
{
    if (this->running_) return;
    Napi::Function emit = info.This().As<Napi::Object>().Get("emit").As<Napi::Function>();
    Napi::Function bound = emit.Get("bind").As<Napi::Function>().Call(emit, {info.This()}).As<Napi::Function>();
    this->tsEmit_ = Napi::ThreadSafeFunction::New(bound.Env(), bound, "replay", 0, 1, [](Napi::Env) {});
    this->abort_.store(false);
    this->running_ = true;
    this->worker_ = std::thread(&NetKittyReplay::run, this);
}

void NetKittyReplay::Stop(const Napi::CallbackInfo &info)
{
    this->stopThread();
}

void NetKittyReplay::stopThread()
{
    if (!this->running_) return;
    this->abort_.store(true);
    if (this->worker_.joinable()) this->worker_.join();
    this->tsEmit_.Release();
    this->running_ = false;
}
