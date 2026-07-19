#include <napi.h>
#include <stdlib.h>
#include "capture.h"

//Snapshot length passed to pcap_open_live, and the upper bound the per-packet copy is clamped to.
#define NK_CAPTURE_SNAPLEN 262144
//Read timeout (ms) for the blocking capture handle: bounds how long a Stop() waits for the capture
//thread to notice pcap_breakloop when the link is idle.
#define NK_CAPTURE_TIMEOUT_MS 250

using namespace Napi;

Napi::Object NetKittyCapture::Init(Napi::Env env, Napi::Object exports)
{
    Napi::Function func = DefineClass(
        env,
        "NetKittyCapture",
        {
            InstanceMethod("start", &NetKittyCapture::Start),
            InstanceMethod("stop", &NetKittyCapture::Stop),
            InstanceMethod("setFilter", &NetKittyCapture::SetFilter),
        });
    exports.Set("NetKittyCapture", func);
    return exports;
}

NetKittyCapture::NetKittyCapture(const Napi::CallbackInfo &info) : ObjectWrap(info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1)
    {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return;
    }
    if (!info[0].IsObject())
    {
        Napi::TypeError::New(env, "Set an options for the parser").ThrowAsJavaScriptException();
        return;
    }

    Napi::Object options = info[0].As<Napi::Object>();
    if (options.Has("iface")) this->iface = options.Get("iface").As<Napi::String>().Utf8Value();
    this->filter = options.Has("filter") ? options.Get("filter").As<Napi::String>().Utf8Value() : "";
    this->stop_.store(false);
    this->running_ = false;
}

NetKittyCapture::~NetKittyCapture()
{
    //Safety net: if JS drops the object without calling stop(), still tear the thread/handle down.
    this->stopCapture();
}

//Runs on the capture thread. Copies each packet (clamped to snaplen) and hands it to JS via the TSFN.
void NetKittyCapture::EmitPacket(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data)
{
    NetKittyCapture *obj = (NetKittyCapture *)user;

    size_t copy_len = pkt_hdr->caplen;
    if (copy_len > NK_CAPTURE_SNAPLEN) copy_len = NK_CAPTURE_SNAPLEN;

    PacketEventData *eventData = new PacketEventData;
    eventData->pkt_data = new u_char[copy_len];
    eventData->copy_len = copy_len;
    eventData->tv = pkt_hdr->ts; // kernel/driver capture timestamp
    memcpy(eventData->pkt_data, pkt_data, copy_len);

    auto callback = [](Napi::Env env, Napi::Function jsCallback, PacketEventData *data)
    {
        jsCallback.Call({Napi::String::New(env, "data"),
                         Napi::Buffer<uint8_t>::Copy(env, data->pkt_data, data->copy_len),
                         Napi::Number::New(env, data->tv.tv_sec),
                         Napi::Number::New(env, data->tv.tv_usec)});
        delete[] data->pkt_data;
        delete data;
    };

    if (obj->tsEmit_.BlockingCall(eventData, callback) != napi_ok)
    {
        //TSFN is closing (Stop in progress) — drop this packet instead of leaking it.
        delete[] eventData->pkt_data;
        delete eventData;
    }
}

void NetKittyCapture::captureLoop()
{
    while (!this->stop_.load())
    {
        int r = pcap_dispatch(this->pcap_handle, -1, NetKittyCapture::EmitPacket, (u_char *)this);
        //r == 0: read timeout with no packets (idle link) — loop and recheck stop_.
        //r < 0: -1 error or -2 pcap_breakloop — leave the loop.
        if (r < 0) break;
    }
}

bool NetKittyCapture::applyFilter(std::string &err)
{
    if (this->filter.empty()) return true;
    bpf_u_int32 netmask = 0xffffff;
    if (pcap_compile(this->pcap_handle, &this->fcode, this->filter.c_str(), 1, netmask) < 0)
    {
        err = "Error compiling filter: wrong syntax.";
        return false;
    }
    bool ok = pcap_setfilter(this->pcap_handle, &this->fcode) >= 0;
    pcap_freecode(&this->fcode);
    if (!ok) err = "Error setting the filter";
    return ok;
}

void NetKittyCapture::Start(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (this->running_) return; // idempotent

    Napi::Function emit = info.This().As<Napi::Object>().Get("emit").As<Napi::Function>();
    Napi::Function bound = emit.Get("bind").As<Function>().Call(emit, {info.This()}).As<Function>();
    this->tsEmit_ = Napi::ThreadSafeFunction::New(bound.Env(), bound, "packet", 0, 1, [](Napi::Env) {});

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    this->pcap_handle = pcap_open_live(this->iface.c_str(), NK_CAPTURE_SNAPLEN, 1, NK_CAPTURE_TIMEOUT_MS, errbuf);
    //pcap_open_live returns NULL only on failure; a non-empty errbuf on success is just a warning.
    if (this->pcap_handle == NULL)
    {
        this->tsEmit_.Release();
        Napi::Error::New(env, errbuf).ThrowAsJavaScriptException();
        return;
    }

    std::string ferr;
    if (!this->applyFilter(ferr))
    {
        pcap_close(this->pcap_handle);
        this->pcap_handle = NULL;
        this->tsEmit_.Release();
        Napi::Error::New(env, ferr).ThrowAsJavaScriptException();
        return;
    }

    this->stop_.store(false);
    this->running_ = true;
    this->worker_ = std::thread(&NetKittyCapture::captureLoop, this);
}

void NetKittyCapture::Stop(const Napi::CallbackInfo &info)
{
    this->stopCapture();
}

//Stop the capture thread, release the TSFN and close the handle. Guarded/idempotent and safe from the
//destructor. Order: signal stop -> break the blocking dispatch -> join the producer -> release the
//consumer TSFN -> close the pcap handle. Joining before Release/close avoids any use-after-free race.
void NetKittyCapture::stopCapture()
{
    if (!this->running_) return;
    this->stop_.store(true);
    if (this->pcap_handle) pcap_breakloop(this->pcap_handle);
    if (this->worker_.joinable()) this->worker_.join();
    this->tsEmit_.Release();
    if (this->pcap_handle)
    {
        pcap_close(this->pcap_handle);
        this->pcap_handle = NULL;
    }
    this->running_ = false;
}

void NetKittyCapture::SetFilter(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1)
    {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return;
    }
    if (!info[0].IsString())
    {
        Napi::TypeError::New(env, "Filter should be a string value").ThrowAsJavaScriptException();
        return;
    }
    this->filter = info[0].As<Napi::String>().Utf8Value();
    if (!this->running_ || this->pcap_handle == NULL) return; // applied on next start()

    //pcap_t is not thread-safe: pause the capture thread before touching the handle, then resume.
    this->stop_.store(true);
    pcap_breakloop(this->pcap_handle);
    if (this->worker_.joinable()) this->worker_.join();

    std::string ferr;
    bool ok = this->applyFilter(ferr);

    this->stop_.store(false);
    this->worker_ = std::thread(&NetKittyCapture::captureLoop, this);

    if (!ok) Napi::Error::New(env, ferr).ThrowAsJavaScriptException();
}
