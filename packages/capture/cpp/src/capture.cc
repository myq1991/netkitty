#include <napi.h>
#include <stdlib.h>
#include <pthread.h>
#include <uv.h>
#include "capture.h"

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
            InstanceMethod("send", &NetKittyCapture::SendPacket),
        });
    exports.Set("NetKittyCapture", func);
    return exports;
}

NetKittyCapture::NetKittyCapture(const Napi::CallbackInfo &info) : ObjectWrap(info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1)
    {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsObject())
    {
        Napi::TypeError::New(env, "Set an options for the parser")
            .ThrowAsJavaScriptException();
        return;
    }

    Napi::Object options = info[0].As<Napi::Object>();
    if (options.Has("iface"))
    {
        this->iface = options.Get("iface").As<Napi::String>().Utf8Value();
    }

    if (options.Has("filter"))
    {
        this->filter = options.Get("filter").As<Napi::String>().Utf8Value();
    }
    else
    {
        this->filter = "";
    }
#ifdef _WIN32
    this->wait = nullptr;
#endif
    this->handling_packets = false;
    this->closing = false;
    this->tsfn_active = false;
    this->uv_active = false;
}

#ifdef _WIN32
void NetKittyCapture::cb_packets(uv_async_t *handle)
{
    NetKittyCapture *obj = (NetKittyCapture *)handle->data;
    int packet_count;

    if (obj->closing)
        return obj->cleanup();

    obj->handling_packets = true;

    do
    {
        packet_count = pcap_dispatch(obj->pcap_handle,
                                     1,
                                     NetKittyCapture::EmitPacket,
                                     (u_char *)obj);
    } while (packet_count > 0 && !obj->closing);

    obj->handling_packets = false;
    if (obj->closing)
        obj->cleanup();
}
void CALLBACK NetKittyCapture::OnPacket(void *data, BOOLEAN didTimeout)
{
    // assert(!didTimeout);
    uv_async_t *async = (uv_async_t *)data;
    int r = uv_async_send(async);
    // assert(r == 0);
}
void NetKittyCapture::cb_close(uv_handle_t *handle)
{
}
#else
void NetKittyCapture::cb_packets(uv_poll_t *handle, int status, int events)
{
    // assert(status == 0);
    NetKittyCapture *obj = (NetKittyCapture *)handle->data;

    int packet_count;

    if (obj->closing)
        return obj->cleanup();

    if (events & UV_READABLE)
    {
        obj->handling_packets = true;

        do
        {
            packet_count = pcap_dispatch(obj->pcap_handle,
                                         1,
                                         NetKittyCapture::EmitPacket,
                                         (u_char *)obj);
        } while (packet_count > 0 && !obj->closing);

        obj->handling_packets = false;
        if (obj->closing)
            obj->cleanup();
    }
}
#endif

void NetKittyCapture::EmitPacket(u_char *user,
                                   const struct pcap_pkthdr *pkt_hdr,
                                   const u_char *pkt_data)
{
    NetKittyCapture *obj = (NetKittyCapture *)user;

    PacketEventData *eventData = new PacketEventData;
    eventData->pkt_data = new u_char[pkt_hdr->caplen];
    eventData->copy_len = pkt_hdr->caplen;
    gettimeofday(&eventData->tv, NULL);
    memcpy(eventData->pkt_data, pkt_data, pkt_hdr->caplen);

    auto callback = [](Napi::Env env, Napi::Function jsCallback, PacketEventData *data)
    {
        // printf("%d \n", data->copy_len);
        // printf("Time: %ld.%06ld\n", data->tv.tv_sec, data->tv.tv_usec);
        jsCallback.Call({Napi::String::New(env, "data"),
                         Napi::Buffer<uint8_t>::Copy(env, data->pkt_data, data->copy_len), Napi::Number::New(env, data->tv.tv_sec), Napi::Number::New(env, data->tv.tv_usec)});
        delete[] data->pkt_data;
        delete data;
    };
    obj->tsEmit_.BlockingCall(eventData, callback);
}

void NetKittyCapture::Start(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    Napi::Function emit = info.This().As<Napi::Object>().Get("emit").As<Napi::Function>();
    Napi::Function bound = emit.Get("bind").As<Function>().Call(emit, {info.This()}).As<Function>();

    this->tsEmit_ = Napi::ThreadSafeFunction::New(
        bound.Env(),
        bound,          // JavaScript function called asynchronously
        "packet",       // Name
        0,              // Unlimited queue
        1,              // Only one thread will use this initially
        [](Napi::Env) { // Finalizer used to clean threads up
        });
    this->tsfn_active = true;

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    // printf("%s", errbuf);
    this->pcap_handle = pcap_open_live(this->iface.c_str(), // name of the device
                                       262144,              // portion of the packet to capture.
                                       1,                   // promiscuous mode (nonzero means promiscuous)
                                       250,                 // read timeout
                                       errbuf               // error buffer
    );

    // if (pcap_set_buffer_size(this->pcap_handle, 10485760) != 0)
    // {
    //     Napi::TypeError::New(env, "Unable to set buffer size").ThrowAsJavaScriptException();
    //     return;
    // }
    //pcap_open_live returns NULL only on failure; a non-empty errbuf on success is just a warning
    //(e.g. promiscuous mode unsupported), so key the error strictly on a NULL handle.
    if (this->pcap_handle == NULL)
    {
        this->teardown();
        Napi::Error::New(env, errbuf).ThrowAsJavaScriptException();
        return;
    }

    int r;

#ifdef _WIN32
    if (pcap_setnonblock(this->pcap_handle, 1, errbuf) == -1)
    {
        Napi::TypeError::New(env, errbuf).ThrowAsJavaScriptException();
        return;
    }

    pcap_setmintocopy(this->pcap_handle, 0);

    // uv_async_init
    r = uv_async_init(uv_default_loop(),
                      &this->async,
                      (uv_async_cb)NetKittyCapture::cb_packets);
    // assert(r == 0);
    if(r!=0){
        this->teardown();
        Napi::Error::New(env,"uv_async_init error").ThrowAsJavaScriptException();
        return;
    }
    this->uv_active = true;
    this->async.data = this;
    r = RegisterWaitForSingleObject(
        &this->wait,
        pcap_getevent(this->pcap_handle),
        NetKittyCapture::OnPacket,
        &this->async,
        INFINITE,
        WT_EXECUTEINWAITTHREAD);
    if (!r)
    {
        char *errmsg = nullptr;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      nullptr,
                      GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR)&errmsg,
                      0,
                      nullptr);
        this->teardown();
        Napi::Error::New(env, errmsg).ThrowAsJavaScriptException();
        return;
    }

#else
    this->fd = pcap_get_selectable_fd(this->pcap_handle);
    r = uv_poll_init(uv_default_loop(), &this->poll_handle, this->fd);
//     assert(r == 0);
    if(r!=0){
        this->teardown();
        Napi::Error::New(env,"uv_poll_init error").ThrowAsJavaScriptException();
        return;
    }
    this->uv_active = true;
    this->poll_handle.data = this;
    r = uv_poll_start(&this->poll_handle, UV_READABLE, NetKittyCapture::cb_packets);
#endif
    if (!this->filter.empty())
    {
        bpf_u_int32 NetMask = 0xffffff;

        // compile the filter
        if (pcap_compile(this->pcap_handle, &this->fcode, this->filter.c_str(), 1, NetMask) < 0)
        {
            pcap_freecode(&this->fcode);
            this->teardown();
            Napi::Error::New(env, "Error compiling filter: wrong syntax.")
                .ThrowAsJavaScriptException();
            return;
        }

        // set the filter
        if (pcap_setfilter(this->pcap_handle, &this->fcode) < 0)
        {
            pcap_freecode(&this->fcode);
            this->teardown();
            Napi::Error::New(env, "Error setting the filter")
                .ThrowAsJavaScriptException();
            return;
        }
    }
}

void NetKittyCapture::Stop(const Napi::CallbackInfo &info)
{
    this->teardown();
}

//Release every native resource, guarded and idempotent: safe to call twice, from a Start() failure
//path, or on a handle that was never opened. Order: drop the JS callback, stop the loop watcher, then
//close the pcap handle. Nulling pcap_handle is what makes a later Stop()/SetFilter() a no-op instead
//of a double free.
void NetKittyCapture::teardown()
{
    if (this->tsfn_active)
    {
        this->tsEmit_.Release();
        this->tsfn_active = false;
    }
    if (this->uv_active)
    {
#ifdef _WIN32
        if (this->wait)
        {
            UnregisterWait(this->wait);
            this->wait = nullptr;
        }
        uv_close((uv_handle_t *)&this->async, NetKittyCapture::cb_close);
#else
        uv_poll_stop(&this->poll_handle);
#endif
        this->uv_active = false;
    }
    if (this->pcap_handle)
    {
        pcap_close(this->pcap_handle);
        this->pcap_handle = NULL;
    }
}

void NetKittyCapture::SetFilter(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1)
    {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsString())
    {
        Napi::TypeError::New(env, "Filter should be a string value")
            .ThrowAsJavaScriptException();
        return;
    }

    std::string filter = info[0].As<Napi::String>().Utf8Value();

    this->filter = filter;

    if (this->pcap_handle == NULL)
    {
        return;
    }

#ifdef _WIN32

#else
    uv_poll_stop(&this->poll_handle);
    uv_poll_start(&this->poll_handle, UV_READABLE, NetKittyCapture::cb_packets);
#endif
    bpf_u_int32 NetMask = 0xffffff;

    // compile the filter
    if (pcap_compile(this->pcap_handle, &this->fcode, filter.c_str(), 1, NetMask) < 0)
    {
        pcap_freecode(&this->fcode);
        this->teardown();
        Napi::Error::New(env, "Error compiling filter: wrong syntax.")
            .ThrowAsJavaScriptException();
        return;
    }

    // set the filter
    if (pcap_setfilter(this->pcap_handle, &this->fcode) < 0)
    {
        pcap_freecode(&this->fcode);
        this->teardown();
        Napi::Error::New(env, "Error setting the filter")
            .ThrowAsJavaScriptException();
        return;
    }

    pcap_freecode(&this->fcode);
}

void NetKittyCapture::SendPacket(const Napi::CallbackInfo &info)
{
    if (info.Length() != 1)
    {
        Napi::Error::New(info.Env(), "Expected exactly one argument")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsBuffer())
    {
        Napi::Error::New(info.Env(), "Expected an Buffer")
            .ThrowAsJavaScriptException();
        return;
    }

    Napi::Buffer<char> buf = info[0].As<Napi::Buffer<char>>();
    size_t buffer_size = buf.Length();

    // pcap_send_packet
    if (pcap_sendpacket(this->pcap_handle,
                        (const u_char *)buf.Data(),
                        (int)buffer_size) == -1)
    {
        Napi::Error::New(info.Env(), pcap_geterr(this->pcap_handle))
            .ThrowAsJavaScriptException();
        return;
    }
}

bool NetKittyCapture::close()
{
    if (this->pcap_handle && !this->closing)
    {
#ifdef _WIN32
        if (this->wait)
        {
            UnregisterWait(this->wait);
            this->wait = nullptr;
        }
        uv_close((uv_handle_t *)&this->async, NetKittyCapture::cb_close);
#else
        uv_poll_stop(&this->poll_handle);
#endif
        this->closing = true;
        this->cleanup();
        return true;
    }
    return false;
}

void NetKittyCapture::cleanup()
{
#ifdef _WIN32
    this->wait = nullptr;
#endif
    this->handling_packets = false;
    this->closing = true;
}
