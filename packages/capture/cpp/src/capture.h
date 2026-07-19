#ifndef NETKITTY_PCAP_CAPTURE_H
#define NETKITTY_PCAP_CAPTURE_H

#include <napi.h>
#include <string.h>
#include <string>
#include <thread>
#include <atomic>
#include "pcap_api.h"

struct PacketEventData
{
    u_char *pkt_data;
    size_t copy_len;
    struct timeval tv;
};

// Each instance owns one pcap handle captured on its own dedicated thread (blocking pcap_dispatch),
// delivering packets to JS via a ThreadSafeFunction. This is platform-uniform: no libuv fd/event
// integration, so the same code path runs on Linux, macOS and Windows.
class NetKittyCapture : public Napi::ObjectWrap<NetKittyCapture>
{
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    static void EmitPacket(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data);
    NetKittyCapture(const Napi::CallbackInfo &);
    ~NetKittyCapture();
    void Start(const Napi::CallbackInfo &);
    void Stop(const Napi::CallbackInfo &);
    void SetFilter(const Napi::CallbackInfo &);

private:
    Napi::ThreadSafeFunction tsEmit_;
    std::string iface;
    std::string filter;
    pcap_t *pcap_handle = NULL;
    std::thread worker_;
    std::atomic<bool> stop_;
    bool running_;
    struct bpf_program fcode;
    void captureLoop();
    void stopCapture();
    bool applyFilter(std::string &err);
};

#endif
