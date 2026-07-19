#include <napi.h>
#include "replay.h"
#include "pcap_api.h"

// Reports whether the pcap backend is available: on Windows this loads wpcap.dll (Npcap) and returns
// false if Npcap is not installed; on POSIX it is always true.
Napi::Boolean Prepare(const Napi::CallbackInfo &info)
{
    return Napi::Boolean::New(info.Env(), NkPcapLoad());
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    NetKittyReplay::Init(env, exports);
    exports.Set("Prepare", Napi::Function::New(env, Prepare));
    return exports;
}

NODE_API_MODULE(netkitty_replay, Init)
