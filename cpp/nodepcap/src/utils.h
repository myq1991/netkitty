#ifndef ACE_PCAP_UTILS_H
#define ACE_PCAP_UTILS_H

#include <uv.h>
#include <napi.h>
#include <string.h>
#include <pcap.h>

Napi::Array GetNetworkInterfaces(const Napi::CallbackInfo &);
Napi::String GetNetworkInterface(const Napi::CallbackInfo &);
Napi::Boolean Prepare(const Napi::CallbackInfo &);

#endif
