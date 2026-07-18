#include <napi.h>
#include "capture.h"
#include "utils.h"

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
  Napi::HandleScope scope(env);
  Capture::Init(env, exports);
  exports.Set("GetNetworkInterfaces", Napi::Function::New(env, GetNetworkInterfaces));
  exports.Set("Prepare", Napi::Function::New(env, Prepare));
  return exports;
}

NODE_API_MODULE(nodepcap, Init);
