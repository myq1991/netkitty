#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Read-only network interface enumeration + stats, using only OS system APIs (no libpcap/Npcap, no
// dynamic loading, no bundled headers). Reports EVERY interface including administratively-down ones
// (which Node's os.networkInterfaces() omits), with MAC, IPv4/IPv6 addresses, up state, MTU and
// per-interface tx/rx counters.

struct IfaceAddr
{
    std::string family; // "ipv4" | "ipv6"
    std::string address;
    std::string netmask;
};

struct IfaceInfo
{
    std::string name;
    std::string mac;
    std::string description;
    bool up = false;
    uint32_t mtu = 0;
    std::vector<IfaceAddr> addresses;
    uint64_t rxBytes = 0, rxPackets = 0, rxErrors = 0, rxDropped = 0;
    uint64_t txBytes = 0, txPackets = 0, txErrors = 0, txDropped = 0;
};

static std::string macFromBytes(const unsigned char *b, size_t len)
{
    if (len != 6) return "";
    char m[18];
    snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return std::string(m);
}

// ------------------------------------------------------------------ Windows

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

static std::string wideToUtf8(const wchar_t *w)
{
    if (!w) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string s((size_t)(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], len, nullptr, nullptr);
    return s;
}

static std::string prefixToMaskV4(uint8_t prefix)
{
    uint32_t mask = prefix ? (0xffffffffu << (32 - prefix)) : 0u;
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (mask >> 24) & 0xff, (mask >> 16) & 0xff, (mask >> 8) & 0xff, mask & 0xff);
    return std::string(buf);
}

static void collect(std::vector<IfaceInfo> &out)
{
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) return;
    std::vector<char> buffer(size);
    IP_ADAPTER_ADDRESSES *adapters = (IP_ADAPTER_ADDRESSES *)buffer.data();
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size) != ERROR_SUCCESS) return;

    for (IP_ADAPTER_ADDRESSES *a = adapters; a != nullptr; a = a->Next)
    {
        IfaceInfo info;
        info.name = wideToUtf8(a->FriendlyName);
        info.description = wideToUtf8(a->Description);
        info.up = (a->OperStatus == IfOperStatusUp);
        info.mtu = a->Mtu;
        if (a->PhysicalAddressLength == 6) info.mac = macFromBytes(a->PhysicalAddress, 6);

        for (IP_ADAPTER_UNICAST_ADDRESS *ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next)
        {
            SOCKADDR *sa = ua->Address.lpSockaddr;
            if (!sa) continue;
            char buf[INET6_ADDRSTRLEN] = {0};
            if (sa->sa_family == AF_INET)
            {
                inet_ntop(AF_INET, &((sockaddr_in *)sa)->sin_addr, buf, sizeof(buf));
                info.addresses.push_back({"ipv4", buf, prefixToMaskV4((uint8_t)ua->OnLinkPrefixLength)});
            }
            else if (sa->sa_family == AF_INET6)
            {
                inet_ntop(AF_INET6, &((sockaddr_in6 *)sa)->sin6_addr, buf, sizeof(buf));
                char pfx[8];
                snprintf(pfx, sizeof(pfx), "/%u", ua->OnLinkPrefixLength);
                info.addresses.push_back({"ipv6", buf, std::string(pfx)});
            }
        }

        MIB_IF_ROW2 row;
        memset(&row, 0, sizeof(row));
        row.InterfaceLuid = a->Luid;
        if (GetIfEntry2(&row) == NO_ERROR)
        {
            info.rxBytes = row.InOctets;
            info.txBytes = row.OutOctets;
            info.rxPackets = row.InUcastPkts + row.InNUcastPkts;
            info.txPackets = row.OutUcastPkts + row.OutNUcastPkts;
            info.rxErrors = row.InErrors;
            info.txErrors = row.OutErrors;
            info.rxDropped = row.InDiscards;
            info.txDropped = row.OutDiscards;
        }
        out.push_back(info);
    }
}

// ------------------------------------------------------------------ POSIX (Linux + macOS)

#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef __linux__
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#endif

#ifdef __linux__
static uint64_t readSysU64(const std::string &iface, const char *path)
{
    std::string p = "/sys/class/net/" + iface + "/" + path;
    FILE *f = fopen(p.c_str(), "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return (uint64_t)v;
}
#endif

static void collect(std::vector<IfaceInfo> &out)
{
    struct ifaddrs *ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return;

    std::map<std::string, size_t> index;
    for (struct ifaddrs *ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_name) continue;
        std::string name = ifa->ifa_name;
        size_t idx;
        auto it = index.find(name);
        if (it == index.end())
        {
            idx = out.size();
            index[name] = idx;
            out.emplace_back();
            out[idx].name = name;
        }
        else
        {
            idx = it->second;
        }
        IfaceInfo &info = out[idx];
        info.up = (ifa->ifa_flags & IFF_UP) != 0;
        if (!ifa->ifa_addr) continue;

        int fam = ifa->ifa_addr->sa_family;
        if (fam == AF_INET)
        {
            char buf[INET_ADDRSTRLEN] = {0}, mask[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, buf, sizeof(buf));
            if (ifa->ifa_netmask) inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr, mask, sizeof(mask));
            info.addresses.push_back({"ipv4", buf, mask});
        }
        else if (fam == AF_INET6)
        {
            char buf[INET6_ADDRSTRLEN] = {0}, mask[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, buf, sizeof(buf));
            if (ifa->ifa_netmask) inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr, mask, sizeof(mask));
            info.addresses.push_back({"ipv6", buf, mask});
        }
#ifdef __linux__
        else if (fam == AF_PACKET)
        {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == 6) info.mac = macFromBytes(sll->sll_addr, 6);
        }
#else
        else if (fam == AF_LINK)
        {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_alen == 6) info.mac = macFromBytes((unsigned char *)LLADDR(sdl), 6);
            if (ifa->ifa_data)
            {
                struct if_data *d = (struct if_data *)ifa->ifa_data;
                info.mtu = d->ifi_mtu;
                info.rxBytes = d->ifi_ibytes;
                info.txBytes = d->ifi_obytes;
                info.rxPackets = d->ifi_ipackets;
                info.txPackets = d->ifi_opackets;
                info.rxErrors = d->ifi_ierrors;
                info.txErrors = d->ifi_oerrors;
                info.rxDropped = d->ifi_iqdrops;
                info.txDropped = 0;
            }
        }
#endif
    }
    freeifaddrs(ifap);

#ifdef __linux__
    // Linux: MTU + tx/rx counters from sysfs (robust across glibc and musl).
    for (IfaceInfo &info : out)
    {
        info.mtu = (uint32_t)readSysU64(info.name, "mtu");
        info.rxBytes = readSysU64(info.name, "statistics/rx_bytes");
        info.rxPackets = readSysU64(info.name, "statistics/rx_packets");
        info.rxErrors = readSysU64(info.name, "statistics/rx_errors");
        info.rxDropped = readSysU64(info.name, "statistics/rx_dropped");
        info.txBytes = readSysU64(info.name, "statistics/tx_bytes");
        info.txPackets = readSysU64(info.name, "statistics/tx_packets");
        info.txErrors = readSysU64(info.name, "statistics/tx_errors");
        info.txDropped = readSysU64(info.name, "statistics/tx_dropped");
    }
#endif
}

#endif

// ------------------------------------------------------------------ N-API glue

static Napi::Object counters(Napi::Env env, uint64_t bytes, uint64_t packets, uint64_t errors, uint64_t dropped)
{
    Napi::Object o = Napi::Object::New(env);
    o.Set("bytes", Napi::Number::New(env, (double)bytes));
    o.Set("packets", Napi::Number::New(env, (double)packets));
    o.Set("errors", Napi::Number::New(env, (double)errors));
    o.Set("dropped", Napi::Number::New(env, (double)dropped));
    return o;
}

Napi::Value List(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    std::vector<IfaceInfo> ifaces;
    collect(ifaces);

    Napi::Array arr = Napi::Array::New(env, ifaces.size());
    for (size_t i = 0; i < ifaces.size(); i++)
    {
        const IfaceInfo &f = ifaces[i];
        Napi::Object o = Napi::Object::New(env);
        o.Set("name", Napi::String::New(env, f.name));
        o.Set("mac", Napi::String::New(env, f.mac));
        o.Set("up", Napi::Boolean::New(env, f.up));
        o.Set("mtu", Napi::Number::New(env, (double)f.mtu));
        o.Set("description", Napi::String::New(env, f.description));

        Napi::Array addrs = Napi::Array::New(env, f.addresses.size());
        for (size_t j = 0; j < f.addresses.size(); j++)
        {
            Napi::Object ao = Napi::Object::New(env);
            ao.Set("family", Napi::String::New(env, f.addresses[j].family));
            ao.Set("address", Napi::String::New(env, f.addresses[j].address));
            ao.Set("netmask", Napi::String::New(env, f.addresses[j].netmask));
            addrs.Set((uint32_t)j, ao);
        }
        o.Set("addresses", addrs);
        o.Set("rx", counters(env, f.rxBytes, f.rxPackets, f.rxErrors, f.rxDropped));
        o.Set("tx", counters(env, f.txBytes, f.txPackets, f.txErrors, f.txDropped));
        arr.Set((uint32_t)i, o);
    }
    return arr;
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports.Set("list", Napi::Function::New(env, List));
    return exports;
}

NODE_API_MODULE(netkitty_iface, Init)
