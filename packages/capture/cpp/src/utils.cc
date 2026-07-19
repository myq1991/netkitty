#include "utils.h"

#ifdef __linux__
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
//
// Global public data
//
unsigned char cMacAddr[8]; // Server's MAC address

static int GetMacAddress(char *pIface)
{
    int nSD;                        // Socket descriptor
    struct ifreq sIfReq;            // Interface request
    struct if_nameindex *pIfList;   // Ptr to interface name index
    struct if_nameindex *pListSave; // Ptr to interface name index

    //
    // Initialize this function
    //
    pIfList = (struct if_nameindex *)NULL;
    pListSave = (struct if_nameindex *)NULL;
#ifndef SIOCGIFADDR
    // The kernel does not support the required ioctls
    return (0);
#endif

    //
    // Create a socket that we can use for all of our ioctls
    //
    nSD = socket(PF_INET, SOCK_STREAM, 0);
    if (nSD < 0)
    {
        // Socket creation failed, this is a fatal error
        printf("File %s: line %d: Socket failed\n", __FILE__, __LINE__);
        return (0);
    }

    //
    // Obtain a list of dynamically allocated structures
    //
    pIfList = pListSave = if_nameindex();

    //
    // Walk thru the array returned and query for each interface's
    // address
    //
    for (pIfList; *(char *)pIfList != 0; pIfList++)
    {
        //
        // Determine if we are processing the interface that we
        // are interested in
        //
        if (strcmp(pIfList->if_name, pIface))
            // Nope, check the next one in the list
            continue;
        strncpy(sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE);

        //
        // Get the MAC address for this interface
        //
        if (ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0)
        {
            // We failed to get the MAC address for the interface
            printf("File %s: line %d: Ioctl failed\n", __FILE__, __LINE__);
            return (0);
        }
        memmove((void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6);
        break;
    }

    //
    // Clean up things and return
    //
    if_freenameindex(pListSave);
    close(nSD);
    return (1);
}

#elif __APPLE__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

unsigned char cMacAddr[8]; // Server's MAC address

static int GetMacAddress(char *pIface)
{
    int mib[6];
    size_t len;
    char buf[1024];
    unsigned char *ptr;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;

    if ((mib[5] = if_nametoindex(pIface)) == 0)
        return 0;

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
        return 0;

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
        return 0;

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);
    memcpy((void *)&cMacAddr,ptr,6);
    return 1;
}
#elif defined(_WIN32)
#include <stdlib.h>
#include <string.h>
#include <iphlpapi.h>

unsigned char cMacAddr[8]; // Server's MAC address

// pcap device names on Windows look like "\Device\NPF_{GUID}"; GetAdaptersAddresses reports
// AdapterName as "{GUID}", so match on the GUID substring and copy the physical address.
static int GetMacAddress(char *pIface)
{
    const char *guid = strstr(pIface, "{");
    if (guid == NULL) return 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) return 0;
    IP_ADAPTER_ADDRESSES *adapters = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (adapters == NULL) return 0;
    int found = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &size) == ERROR_SUCCESS)
    {
        for (IP_ADAPTER_ADDRESSES *a = adapters; a != NULL; a = a->Next)
        {
            if (a->AdapterName != NULL && strcmp(a->AdapterName, guid) == 0)
            {
                if (a->PhysicalAddressLength >= 6)
                {
                    memcpy(cMacAddr, a->PhysicalAddress, 6);
                    found = 1;
                }
                break;
            }
        }
    }
    free(adapters);
    return found;
}
#endif

#ifdef _WIN32
#include <stdio.h>
#include <tchar.h>
#include <libloaderapi.h>
BOOL IsNpcapLoaded()
{
    HMODULE hNpcap = LoadLibraryExA(".\\Npcap\\Packet.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hNpcap == NULL)
    {
        return FALSE;
    }
    else
    {
        FreeLibrary(hNpcap);
        return TRUE;
    }
}
BOOL SetWorkDirectoryForNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len)
    {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0)
    {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

using namespace Napi;

Napi::Boolean Prepare(const Napi::CallbackInfo &info)
{
#ifdef _WIN32
    // check if Npcap is installed
    if (!IsNpcapLoaded())
    {
        // fprintf(stderr, "Npcap is not installed.\n");
        return Napi::Boolean::New(info.Env(), false);
    }

    /* Load Npcap and its functions. */
    if (!SetWorkDirectoryForNpcapDlls())
    {
        // fprintf(stderr, "Couldn't load Npcap\n");
        return Napi::Boolean::New(info.Env(), false);
    }

    // Resolve wpcap.dll entry points at runtime (no import lib, no bundled SDK).
    if (!NkPcapLoad())
    {
        return Napi::Boolean::New(info.Env(), false);
    }
#endif

    return Napi::Boolean::New(info.Env(), true);
}

Napi::Array GetNetworkInterfaces(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = nullptr, *dev;
    auto arr = Napi::Array::New(env);
    unsigned int index = 0;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        Napi::TypeError::New(env, errbuf)
            .ThrowAsJavaScriptException();
        return Napi::Array::New(env, 0);
    }

    for (dev = alldevs; dev != nullptr; dev = dev->next)
    {
        if (dev->addresses == nullptr)
            continue;
        if (dev->flags & PCAP_IF_LOOPBACK)
            continue; // If the interface is LoopInterface, continue
        Napi::Object deviceObject = Napi::Object::New(env);
        deviceObject.Set("name", Napi::String::New(env, dev->name));
        memset((void *)&cMacAddr[0], 0, sizeof(cMacAddr));
        GetMacAddress(dev->name);
        char macAddress[18];
        snprintf(macAddress, sizeof(macAddress), "%02X:%02X:%02X:%02X:%02X:%02X", cMacAddr[0], cMacAddr[1], cMacAddr[2],
                 cMacAddr[3],cMacAddr[4], cMacAddr[5]);
        deviceObject.Set("mac", Napi::String::New(env, (const char *)&macAddress));
        arr[index] = deviceObject;
        index++;
    }

    return arr;
}
