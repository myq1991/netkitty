#include "pcap_api.h"

// On POSIX this is an empty translation unit (pcap is linked directly via -lpcap).
// On Windows it holds the runtime-resolved wpcap.dll entry-point table.
#ifdef _WIN32

NkPcapApi g_nkpcap = {};

bool NkPcapLoad()
{
    static bool loaded = false;
    if (loaded) return true;

    // wpcap.dll ships in %SystemRoot%\System32\Npcap; SetWorkDirectoryForNpcapDlls()
    // (called from Prepare() before us) puts that directory on the DLL search path.
    HMODULE h = LoadLibraryExA("wpcap.dll", NULL,
                               LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS);
    if (h == NULL) return false;

    g_nkpcap.open_live = (pcap_t * (*)(const char *, int, int, int, char *)) GetProcAddress(h, "pcap_open_live");
    g_nkpcap.dispatch = (int (*)(pcap_t *, int, pcap_handler, u_char *)) GetProcAddress(h, "pcap_dispatch");
    g_nkpcap.compile = (int (*)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32)) GetProcAddress(h, "pcap_compile");
    g_nkpcap.freecode = (void (*)(struct bpf_program *)) GetProcAddress(h, "pcap_freecode");
    g_nkpcap.setfilter = (int (*)(pcap_t *, struct bpf_program *)) GetProcAddress(h, "pcap_setfilter");
    g_nkpcap.close_ = (void (*)(pcap_t *)) GetProcAddress(h, "pcap_close");
    g_nkpcap.findalldevs = (int (*)(pcap_if_t **, char *)) GetProcAddress(h, "pcap_findalldevs");
    g_nkpcap.setnonblock = (int (*)(pcap_t *, int, char *)) GetProcAddress(h, "pcap_setnonblock");
    g_nkpcap.setmintocopy = (int (*)(pcap_t *, int)) GetProcAddress(h, "pcap_setmintocopy");
    g_nkpcap.getevent = (HANDLE(*)(pcap_t *)) GetProcAddress(h, "pcap_getevent");

    loaded = g_nkpcap.open_live && g_nkpcap.dispatch && g_nkpcap.compile &&
             g_nkpcap.freecode && g_nkpcap.setfilter && g_nkpcap.close_ &&
             g_nkpcap.findalldevs && g_nkpcap.setnonblock &&
             g_nkpcap.setmintocopy && g_nkpcap.getevent;
    return loaded;
}

#endif // _WIN32
