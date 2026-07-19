#include "pcap_api.h"

// POSIX: empty TU (pcap linked directly via -lpcap). Windows: resolve wpcap.dll at runtime.
#ifdef _WIN32

NkReplayPcapApi g_nkpcap = {};

// Npcap installs wpcap.dll in %SystemRoot%\System32 (WinPcap-compatible mode) and in a Npcap subdir;
// add that subdir to the DLL search path so wpcap.dll and its Packet.dll dependency both resolve.
static void addNpcapDllDir()
{
    wchar_t dir[512];
    UINT n = GetSystemDirectoryW(dir, 500);
    if (n > 0 && n < 500)
    {
        wcscat_s(dir, 512, L"\\Npcap");
        AddDllDirectory(dir);
        SetDllDirectoryW(dir);
    }
}

bool NkPcapLoad()
{
    static bool loaded = false;
    if (loaded) return true;

    addNpcapDllDir();
    HMODULE h = LoadLibraryExA("wpcap.dll", NULL,
                               LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (h == NULL) return false;

    g_nkpcap.open_live = (pcap_t * (*)(const char *, int, int, int, char *)) GetProcAddress(h, "pcap_open_live");
    g_nkpcap.sendpacket = (int (*)(pcap_t *, const unsigned char *, int)) GetProcAddress(h, "pcap_sendpacket");
    g_nkpcap.geterr = (char *(*)(pcap_t *)) GetProcAddress(h, "pcap_geterr");
    g_nkpcap.close_ = (void (*)(pcap_t *)) GetProcAddress(h, "pcap_close");

    loaded = g_nkpcap.open_live && g_nkpcap.sendpacket && g_nkpcap.geterr && g_nkpcap.close_;
    return loaded;
}

#endif // _WIN32
