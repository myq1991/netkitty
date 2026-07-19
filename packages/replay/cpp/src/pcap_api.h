#ifndef NETKITTY_REPLAY_PCAP_API_H
#define NETKITTY_REPLAY_PCAP_API_H

// One seam for reaching libpcap/Npcap without vendoring any header or import library — mirrors the
// approach in @netkitty/capture but trimmed to just what sending needs (open_live / sendpacket /
// geterr / close). POSIX: system <pcap.h> + link -lpcap. Windows: minimal declarations + runtime
// LoadLibrary of wpcap.dll (the user must have Npcap installed).

#ifndef _WIN32

#include <pcap.h>
static inline bool NkPcapLoad() { return true; }

#else // _WIN32

#include <windows.h>

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif

typedef struct pcap pcap_t; // opaque handle

struct NkReplayPcapApi
{
    pcap_t *(*open_live)(const char *, int, int, int, char *);
    int (*sendpacket)(pcap_t *, const unsigned char *, int);
    char *(*geterr)(pcap_t *);
    void (*close_)(pcap_t *);
};
extern NkReplayPcapApi g_nkpcap;

// Point the loader at the Npcap directory, load wpcap.dll and resolve entry points once (idempotent).
// Returns false if Npcap is not installed / a symbol is missing.
bool NkPcapLoad();

#define pcap_open_live g_nkpcap.open_live
#define pcap_sendpacket g_nkpcap.sendpacket
#define pcap_geterr g_nkpcap.geterr
#define pcap_close g_nkpcap.close_

#endif // _WIN32

#endif
