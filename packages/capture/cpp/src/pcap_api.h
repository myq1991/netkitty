#ifndef NETKITTY_PCAP_API_H
#define NETKITTY_PCAP_API_H

// One seam for reaching libpcap/Npcap without vendoring any third-party header or
// import library:
//   - POSIX/macOS: include the system <pcap.h> and link -lpcap normally.
//   - Windows: there is no system libpcap. We declare the minimal, long-stable
//     libpcap ABI this addon actually uses and resolve wpcap.dll at RUNTIME
//     (LoadLibrary/GetProcAddress) in NkPcapLoad(); nothing is bundled. The end
//     user must have Npcap installed.

#ifndef _WIN32

#include <pcap.h>
static inline bool NkPcapLoad() { return true; }

#else // _WIN32

#include <winsock2.h> // struct timeval, u_char / u_int typedefs (include before windows.h)
#include <windows.h>  // HANDLE, LoadLibrary, GetProcAddress

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE 256
#endif
#define PCAP_IF_LOOPBACK 0x00000001

typedef unsigned int bpf_u_int32;

typedef struct pcap pcap_t; // opaque capture handle

struct pcap_pkthdr
{
    struct timeval ts;  // time stamp
    bpf_u_int32 caplen; // length of portion present
    bpf_u_int32 len;    // length of this packet on the wire
};

struct pcap_addr; // opaque; only referenced as a pointer
struct pcap_if
{
    struct pcap_if *next;
    char *name;
    char *description;
    struct pcap_addr *addresses;
    bpf_u_int32 flags;
};
typedef struct pcap_if pcap_if_t;

struct bpf_insn; // opaque
struct bpf_program
{
    u_int bf_len;
    struct bpf_insn *bf_insns;
};

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

// wpcap.dll entry points, resolved at runtime. All exports are __cdecl.
struct NkPcapApi
{
    pcap_t *(*open_live)(const char *, int, int, int, char *);
    int (*dispatch)(pcap_t *, int, pcap_handler, u_char *);
    int (*compile)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
    void (*freecode)(struct bpf_program *);
    int (*setfilter)(pcap_t *, struct bpf_program *);
    void (*close_)(pcap_t *);
    int (*findalldevs)(pcap_if_t **, char *);
    int (*setnonblock)(pcap_t *, int, char *);
    int (*setmintocopy)(pcap_t *, int);
    HANDLE (*getevent)(pcap_t *);
};
extern NkPcapApi g_nkpcap;

// Load wpcap.dll and resolve every entry point once (idempotent). Returns false
// if the DLL or any symbol is missing (Npcap not installed / too old).
bool NkPcapLoad();

#define pcap_open_live g_nkpcap.open_live
#define pcap_dispatch g_nkpcap.dispatch
#define pcap_compile g_nkpcap.compile
#define pcap_freecode g_nkpcap.freecode
#define pcap_setfilter g_nkpcap.setfilter
#define pcap_close g_nkpcap.close_
#define pcap_findalldevs g_nkpcap.findalldevs
#define pcap_setnonblock g_nkpcap.setnonblock
#define pcap_setmintocopy g_nkpcap.setmintocopy
#define pcap_getevent g_nkpcap.getevent

#endif // _WIN32

#endif // NETKITTY_PCAP_API_H
