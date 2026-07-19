#ifndef NETKITTY_REPLAY_SEND_BACKEND_H
#define NETKITTY_REPLAY_SEND_BACKEND_H

#include <string>

// A packet-send backend: put one complete L2 frame on the wire. OpenSendBackend() picks the fastest
// available for the platform, matching tcpreplay's preference order (clean-room reimplemented):
//   Linux:   TX_RING (PACKET_MMAP) > PF_PACKET (raw AF_PACKET socket) > pcap_sendpacket
//   BSD/mac: BPF (/dev/bpf) > pcap_sendpacket
//   Windows: pcap_sendpacket (Npcap) only
// If the platform-native backend can't open (e.g. no CAP_NET_RAW / permission), it falls back to pcap.
class ISendBackend
{
public:
    virtual ~ISendBackend() {}
    virtual int send(const unsigned char *data, int len) = 0; // 0 = ok, -1 = error
    virtual const char *name() const = 0;
};

ISendBackend *OpenSendBackend(const std::string &device, std::string &err);

// The pcap fallback backend, defined in its own translation unit so <pcap.h> never shares a TU with
// the system <net/bpf.h> (both declare struct bpf_program).
ISendBackend *OpenPcapBackend(const std::string &device, std::string &err);

#endif
