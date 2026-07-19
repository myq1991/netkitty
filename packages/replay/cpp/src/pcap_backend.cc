#include "send_backend.h"
#include "pcap_api.h"

// The pcap fallback backend — portable, and the ONLY path on Windows (Npcap). Kept in its own
// translation unit: <pcap.h> declares struct bpf_program, which collides with the system <net/bpf.h>
// pulled in by the BPF backend in send_backend.cc. Isolating pcap.h here avoids that clash.

class PcapBackend : public ISendBackend
{
public:
    static PcapBackend *open(const std::string &device, std::string &err)
    {
        if (!NkPcapLoad())
        {
            err = "libpcap/Npcap not available (is Npcap installed?)";
            return nullptr;
        }
        char errbuf[PCAP_ERRBUF_SIZE] = "";
        pcap_t *h = pcap_open_live(device.c_str(), 65536, 0, 1000, errbuf);
        if (h == NULL)
        {
            err = errbuf[0] ? errbuf : "pcap_open_live failed";
            return nullptr;
        }
        return new PcapBackend(h);
    }
    ~PcapBackend() override
    {
        if (handle_) pcap_close(handle_);
    }
    int send(const unsigned char *data, int len) override { return pcap_sendpacket(handle_, data, len); }
    const char *name() const override { return "pcap"; }

private:
    explicit PcapBackend(pcap_t *h) : handle_(h) {}
    pcap_t *handle_;
};

ISendBackend *OpenPcapBackend(const std::string &device, std::string &err)
{
    return PcapBackend::open(device, err);
}
