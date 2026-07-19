#include "send_backend.h"

// The pcap backend lives in pcap_backend.cc (its own TU) so <pcap.h> is never included alongside the
// system <net/bpf.h> used by the BPF backend below (both declare struct bpf_program).

// ---------------------------------------------------------------- Linux: PF_PACKET raw socket

#ifdef __linux__
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>

class PfPacketBackend : public ISendBackend
{
public:
    static PfPacketBackend *open(const std::string &device, std::string &err)
    {
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0)
        {
            err = std::string("AF_PACKET socket: ") + strerror(errno);
            return nullptr;
        }
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        {
            err = std::string("SIOCGIFINDEX ") + device + ": " + strerror(errno);
            ::close(fd);
            return nullptr;
        }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
        {
            err = std::string("bind AF_PACKET: ") + strerror(errno);
            ::close(fd);
            return nullptr;
        }
        return new PfPacketBackend(fd);
    }
    ~PfPacketBackend() override
    {
        if (fd_ >= 0) ::close(fd_);
    }
    int send(const unsigned char *data, int len) override
    {
        ssize_t r = ::send(fd_, data, (size_t)len, 0);
        return r == (ssize_t)len ? 0 : -1;
    }
    const char *name() const override { return "pf_packet"; }

private:
    explicit PfPacketBackend(int fd) : fd_(fd) {}
    int fd_;
};
#endif // __linux__

// ---------------------------------------------------------------- BSD/macOS: BPF (/dev/bpf)

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstdio>

class BpfBackend : public ISendBackend
{
public:
    static BpfBackend *open(const std::string &device, std::string &err)
    {
        int fd = -1;
        for (int i = 0; i < 256; i++)
        {
            char path[32];
            snprintf(path, sizeof(path), "/dev/bpf%d", i);
            fd = ::open(path, O_RDWR);
            if (fd >= 0) break;
            if (errno == EBUSY) continue;
            if (errno == ENOENT) break;
        }
        if (fd < 0)
        {
            err = std::string("open /dev/bpf: ") + strerror(errno);
            return nullptr;
        }
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, BIOCSETIF, &ifr) < 0)
        {
            err = std::string("BIOCSETIF ") + device + ": " + strerror(errno);
            ::close(fd);
            return nullptr;
        }
        //We supply complete L2 headers (do not let BPF fill in the source MAC).
        unsigned int one = 1;
        ioctl(fd, BIOCSHDRCMPLT, &one);
        return new BpfBackend(fd);
    }
    ~BpfBackend() override
    {
        if (fd_ >= 0) ::close(fd_);
    }
    int send(const unsigned char *data, int len) override
    {
        ssize_t r = ::write(fd_, data, (size_t)len);
        return r == (ssize_t)len ? 0 : -1;
    }
    const char *name() const override { return "bpf"; }

private:
    explicit BpfBackend(int fd) : fd_(fd) {}
    int fd_;
};
#endif // BSD/macOS

// ---------------------------------------------------------------- selection

ISendBackend *OpenSendBackend(const std::string &device, std::string &err)
{
    std::string nativeErr;
#ifdef __linux__
    //TX_RING > PF_PACKET > pcap. (TX_RING added later; PF_PACKET is the primary for now.)
    if (ISendBackend *b = PfPacketBackend::open(device, nativeErr)) return b;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    if (ISendBackend *b = BpfBackend::open(device, nativeErr)) return b;
#endif
    std::string pcapErr;
    if (ISendBackend *b = OpenPcapBackend(device, pcapErr)) return b;
    err = !pcapErr.empty() ? pcapErr : (!nativeErr.empty() ? nativeErr : "no send backend could open the device");
    return nullptr;
}
