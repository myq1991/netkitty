#include "send_backend.h"

// The pcap backend lives in pcap_backend.cc (its own TU) so <pcap.h> is never included alongside the
// system <net/bpf.h> used by the BPF backend below (both declare struct bpf_program).

// ---------------------------------------------------------------- Linux: PF_PACKET raw socket

#ifdef __linux__
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cstdint>
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

// TX_RING (PACKET_MMAP): a ring buffer shared with the kernel via mmap. Frames are copied into ring
// slots and transmitted in batches with a single send(), removing the per-frame syscall+copy that caps
// PF_PACKET's rate. This is the high-throughput path for traffic generation. In paced modes the engine
// calls flush() after every frame, so it degrades gracefully to one-frame-per-kick.
class TxRingBackend : public ISendBackend
{
public:
    static TxRingBackend *open(const std::string &device, std::string &err)
    {
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0)
        {
            err = std::string("AF_PACKET socket: ") + strerror(errno);
            return nullptr;
        }
        int ver = TPACKET_V2;
        if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0)
        {
            err = std::string("PACKET_VERSION: ") + strerror(errno);
            ::close(fd);
            return nullptr;
        }
        struct tpacket_req req;
        memset(&req, 0, sizeof(req));
        req.tp_frame_size = FRAME_SIZE;
        req.tp_block_size = BLOCK_SIZE;
        req.tp_block_nr = BLOCK_NR;
        req.tp_frame_nr = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;
        if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0)
        {
            err = std::string("PACKET_TX_RING: ") + strerror(errno);
            ::close(fd);
            return nullptr;
        }
        size_t ringBytes = (size_t)req.tp_block_size * req.tp_block_nr;
        void *ring = mmap(nullptr, ringBytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ring == MAP_FAILED)
        {
            err = std::string("mmap tx ring: ") + strerror(errno);
            ::close(fd);
            return nullptr;
        }
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
        {
            err = std::string("SIOCGIFINDEX ") + device + ": " + strerror(errno);
            munmap(ring, ringBytes);
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
            munmap(ring, ringBytes);
            ::close(fd);
            return nullptr;
        }
        //Best-effort: bypass the qdisc layer for lower overhead (ignored on kernels < 3.14).
        int one = 1;
        setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
        return new TxRingBackend(fd, (uint8_t *)ring, ringBytes, req.tp_frame_nr);
    }

    ~TxRingBackend() override
    {
        if (ring_) munmap(ring_, ringBytes_);
        if (fd_ >= 0) ::close(fd_);
    }

    int send(const unsigned char *data, int len) override
    {
        const size_t dataOff = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
        if ((size_t)len > FRAME_SIZE - dataOff) return -1; // frame too large for a ring slot
        struct tpacket2_hdr *hdr = frame(cur_);
        //Wait until the kernel has finished with this slot, kicking to drain if it is still busy.
        for (;;)
        {
            uint32_t st = status(hdr);
            if (st == TP_STATUS_AVAILABLE) break;
            if (st & TP_STATUS_WRONG_FORMAT) { setStatus(hdr, TP_STATUS_AVAILABLE); break; }
            if (kick(0) < 0 && errno != ENOBUFS) return -1;
            struct pollfd pfd;
            pfd.fd = fd_;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            poll(&pfd, 1, 100);
        }
        memcpy((uint8_t *)hdr + dataOff, data, (size_t)len);
        hdr->tp_len = (unsigned int)len;
        setStatus(hdr, TP_STATUS_SEND_REQUEST);
        cur_ = (cur_ + 1) % frameNr_;
        if (++pending_ >= KICK_BATCH)
        {
            kick(MSG_DONTWAIT);
            pending_ = 0;
        }
        return 0;
    }

    int flush() override
    {
        pending_ = 0;
        //Blocking kick: transmit every queued frame before returning.
        return kick(0) < 0 ? -1 : 0;
    }

    const char *name() const override { return "tx_ring"; }

private:
    static const size_t FRAME_SIZE = 2048;      // per-slot size (>= header + 1518 MTU frame)
    static const size_t BLOCK_SIZE = 1 << 17;   // 128 KiB block = 64 frames
    static const size_t BLOCK_NR = 16;          // 1024 frames total (2 MiB ring)
    static const unsigned KICK_BATCH = 64;      // enqueue this many before a non-blocking kick

    TxRingBackend(int fd, uint8_t *ring, size_t ringBytes, unsigned frameNr)
        : fd_(fd), ring_(ring), ringBytes_(ringBytes), frameNr_(frameNr), cur_(0), pending_(0) {}

    struct tpacket2_hdr *frame(unsigned i) { return (struct tpacket2_hdr *)(ring_ + (size_t)i * FRAME_SIZE); }
    static uint32_t status(struct tpacket2_hdr *h) { return __atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE); }
    static void setStatus(struct tpacket2_hdr *h, uint32_t s) { __atomic_store_n(&h->tp_status, s, __ATOMIC_RELEASE); }
    int kick(int flags) { return (int)::send(fd_, nullptr, 0, flags); }

    int fd_;
    uint8_t *ring_;
    size_t ringBytes_;
    unsigned frameNr_;
    unsigned cur_;
    unsigned pending_;
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
    //TX_RING (PACKET_MMAP) > PF_PACKET > pcap.
    if (ISendBackend *b = TxRingBackend::open(device, nativeErr)) return b;
    {
        std::string pfErr;
        if (ISendBackend *b = PfPacketBackend::open(device, pfErr)) return b;
        if (!pfErr.empty()) nativeErr = pfErr;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    if (ISendBackend *b = BpfBackend::open(device, nativeErr)) return b;
#endif
    std::string pcapErr;
    if (ISendBackend *b = OpenPcapBackend(device, pcapErr)) return b;
    err = !pcapErr.empty() ? pcapErr : (!nativeErr.empty() ? nativeErr : "no send backend could open the device");
    return nullptr;
}
