#ifndef THQUIC_UTILS_SOCKET_HH
#define THQUIC_UTILS_SOCKET_HH

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "time.hh"
#include "utils/bytestream.hh"
#include "utils/chunkstream.hh"
#include "utils/log.hh"

namespace thquic {
using namespace std::chrono_literals;

namespace utils {

constexpr int INVALID_SOCKET = -1;
constexpr int MSG_BUFFER_SIZE = 1536;
constexpr int CMSG_BUFFER_SIZE = 1024;

class UDPDatagram {
   public:
    UDPDatagram();

    UDPDatagram(utils::ByteStream& stream, struct sockaddr_in srcAddr,
                struct sockaddr_in dstAddr, uint8_t ecn);

    int parseCMsg();

    int setDestAddrPort(uint16_t port);

    int synthesisCMsg();

    void* getCMsgNextPtr(int CMsgLevel, int CMsgType, size_t CMsgDataLen);

    struct msghdr* rawMsgHdr();

    const std::unique_ptr<uint8_t[]>& Buffer() const;

    std::unique_ptr<uint8_t[]> FetchBuffer();

    void SetBufferLen(size_t bufferSize);

    size_t BufferLen() const;

    const struct sockaddr_in& GetAddrSrc();
    const struct sockaddr_in& GetAddrDst();

   private:
    std::unique_ptr<uint8_t[]> buffer;
    size_t bufferSize;

    uint8_t CMsgBuffer[CMSG_BUFFER_SIZE];

    struct sockaddr_in srcAddr;
    struct sockaddr_in dstAddr;
    int destIf;
    uint8_t ecn;

    struct iovec dataBuf;
    struct msghdr socketMsgHdr;

    struct cmsghdr* lastCMsg;
    size_t CMsgLen;
};

class UDPSocket {
   public:
    UDPSocket(int localPort = 0, std::string localAddress = "");

    ~UDPSocket();

    int setSockOption();

    int bindToPort(std::string localAddress);

    std::unique_ptr<UDPDatagram> tryRecvMsg(clock::duration timeout);

    int trySendMsg(std::shared_ptr<utils::UDPDatagram> datagram,
                   clock::duration timeout);

    std::unique_ptr<UDPDatagram> recvMsg();

    int sendMsg(const std::shared_ptr<utils::UDPDatagram>& datagram,
                bool trySelect = true);

    uint16_t GetLocalPort();

    int getSocketLocalPort();

   private:
    std::unique_ptr<char[]> buffer;
    int bufferSize;

    int localPort;
    int socketFD;

    bool sendECNSet;
    bool recvECNSet;
};
}  // namespace utils
}  // namespace thquic

#endif
