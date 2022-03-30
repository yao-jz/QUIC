#include "socket.hh"

namespace thquic::utils {

UDPDatagram::UDPDatagram()
    : CMsgBuffer{},
      srcAddr{},
      dstAddr{},
      destIf(0),
      ecn(0),
      dataBuf{},
      socketMsgHdr{} {
    this->buffer = std::make_unique<uint8_t[]>(MSG_BUFFER_SIZE);
    this->bufferSize = MSG_BUFFER_SIZE;

    this->dataBuf.iov_base = this->buffer.get();
    this->dataBuf.iov_len = this->bufferSize;

    this->socketMsgHdr.msg_name = &this->srcAddr;
    this->socketMsgHdr.msg_namelen = sizeof(struct sockaddr_storage);
    this->socketMsgHdr.msg_iov = &dataBuf;
    this->socketMsgHdr.msg_iovlen = 1;
    this->socketMsgHdr.msg_flags = 0;
    this->socketMsgHdr.msg_control = static_cast<void*>(this->CMsgBuffer);
    this->socketMsgHdr.msg_controllen = CMSG_BUFFER_SIZE;

    this->lastCMsg = nullptr;
    this->CMsgLen = 0;
}

UDPDatagram::UDPDatagram(ByteStream& stream, struct sockaddr_in srcAddr,
                         struct sockaddr_in dstAddr, uint8_t ecn)
    : buffer(stream.FetchBuffer()),
      bufferSize(stream.GetBufferLen()),
      CMsgBuffer{},
      srcAddr{srcAddr},
      dstAddr{dstAddr},
      ecn(ecn),
      dataBuf{buffer.get(), bufferSize},
      socketMsgHdr{} {
    this->socketMsgHdr.msg_name = &this->dstAddr;
    this->socketMsgHdr.msg_namelen = sizeof(struct sockaddr_in);
    this->socketMsgHdr.msg_iov = &dataBuf;
    this->socketMsgHdr.msg_iovlen = 1;
    this->socketMsgHdr.msg_control = (void*)CMsgBuffer;
    this->socketMsgHdr.msg_controllen = CMSG_BUFFER_SIZE;

    this->lastCMsg = nullptr;
    this->CMsgLen = 0;

    this->synthesisCMsg();
}

int UDPDatagram::parseCMsg() {
    struct cmsghdr* cmsg;

    for (cmsg = CMSG_FIRSTHDR(&this->socketMsgHdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&this->socketMsgHdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP) {
            if (cmsg->cmsg_type == IP_PKTINFO) {
                auto pPktInfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
                this->dstAddr.sin_family = AF_INET;
                this->dstAddr.sin_port = 0;
                this->dstAddr.sin_addr.s_addr = pPktInfo->ipi_addr.s_addr;
                this->destIf = pPktInfo->ipi_ifindex;
            }
        } else if ((cmsg->cmsg_type == IP_TOS ||
                    cmsg->cmsg_type == IP_RECVTOS) &&
                   cmsg->cmsg_len > 0) {
            this->ecn = *(static_cast<unsigned char*>(CMSG_DATA(cmsg)));
        }
    }
    return 0;
}

int UDPDatagram::setDestAddrPort(uint16_t port) {
    this->dstAddr.sin_port = port;
    return 0;
}

int UDPDatagram::synthesisCMsg() {
    auto pktinfo = static_cast<struct in_pktinfo*>(this->getCMsgNextPtr(
        IPPROTO_IP, IP_PKTINFO, sizeof(struct in_pktinfo)));
    if (pktinfo != nullptr) {
        pktinfo->ipi_addr.s_addr = this->srcAddr.sin_addr.s_addr;
        // TODO: Is this necessary ?
        // pktinfo->ipi_ifindex = this->destIf;
    }
    this->socketMsgHdr.msg_controllen = this->CMsgLen;
    if (this->socketMsgHdr.msg_controllen == 0) {
        this->socketMsgHdr.msg_control = nullptr;
    }
    return 0;
}

void* UDPDatagram::getCMsgNextPtr(int CMsgLevel, int CMsgType,
                                  size_t CMsgDataLen) {
    struct cmsghdr* cmsg =
        (this->lastCMsg == NULL)
            ? CMSG_FIRSTHDR(&this->socketMsgHdr)
            : reinterpret_cast<struct cmsghdr*>(
                  reinterpret_cast<uint8_t*>(this->lastCMsg) +
                  CMSG_ALIGN(this->lastCMsg->cmsg_len));

    if (this->lastCMsg != NULL) {
        size_t CMsgRequiredSpace = CMSG_SPACE(CMsgDataLen);
        this->CMsgLen += CMsgRequiredSpace;
        memset(cmsg, 0, CMsgRequiredSpace);

        cmsg->cmsg_level = CMsgLevel;
        cmsg->cmsg_type = CMsgType;
        cmsg->cmsg_len = CMSG_LEN(CMsgDataLen);
        this->lastCMsg = cmsg;
        return static_cast<void*>(CMSG_DATA(cmsg));
    }

    return nullptr;
}

struct msghdr* UDPDatagram::rawMsgHdr() {
    return &this->socketMsgHdr;
}

const std::unique_ptr<uint8_t[]>& UDPDatagram::Buffer() const {
    return this->buffer;
}

std::unique_ptr<uint8_t[]> UDPDatagram::FetchBuffer() {
    return std::move(this->buffer);
}

void UDPDatagram::SetBufferLen(size_t bufferSize) {
    this->bufferSize = bufferSize;
}

size_t UDPDatagram::BufferLen() const { return this->bufferSize; }

const struct sockaddr_in& UDPDatagram::GetAddrSrc() { return this->srcAddr; }

const struct sockaddr_in& UDPDatagram::GetAddrDst() { return this->dstAddr; }

UDPSocket::UDPSocket(int localPort, std::string localAddress) {
    this->localPort = localPort;
    this->buffer = nullptr;
    this->socketFD = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    this->setSockOption();

    if (this->socketFD == INVALID_SOCKET) {
        throw std::system_error(errno, std::generic_category());
    }

    if (this->localPort != 0) {
        this->bindToPort(localAddress);
    }

    this->buffer = std::make_unique<char[]>(MSG_BUFFER_SIZE);
    this->bufferSize = MSG_BUFFER_SIZE;

    this->sendECNSet = false;
    this->recvECNSet = false;
}

UDPSocket::~UDPSocket() {
    if (this->socketFD != INVALID_SOCKET) {
        if (close(this->socketFD) < 0) {
            // TODO: log this rare case but exit normally.
        }
        this->socketFD = INVALID_SOCKET;
    }
}

int UDPSocket::setSockOption() {
    int set = 1;
    if (setsockopt(this->socketFD, IPPROTO_IP, IP_PKTINFO,
                   static_cast<const void*>(&set), sizeof(int)) < 0) {
        throw std::system_error(errno, std::generic_category());
    }

    uint32_t ecn = IPTOS_MINCOST;
    /* Request setting ECN_ECT_0 in outgoing packets */
    this->sendECNSet =
        setsockopt(this->socketFD, IPPROTO_IP, IP_TOS,
                   static_cast<const void*>(&ecn), sizeof(ecn)) >= 0;

    set = 1;
    this->recvECNSet =
        setsockopt(this->socketFD, IPPROTO_IP, IP_RECVTOS,
                   static_cast<const void*>(&set), sizeof(int)) >= 0;

    return 0;
}

int UDPSocket::bindToPort(std::string localAddress) {
    struct sockaddr_in address {};
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = (unsigned short)this->localPort;
    if (!localAddress.empty()) {
        address.sin_addr = {inet_addr(localAddress.c_str())};
    }

    constexpr int ADDRESS_LENGTH = sizeof(struct sockaddr_in);
    if (bind(this->socketFD, reinterpret_cast<struct sockaddr*>(&address),
             ADDRESS_LENGTH) < 0) {
        throw std::system_error(errno, std::generic_category());
    }

    struct sockaddr_in localAddr {};
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(this->socketFD,
                    reinterpret_cast<struct sockaddr*>(&localAddr), &len) < 0) {
        throw std::system_error(errno, std::generic_category());
    }

    utils::logger::warn("QUIC context listen on {}",
                        utils::formatNetworkAddress(localAddr));

    return 0;
}

std::unique_ptr<UDPDatagram> UDPSocket::tryRecvMsg(clock::duration timeout) {
    fd_set readFDs;
    FD_ZERO(&readFDs);
    FD_SET(this->socketFD, &readFDs);

    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timeout - seconds);
    struct timeval tv {};
    tv.tv_sec = static_cast<long>(seconds.count());
    tv.tv_usec = static_cast<long>(milliseconds.count());

    int ret = select(this->socketFD + 1, &readFDs, NULL, NULL, &tv);
    if (ret == -1) {
        throw std::system_error(errno, std::generic_category());
    }

    if (ret > 0 && FD_ISSET(this->socketFD, &readFDs)) {
        return this->recvMsg();
    }
    return nullptr;
}

int UDPSocket::trySendMsg(std::shared_ptr<utils::UDPDatagram> datagram,
                          clock::duration timeout) {
    fd_set writeFDs;
    FD_ZERO(&writeFDs);
    FD_SET(this->socketFD, &writeFDs);

    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timeout - seconds);
    struct timeval tv {
        static_cast<long>(seconds.count()),
            static_cast<long>(milliseconds.count())
    };

    int ret = select(this->socketFD + 1, NULL, &writeFDs, NULL, &tv);
    if (ret == -1) {
        throw std::system_error(errno, std::generic_category());
    }
    if (ret > 0 && FD_ISSET(this->socketFD, &writeFDs)) {
        return this->sendMsg(std::move(datagram), false);
    }
    return 0;
}

std::unique_ptr<UDPDatagram> UDPSocket::recvMsg() {
    int bytesRecv = 0;

    auto datagram = std::make_unique<UDPDatagram>();

    bytesRecv = recvmsg(this->socketFD, datagram->rawMsgHdr(), 0);

    if (bytesRecv > 0) {
        datagram->parseCMsg();
        datagram->setDestAddrPort(this->GetLocalPort());
        datagram->SetBufferLen(bytesRecv);
        return datagram;
    }

    if (bytesRecv < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return nullptr;
        }
        throw std::system_error(errno, std::generic_category());
    }

    return nullptr;
}

int UDPSocket::sendMsg(const std::shared_ptr<utils::UDPDatagram>& datagram,
                       bool trySelect) {
    int bytesSent;

    bytesSent = sendmsg(this->socketFD, datagram->rawMsgHdr(), 0);
    if (bytesSent == -1) {
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && trySelect) {
            this->trySendMsg(datagram, 50ms);
        }
        throw std::system_error(errno, std::generic_category());
    }
    return 0;
}

uint16_t UDPSocket::GetLocalPort() {
    if (this->localPort == 0) {
        this->getSocketLocalPort();
    }
    return this->localPort;
}

int UDPSocket::getSocketLocalPort() {
    struct sockaddr_storage localAddr {};
    socklen_t len = sizeof(struct sockaddr_storage);
    int ret = getsockname(this->socketFD,
                          reinterpret_cast<struct sockaddr*>(&localAddr), &len);
    if (ret != 0) {
        throw std::system_error(errno, std::generic_category());
    }
    this->localPort =
        reinterpret_cast<struct sockaddr_in*>(&localAddr)->sin_port;
    return 0;
}
}  // namespace thquic::utils