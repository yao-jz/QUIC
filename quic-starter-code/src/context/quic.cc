#include <iostream>
#include "quic.hh"

namespace thquic::context {
thquic::context::QUIC::QUIC(thquic::context::PeerType type) : type(type) {
    if (type != PeerType::CLIENT) {
        throw std::invalid_argument("illegal client context config");
    }
}

QUIC::QUIC(PeerType type, uint16_t port, std::string address)
    : type(type), socket(port, address) {
    if (type != PeerType::SERVER || port == 0) {
        throw std::invalid_argument("illegal server context config.");
    }
}

int QUIC::CloseConnection([[maybe_unused]] uint64_t sequence,
                          [[maybe_unused]] const std::string& reason,
                          [[maybe_unused]] uint64_t errorCode) {
    return 0;
}

int QUIC::SetConnectionCloseCallback(
    [[maybe_unused]] uint64_t sequence,
    [[maybe_unused]] ConnectionCloseCallbackType callback) {
    return 0;
}

int QUIC::SocketLoop() {
    std::cout << "enter socket loop " << std::endl;
    for (;;) {
        auto datagram = this->socket.tryRecvMsg(10ms);
        if (datagram) {
            this->incomingMsg(std::move(datagram));
        }


        for (auto& connection : this->connections) {
            auto& pendingPackets = connection.second->GetPendingPackets();
            while (!pendingPackets.empty()) {
                auto newDatagram = QUIC::encodeDatagram(pendingPackets.front());
                this->socket.sendMsg(newDatagram);
                pendingPackets.pop_front();
            }
        }
    }
    return 0;
}

uint64_t QUIC::CreateStream([[maybe_unused]] uint64_t sequence,
                            [[maybe_unused]] bool bidirectional) {
    return 0;
}

uint64_t QUIC::CloseStream([[maybe_unused]] uint64_t sequence,
                           [[maybe_unused]] uint64_t streamID) {
    return 0;
}

uint64_t QUIC::SendData([[maybe_unused]] uint64_t sequence,
                        [[maybe_unused]] uint64_t streamID,
                        [[maybe_unused]] std::unique_ptr<uint8_t[]> buf,
                        [[maybe_unused]] size_t len,
                        [[maybe_unused]] bool FIN) {
    return 0;
}

int QUIC::SetStreamReadyCallback(
    [[maybe_unused]] uint64_t sequence,
    [[maybe_unused]] StreamReadyCallbackType callback) {
    return 0;
}

int QUIC::SetStreamDataReadyCallback(
    [[maybe_unused]] uint64_t sequence, [[maybe_unused]] uint64_t streamID,
    [[maybe_unused]] StreamDataReadyCallbackType callback) {
    return 0;
}

std::shared_ptr<utils::UDPDatagram> QUIC::encodeDatagram(
    const std::shared_ptr<payload::Packet>& pkt) {
    utils::ByteStream stream(pkt->EncodeLen());
    pkt->Encode(stream);
    return std::make_shared<utils::UDPDatagram>(stream, pkt->GetAddrSrc(),
                                                pkt->GetAddrDst(), 0);
}

/**
 * @brief 处理接收到的包
 * @param datagram 介绍到的报文
 * @return 返回包的处理结果
 * @author weiyz19
 */
int QUIC::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    //==================== start =======================//
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), datagram->BufferLen());
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    payload::PacketType packetType = header->Type();
    // TODO: 解析负载？需要嘛？
    switch(this->type) {
        case PeerType::SERVER:
        {
            switch (packetType) {
                case payload::PacketType::INITIAL:
                    utils::logger::warn("SERVER PacketType::INITIAL\n");
                    break;
                case payload::PacketType::ZERO_RTT:
                    utils::logger::warn("SERVER PacketType::ZERO_RTT\n");
                    break;
                case payload::PacketType::HANDSHAKE:
                    utils::logger::warn("SERVER PacketType::HANDSHAKE\n");
                    break;
                case payload::PacketType::ONE_RTT:
                    utils::logger::warn("SERVER PacketType::ONE_RTT\n");
                    break;
                case payload::PacketType::RETRY:
                    utils::logger::warn("SERVER PacketType::RETRY\n");
                    break;
            }
            break;
        }
        case PeerType::CLIENT:
        {
            switch (packetType) {
                case payload::PacketType::INITIAL:
                    utils::logger::warn("CLIENT PacketType::INITIAL\n");
                    break;
                case payload::PacketType::ZERO_RTT:
                    utils::logger::warn("CLIENT PacketType::ZERO_RTT\n");
                    break;
                case payload::PacketType::HANDSHAKE:
                    utils::logger::warn("CLIENT PacketType::HANDSHAKE\n");
                    break;
                case payload::PacketType::ONE_RTT:
                    utils::logger::warn("CLIENT PacketType::ONE_RTT\n");
                    break;
                case payload::PacketType::RETRY:
                    utils::logger::warn("CLIENT PacketType::RETRY\n");
                    break;
            }
            break;
        }
    }
    //==================== start =======================//
    return 0;
}

QUICServer::QUICServer(uint16_t port, std::string address)
    : QUIC(PeerType::SERVER, port, address) {}

int QUICServer::SetConnectionReadyCallback([
    [maybe_unused]] ConnectionReadyCallbackType callback) {
    return 0;
}

QUICClient::QUICClient() : QUIC(PeerType::CLIENT) {}

uint64_t QUICClient::CreateConnection(
    [[maybe_unused]] sockaddr_in& addrTo,
    [[maybe_unused]] const ConnectionReadyCallbackType& callback) {
    
    // 设置client的ip地址
    // struct sockaddr_in addrFrom {
    //     AF_INET, 25565, {inet_addr("127.0.0.1")}, {0}
    // };
    std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, ConnectionID(), ConnectionID(), 200, 200);
    std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
    std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, addrTo);
    std::shared_ptr<utils::UDPDatagram> initial_dg = QUIC::encodeDatagram(initial_packet);

    this->socket.sendMsg(initial_dg);
   
    return 0;
}

}  // namespace thquic::context