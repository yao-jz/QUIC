#include <iostream>
#include "quic.hh"

namespace thquic::context {
thquic::context::QUIC::QUIC(thquic::context::PeerType type) : type(type), connectionSequence(0) {
    if (type != PeerType::CLIENT) {
        throw std::invalid_argument("illegal client context config");
    }
}

QUIC::QUIC(PeerType type, uint16_t port, std::string address)
    : type(type), socket(port, address), connectionSequence(0) {
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
    if(!bidirectional)
        return uint64_t(2)|((this->stream_count[sequence]++)<<2);
    else
        return (this->stream_count[sequence]++)<<2;
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
    std::cout << "sendData, streamID is " << streamID << std::endl;
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], 0, 0);
    std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, std::move(buf), len, 0, len, FIN);
    std::shared_ptr<payload::Payload> stream_payload = std::make_shared<payload::Payload>();
    stream_payload->AttachFrame(stream_frame);
    sockaddr_in addrTo = this->connections[sequence]->getAddrTo();
    std::shared_ptr<payload::Packet> stream_packet = std::make_shared<payload::Packet>(header, stream_payload, addrTo);
    std::shared_ptr<utils::UDPDatagram> stream_dg = QUIC::encodeDatagram(stream_packet);
    this->socket.sendMsg(stream_dg);
    return 0;
}

int QUIC::SetStreamReadyCallback(
    [[maybe_unused]] uint64_t sequence,
    [[maybe_unused]] StreamReadyCallbackType callback) {
    
    QUICServer* server = static_cast<QUICServer*>(this);
    server->streamReadyCallback = std::bind(callback, sequence, std::placeholders::_1);
    return 0;
}

int QUIC::SetStreamDataReadyCallback(
    [[maybe_unused]] uint64_t sequence, [[maybe_unused]] uint64_t streamID,
    [[maybe_unused]] StreamDataReadyCallbackType callback) {
    
    this->streamDataReadyCallback = std::bind(callback, sequence, streamID, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3);
    return 0;
}

std::shared_ptr<utils::UDPDatagram> QUIC::encodeDatagram(
    const std::shared_ptr<payload::Packet>& pkt) {
    utils::ByteStream stream(pkt->EncodeLen());
    pkt->Encode(stream);
    return std::make_shared<utils::UDPDatagram>(stream, pkt->GetAddrSrc(),
                                                pkt->GetAddrDst(), 0);
}


int QUICClient::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    
    size_t bufferLen = datagram->BufferLen();
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), bufferLen);
    utils::logger::warn("building header...\n");
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    payload::PacketType packetType = header->Type();
    switch (packetType) {
        case payload::PacketType::INITIAL:
        {
            utils::logger::warn("SERVER PacketType::INITIAL\n");
            this->connectionReadyCallback(this->ID2Sequence[header->GetDstID()]);
            std::shared_ptr<payload::LongHeader> lh = std::static_pointer_cast<payload::LongHeader>(header);
            this->SrcID2DstID[header->GetDstID()] = lh->GetSrcID();
            break;
        }
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
    return 0;
}

int QUICServer::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    size_t bufferLen = datagram->BufferLen();
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), bufferLen);
    utils::logger::warn("building header...\n");
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    payload::PacketType packetType = header->Type();
    switch (packetType) {
        case payload::PacketType::INITIAL: {
            std::shared_ptr<Connection> connection = std::make_shared<Connection>();
            ConnectionID id = ConnectionIDGenerator::Get().Generate();
            connection->setAddrTo(datagram->GetAddrSrc());
            uint64_t sequence = this->connectionSequence++;
            this->connections[sequence] = connection;
            this->Sequence2ID[sequence] = id; 
            this->ID2Sequence[id] = sequence;
            std::shared_ptr<payload::LongHeader> lh = std::static_pointer_cast<payload::LongHeader>(header);
            this->SrcID2DstID[id] = lh->GetSrcID();
            utils::logger::warn("CLIENT PacketType::INITIAL\n");
            std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, id, this->SrcID2DstID[id], 200, 200);
            std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
            std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, datagram->GetAddrSrc());
            std::shared_ptr<utils::UDPDatagram> initial_dg = QUIC::encodeDatagram(initial_packet);
            this->socket.sendMsg(initial_dg);
            utils::logger::warn("CLIENT INITIAL PACKET BACK\n");
            this->connectionReadyCallback(sequence);
            break;
        }
        case payload::PacketType::ONE_RTT: {
            utils::logger::warn("CLIENT PacketType::ONE_RTT\n");
            std::list<std::shared_ptr<payload::Frame>> frames = payload::Payload(stream, bufferLen).GetFrames();
            for (auto frame : frames) {
                switch (frame->Type()) {
                    case payload::FrameType::STREAM: {
                        utils::logger::warn("CLIENT Frame Type::STREAM\n");
                        std::shared_ptr<payload::StreamFrame> s_frame = std::static_pointer_cast<payload::StreamFrame>(frame);
                        // default number:
                        uint64_t sequence = 0;
                        uint64_t stream_id = s_frame->StreamID();
                        this->streamReadyCallback(stream_id);
                        break;
                    }
                }
            }
            break;
        }
        case payload::PacketType::HANDSHAKE:
            utils::logger::warn("SERVER PacketType::HANDSHAKE\n");
            break;
        case payload::PacketType::ZERO_RTT:
            utils::logger::warn("SERVER PacketType::ONE_RTT\n");
            break;
        case payload::PacketType::RETRY:
            utils::logger::warn("SERVER PacketType::RETRY\n");
            break;
    }
    return 0;
}

QUICServer::QUICServer(uint16_t port, std::string address)
    : QUIC(PeerType::SERVER, port, address) {}

int QUICServer::SetConnectionReadyCallback([
    [maybe_unused]] ConnectionReadyCallbackType callback) {
    // for server, set connection readycallback
    this->connectionReadyCallback = callback;
    return 0;
}

QUICClient::QUICClient() : QUIC(PeerType::CLIENT) {}

uint64_t QUICClient::CreateConnection(
    [[maybe_unused]] sockaddr_in& addrTo,
    [[maybe_unused]] const ConnectionReadyCallbackType& callback) {
    
    // struct sockaddr_in addrFrom {
    //     AF_INET, this->socket.GetLocalPort(), {inet_addr("127.0.0.1")}, {0}
    // };
    this->addrTo = addrTo;
    ConnectionID id = ConnectionIDGenerator::Get().Generate();
    std::shared_ptr<Connection> connection = std::make_shared<Connection>();
    connection->setAddrTo(addrTo);
    uint64_t sequence = this->connectionSequence++;
    this->connections[sequence] = connection;
    this->ID2Sequence[id] = sequence;
    this->Sequence2ID[sequence] = id;
    std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, id, ConnectionID(), 200, 200);
    std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
    std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, addrTo);
    std::shared_ptr<utils::UDPDatagram> initial_dg = QUIC::encodeDatagram(initial_packet);
    this->socket.sendMsg(initial_dg);
    this->connectionReadyCallback = callback;

    return 0;
}

}  // namespace thquic::context