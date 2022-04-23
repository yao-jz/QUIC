#include <iostream>
#include <time.h>
#include <ctime>
#include <ratio>
#include <chrono>
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
    utils::logger::info("CloseConnection\n");
    auto this_connection = this->connections[sequence];
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), 0, 0);
    std::shared_ptr<payload::ConnectionCloseAppFrame> close_frame = std::make_shared<payload::ConnectionCloseAppFrame>(errorCode,reason);
    std::shared_ptr<payload::Payload> close_payload = std::make_shared<payload::Payload>();
    close_payload->AttachFrame(close_frame);
    sockaddr_in addrTo = this_connection->getAddrTo();
    std::shared_ptr<payload::Packet> close_packet = std::make_shared<payload::Packet>(header, close_payload, addrTo);
    this_connection->insertIntoPending(close_packet);
    return 0;
}

int QUIC::SetConnectionCloseCallback(
    [[maybe_unused]] uint64_t sequence,
    [[maybe_unused]] ConnectionCloseCallbackType callback) {
    this->ConnectionCloseCallback = callback;
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
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
                pendingPackets.front()->MarkSendTimestamp(now);
                auto newDatagram = QUIC::encodeDatagram(pendingPackets.front());
                this->socket.sendMsg(newDatagram);
                connection.second->insertIntoUnAckedPackets(pendingPackets.front()->GetPacketNumber(), pendingPackets.front());
                pendingPackets.pop_front();
            }
        }
    }
    return 0;
}

uint64_t QUIC::CreateStream([[maybe_unused]] uint64_t sequence,
                            [[maybe_unused]] bool bidirectional) {
    if(!bidirectional)
        return uint64_t(2)|((this->stream_count[sequence]++) << 2);
    else
        return (this->stream_count[sequence]++) << 2;
}

uint64_t QUIC::CloseStream([[maybe_unused]] uint64_t sequence,
                           [[maybe_unused]] uint64_t streamID) {
    // TODO: 如果有没有发完的包，如果有的话，在这里需要全部发送
    utils::logger::info("CloseStream\n");
    auto this_connection = this->connections[sequence];
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum, this_connection->getLargestAcked());
    std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, nullptr, 0, 0, 0, true);
    std::shared_ptr<payload::Payload> stream_payload = std::make_shared<payload::Payload>();
    stream_payload->AttachFrame(stream_frame);
    sockaddr_in addrTo = this_connection->getAddrTo();
    std::shared_ptr<payload::Packet> stream_packet = std::make_shared<payload::Packet>(header, stream_payload, addrTo);
    this_connection->insertIntoPending(stream_packet);
    return 0;
}

uint64_t QUIC::SendData([[maybe_unused]] uint64_t sequence,
                        [[maybe_unused]] uint64_t streamID,
                        [[maybe_unused]] std::unique_ptr<uint8_t[]> buf,
                        [[maybe_unused]] size_t len,
                        [[maybe_unused]] bool FIN) {
    utils::logger::info("sendData, streamID is {}\n", streamID);
    auto this_connection = this->connections[sequence];
    // thquic::ConnectionID connection_id = this->connections[sequence]
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], this->pktnum, this_connection->getLargestAcked());
    std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, std::move(buf), len, 0, len, FIN);
    std::shared_ptr<payload::Payload> stream_payload = std::make_shared<payload::Payload>();
    stream_payload->AttachFrame(stream_frame);
    sockaddr_in addrTo = this->connections[sequence]->getAddrTo();
    std::shared_ptr<payload::Packet> stream_packet = std::make_shared<payload::Packet>(header, stream_payload, addrTo);
    this_connection->insertIntoPending(stream_packet);
    return 0;
}

int QUIC::SetStreamReadyCallback(
    [[maybe_unused]] uint64_t sequence,
    [[maybe_unused]] StreamReadyCallbackType callback) {
    
    QUICServer* server = static_cast<QUICServer*>(this);
    server->streamReadyCallback = callback;
    return 0;
}

int QUIC::SetStreamDataReadyCallback(
    [[maybe_unused]] uint64_t sequence, [[maybe_unused]] uint64_t streamID,
    [[maybe_unused]] StreamDataReadyCallbackType callback) {
    
    this->streamDataReadyCallback = callback;
    return 0;
}

std::shared_ptr<utils::UDPDatagram> QUIC::encodeDatagram(
    const std::shared_ptr<payload::Packet>& pkt) {
    utils::ByteStream stream(pkt->EncodeLen());
    pkt->Encode(stream);
    return std::make_shared<utils::UDPDatagram>(stream, pkt->GetAddrSrc(),
                                                pkt->GetAddrDst(), 0);
}


void QUIC::handleACKFrame(std::shared_ptr<payload::ACKFrame> ackFrame, uint64_t sequence) {
    std::list<utils::Interval> ackedIntervals = ackFrame->GetACKRanges().Intervals();
    for (utils::Interval interval : ackedIntervals) {
        utils::logger::warn("ACKED PACKETS: START = {}, END = {}", interval.Start(), interval.End());
        for (uint64_t packetNumber = interval.Start(); packetNumber <= interval.End(); packetNumber++) {
            // change tracking interval
            std::shared_ptr<thquic::payload::Packet> packet = this->connections[sequence]->getUnAckedPacket(packetNumber);
            for (auto frame : packet->GetPktPayload()->GetFrames()) {
                if(frame->Type() == payload::FrameType::ACK) {
                    std::shared_ptr<payload::ACKFrame> subFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                    uint64_t largestAcked = subFrame->GetLargestACKed();
                    this->connections[sequence]->getACKRanges().RemoveInterval(0, largestAcked);
                }
            }
            // remove acked packets
            this->connections[sequence]->removeFromUnAckedPackets(packetNumber);
        }
    }
}


int QUICClient::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    
    size_t bufferLen = datagram->BufferLen();
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), bufferLen);
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    payload::PacketType packetType = header->Type();
    utils::logger::info("RECV A PACKET FROM SERVER, PACKET NUMBER: {}", header->GetPacketNumber());
    switch (packetType) {
        case payload::PacketType::INITIAL:
        {
            utils::logger::warn("SERVER PacketType::INITIAL");
            this->connectionReadyCallback(this->ID2Sequence[header->GetDstID()]);
            std::shared_ptr<payload::LongHeader> lh = std::static_pointer_cast<payload::LongHeader>(header);
            this->SrcID2DstID[header->GetDstID()] = lh->GetSrcID();
            break;
        }
        case payload::PacketType::ZERO_RTT:
            utils::logger::warn("SERVER PacketType::ZERO_RTT");
            break;
        case payload::PacketType::HANDSHAKE:
            utils::logger::warn("SERVER PacketType::HANDSHAKE");
            break;
        case payload::PacketType::ONE_RTT: {
            utils::logger::warn("SERVER PacketType::ONE_RTT");
            uint64_t sequence = this->ID2Sequence[header->GetDstID()];
            uint64_t recvPacketNumber = header->GetPacketNumber();
            bool ackEliciting = false;
            std::list<std::shared_ptr<payload::Frame>> frames = payload::Payload(stream, bufferLen - stream.Pos()).GetFrames();
            for (auto frame : frames) {
                switch (frame->Type()) {
                    case payload::FrameType::STREAM: {
                        ackEliciting = true;
                        utils::logger::warn("SERVER Frame Type::STREAM");
                        std::shared_ptr<payload::StreamFrame> streamFrame = std::static_pointer_cast<payload::StreamFrame>(frame);
                        uint64_t streamID = streamFrame->StreamID();
                        // if (this->stream_count[sequence] <= streamID)
                        //     this->streamReadyCallback(sequence, streamID);
                        this->streamDataReadyCallback(sequence, streamID, streamFrame->FetchBuffer(), streamFrame->GetLength(), streamFrame->FINFlag());
                        break;
                    }
                    case payload::FrameType::CONNECTION_CLOSE: {
                        utils::logger::warn("SERVER Frame Type::CONNECTION_CLOSE");
                        this->ConnectionCloseCallback(sequence, "", 0);
                    }
                    case payload::FrameType::ACK:{
                        std::shared_ptr<payload::ACKFrame> ackFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                        this->handleACKFrame(ackFrame, sequence);
                    }
                }
            }
            if (ackEliciting) {
                this->connections[sequence]->getACKRanges().AddInterval(recvPacketNumber, recvPacketNumber);
            }
            break;
        }
        case payload::PacketType::RETRY:
            utils::logger::warn("SERVER PacketType::RETRY");
            break;
    }
    return 0;
}

int QUICServer::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    size_t bufferLen = datagram->BufferLen();
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), bufferLen);
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    uint64_t sequence = this->ID2Sequence[header->GetDstID()];
    uint64_t recvPacketNumber=header->GetPacketNumber();
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

    this->connections[sequence]->packetRecvTime[recvPacketNumber]=now;

    payload::PacketType packetType = header->Type();
    utils::logger::info("RECV A PACKET FROM CLIENT, PACKET NUMBER: {}", header->GetPacketNumber());
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
            utils::logger::warn("CLIENT PacketType::INITIAL");
            std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, id, this->SrcID2DstID[id], this->pktnum++, connection->getLargestAcked());
            std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
            std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, datagram->GetAddrSrc());
            std::shared_ptr<utils::UDPDatagram> initial_dg = QUIC::encodeDatagram(initial_packet);
            this->socket.sendMsg(initial_dg);
            utils::logger::warn("CLIENT INITIAL PACKET BACK");
            this->connectionReadyCallback(sequence);
            break;
        }
        case payload::PacketType::ONE_RTT: {
            utils::logger::warn("CLIENT PacketType::ONE_RTT");
            std::list<std::shared_ptr<payload::Frame>> frames = payload::Payload(stream, bufferLen - stream.Pos()).GetFrames();
            uint64_t sequence = this->ID2Sequence[header->GetDstID()];
            uint64_t recvPacketNumber = header->GetPacketNumber();
            bool ackEliciting = false;
            for (auto frame : frames) {
                utils::logger::warn("CLIENT Frame Type: {}", frame->Type());
                switch (frame->Type()) {
                    case payload::FrameType::STREAM: {
                        ackEliciting = true;
                        std::shared_ptr<payload::StreamFrame> streamFrame = std::static_pointer_cast<payload::StreamFrame>(frame);
                        uint64_t streamID = streamFrame->StreamID();
                        if (this->stream_count[sequence] <= streamID) {
                            this->streamReadyCallback(sequence, streamID);
                            stream_count[sequence] = streamID + 1;
                        }
                        this->streamDataReadyCallback(sequence, streamID, streamFrame->FetchBuffer(), streamFrame->GetLength(), streamFrame->FINFlag());
                        break;
                    }
                    case payload::FrameType::ACK: {
                        std::shared_ptr<payload::ACKFrame> ackFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                        this->handleACKFrame(ackFrame, sequence);
                    }
                    case payload::FrameType::CONNECTION_CLOSE: {
                        this->ConnectionCloseCallback(sequence, "", 0);
                    }
                }
            }
            if (ackEliciting) {
                this->connections[sequence]->getACKRanges().AddInterval(recvPacketNumber, recvPacketNumber);
            }
            break;
        }
        case payload::PacketType::HANDSHAKE:
            utils::logger::warn("SERVER PacketType::HANDSHAKE");
            break;
        case payload::PacketType::ZERO_RTT:
            utils::logger::warn("SERVER PacketType::ZERO_RTT");
            break;
        case payload::PacketType::RETRY:
            utils::logger::warn("SERVER PacketType::RETRY");
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
    this->addrTo = addrTo;
    ConnectionID id = ConnectionIDGenerator::Get().Generate();
    std::shared_ptr<Connection> connection = std::make_shared<Connection>();
    connection->setAddrTo(addrTo);
    uint64_t sequence = this->connectionSequence++;
    this->connections[sequence] = connection;
    this->ID2Sequence[id] = sequence;
    this->Sequence2ID[sequence] = id;
    std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, id, ConnectionID(), this->pktnum++, connection->getLargestAcked());
    std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
    std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, addrTo);
    std::shared_ptr<utils::UDPDatagram> initial_dg = QUIC::encodeDatagram(initial_packet);
    this->socket.sendMsg(initial_dg);
    this->connectionReadyCallback = callback;

    return 0;
}

}  // namespace thquic::context