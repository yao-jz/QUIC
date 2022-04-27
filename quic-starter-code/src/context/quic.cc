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
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum++, this_connection->getLargestAcked());
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

std::list<std::shared_ptr<payload::Packet>> QUIC::getPackets(std::shared_ptr<thquic::context::Connection> connection)
{
    std::map<uint64_t,std::shared_ptr<payload::Packet>> unAckedPackets = connection->getUnAckedPackets();
    // 超时重传
    std::vector<uint64_t> packetNumsDel;
    for(auto packet_pair : unAckedPackets)
    {
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        if(duration_cast<std::chrono::milliseconds>(now - packet_pair.second->GetSendTimestamp()).count() > 7500)
        {

            this->pendingPackets.push_back(packet_pair.second);
            packetNumsDel.push_back(packet_pair.first);
        }
    }


    if(!pendingPackets.empty() && !this->ACKRanges.Empty())
    {
        std::shared_ptr<payload::Packet> packet = pendingPackets.front();
        std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(20, this->ACKRanges);// todo ACKDelay?
        packetRecvTime.clear();
        packet->GetPktPayload()->AttachFrame(ackFrame);
    }
}

int QUIC::SocketLoop() {
    std::cout << "enter socket loop " << std::endl;
    for (;;) {

        auto datagram = this->socket.tryRecvMsg(10ms);
        if (datagram) {
            this->incomingMsg(std::move(datagram));
        }
        for (auto& connection : this->connections) {
            // 判断是否要发送ping
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
            // ping的间隔时间
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - connection.second->last_ping).count() > 10) {
                // 开始发送PING frame
                utils::logger::info("sending PING FRAME...");
                std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum++, connection.second->getLargestAcked());
                std::shared_ptr<payload::PingFrame> ping_frame = std::make_shared<payload::PingFrame>();
                std::shared_ptr<payload::Payload> ping_payload = std::make_shared<payload::Payload>();
                ping_payload->AttachFrame(ping_frame);
                sockaddr_in addrTo = connection.second->getAddrTo();
                std::shared_ptr<payload::Packet> ping_packet = std::make_shared<payload::Packet>(header, ping_payload, addrTo);
                connection.second->insertIntoPending(ping_packet);
            }
            auto& pendingPackets = connection.second->GetPendingPackets();
            // auto& pendingPackets = connection.second->getPackets();
            // if(pendingPackets.empty())
            // {
            //     // 如果没有需要发送的包，但需要发送纯ACK包
            //     bool flag = false;
            //     for(auto pair : connection.second->packetRecvTime)
            //     {
            //         std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
            //         if(duration_cast<std::chrono::milliseconds>(now - pair.second).count() > 7500)// todo 最大 ack 回复延迟
            //         {
            //             flag = true;
            //             break;
            //         }
            //     }
            //     if(flag)
            //     {
            //         std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[connection.first]], this->pktnum++, connection.second->getLargestAcked());
            //         std::shared_ptr<payload::Payload> payload = std::make_shared<payload::Payload>();
            //         std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(20, connection.second->getACKRanges());// todo ACKDelay?
            //         connection.second->packetRecvTime.clear();
            //         payload->AttachFrame(ackFrame);
            //         std::shared_ptr<payload::Packet> packet = std::make_shared<payload::Packet>(header, payload, connection.second->getAddrTo());
            //         pendingPackets.push_back(packet);
            //     }
            // }
            while (!pendingPackets.empty()) {
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
                utils::logger::info("SEND A PACKET, NUMBER = {}", pendingPackets.front()->GetPacketNumber());
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
    uint64_t id;
    if(!bidirectional)
    {
        id = uint64_t(2)|((this->stream_count[sequence]++) << 2);
    }
    else
    {
        id = (this->stream_count[sequence]++) << 2;
    }
    streamID2Offset[id] = 0;
    return id;    
}

uint64_t QUIC::CloseStream([[maybe_unused]] uint64_t sequence,
                           [[maybe_unused]] uint64_t streamID) {
    // TODO: 如果有没有发完的包，如果有的话，在这里需要全部发送
    utils::logger::info("CloseStream\n");
    auto this_connection = this->connections[sequence];
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum++, this_connection->getLargestAcked());
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
    utils::logger::info("sendData, streamID is {}, offset is {}\n", streamID, this->streamID2Offset[streamID]);
    auto this_connection = this->connections[sequence];
    // thquic::ConnectionID connection_id = this->connections[sequence]
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], this->pktnum++, this_connection->getLargestAcked());
    // std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, std::move(buf), len, 0, len, FIN);
    std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, std::move(buf), len, this->streamID2Offset[streamID], len, FIN);
    this->streamID2Offset[streamID] += len;
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
    uint64_t sequence = this->ID2Sequence[header->GetDstID()];
    payload::PacketType packetType = header->Type();

    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

    // this->connections[sequence]->packetRecvTime[recvPacketNumber]=now;
    
    switch (packetType) {
        case payload::PacketType::INITIAL: {
            std::shared_ptr<payload::Initial> ih = std::static_pointer_cast<payload::Initial>(header);
            ih->RestoreFullPacketNumber(0);
            uint64_t recvPacketNumber = ih->GetPacketNumber();
            utils::logger::info("RECV A INITIAL PACKET FROM SERVER");
            this->connectionReadyCallback(this->ID2Sequence[header->GetDstID()]);
            this->SrcID2DstID[header->GetDstID()] = ih->GetSrcID();
            break;
        }
        case payload::PacketType::ZERO_RTT:
            utils::logger::warn("SERVER PacketType::ZERO_RTT");
            break;
        case payload::PacketType::HANDSHAKE:
            utils::logger::warn("SERVER PacketType::HANDSHAKE");
            break;
        case payload::PacketType::ONE_RTT: {
            std::shared_ptr<payload::ShortHeader> sh = std::static_pointer_cast<payload::ShortHeader>(header);
            sh->RestoreFullPacketNumber(this->connections[sequence]->getLargestAcked());
            uint64_t recvPacketNumber = sh->GetPacketNumber();
            utils::logger::info("RECV A PACKET FROM SERVER, PACKET NUMBER: {}", recvPacketNumber);
            uint64_t sequence = this->ID2Sequence[header->GetDstID()];
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
    payload::PacketType packetType = header->Type();

    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

    switch (packetType) {
        case payload::PacketType::INITIAL: {
            std::shared_ptr<payload::Initial> ih = std::static_pointer_cast<payload::Initial>(header);
            ih->RestoreFullPacketNumber(0);
            uint64_t recvPacketNumber = ih->GetPacketNumber();
            utils::logger::info("RECV A PACKET FROM CLIENT, PACKET NUMBER: {}", recvPacketNumber);
            std::shared_ptr<Connection> connection = std::make_shared<Connection>();
            ConnectionID id = ConnectionIDGenerator::Get().Generate();
            connection->setAddrTo(datagram->GetAddrSrc());
            uint64_t sequence = this->connectionSequence++;
            this->connections[sequence] = connection;
            this->Sequence2ID[sequence] = id; 
            this->ID2Sequence[id] = sequence;
            this->SrcID2DstID[id] = ih->GetSrcID();
            this->connections[sequence]->packetRecvTime[recvPacketNumber] = now;
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
            std::shared_ptr<payload::ShortHeader> sh = std::static_pointer_cast<payload::ShortHeader>(header);
            sh->RestoreFullPacketNumber(this->connections[sequence]->getLargestAcked());
            uint64_t recvPacketNumber = sh->GetPacketNumber();
            utils::logger::info("RECV A PACKET FROM CLIENT, PACKET NUMBER: {}", recvPacketNumber);
            std::list<std::shared_ptr<payload::Frame>> frames = payload::Payload(stream, bufferLen - stream.Pos()).GetFrames();
            uint64_t sequence = this->ID2Sequence[header->GetDstID()];
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
                            streamID2Offset[streamID] = 0;
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
    connection->last_ping = std::chrono::steady_clock::now();
    return 0;
}

}  // namespace thquic::context