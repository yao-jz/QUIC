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
    this_connection->setAlive(false);
    this_connection->getUnAckedPackets().clear();
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

std::list<std::shared_ptr<payload::Packet>>& QUIC::getPackets(std::shared_ptr<thquic::context::Connection> connection)
{
    std::map<uint64_t,std::shared_ptr<payload::Packet>>& unAckedPackets = connection->getUnAckedPackets();
    std::list<std::shared_ptr<payload::Packet>>& pendingPackets = connection->GetPendingPackets();
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

    if (!connection->initial_complete && std::chrono::duration_cast<std::chrono::milliseconds>(now-connection->last_initial).count() > 1000) {
        std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, this->Sequence2ID[connection->sequence], ConnectionID(), this->pktnum++, connection->getLargestAcked());
        std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
        std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, connection->getAddrTo());
        connection->last_ping = std::chrono::steady_clock::now();
        connection->last_initial = std::chrono::steady_clock::now();
        connection->insertIntoPending(initial_packet);
    }

    // restransmisson when time's up
    std::vector<uint64_t> packetNumsDel;
    for(auto packet_pair : unAckedPackets) {
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        if(std::chrono::duration_cast<std::chrono::milliseconds>(now - packet_pair.second->GetSendTimestamp()).count() > 7500) {
            // ignore RETRY packet
            std::shared_ptr<payload::Packet> unAckedPacket = packet_pair.second;
            auto frames = unAckedPacket->GetPktPayload()->GetFrames();
            for(auto frame = frames.begin(); frame != frames.end() ; frame ++)
            {
                if((*frame)->Type() == payload::FrameType::ACK)
                {
                    unAckedPacket->GetPktPayload()->DeleteFrame(frame);
                    break;
                }
            }
            std::shared_ptr<payload::PacketNumberMixin> mixin = std::dynamic_pointer_cast<payload::PacketNumberMixin>(unAckedPacket->GetPktHeader());
            utils::logger::warn("PACKET LOST, NUMBER = {}", unAckedPacket->GetPacketNumber());
            uint64_t full = this->pktnum++;
            // reencode the packet number (because the length field may be changed)
            utils::TruncatedPacketNumber truncated = utils::encodePacketNumber(full, connection->getLargestAcked());
            mixin->ChangeTruncatedPacketNumber(truncated.first, truncated.second);
            mixin->ChangeFullPacketNumber(full);
            connection->insertIntoPending(unAckedPacket);
            packetNumsDel.push_back(packet_pair.first);
        }
    }

    // 不再接受重传之前的包的ack
    for(auto packetnum : packetNumsDel) {
        connection->removeFromUnAckedPackets(packetnum);
    }

    // // 判断是否要发送ping
    // std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    // // ping的间隔时间
    // if (std::chrono::duration_cast<std::chrono::milliseconds>(now - connection->last_ping).count() > 10) {
    //     // 开始发送PING frame
    //     utils::logger::info("sending PING FRAME...");
    //     std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum++, connection->getLargestAcked());
    //     std::shared_ptr<payload::PingFrame> ping_frame = std::make_shared<payload::PingFrame>();
    //     std::shared_ptr<payload::Payload> ping_payload = std::make_shared<payload::Payload>();
    //     ping_payload->AttachFrame(ping_frame);
    //     sockaddr_in addrTo = connection->getAddrTo();
    //     std::shared_ptr<payload::Packet> ping_packet = std::make_shared<payload::Packet>(header, ping_payload, addrTo);
    //     connection->insertIntoPending(ping_packet);
    // }

    // 有即将发送的包，顺带发送ack
    if(!pendingPackets.empty() && !connection->getACKRanges().Empty())
    {
        std::shared_ptr<payload::Packet> packet = pendingPackets.front();
        std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(20, connection->getACKRanges());// todo ACKDelay?
        connection->packetRecvTime.clear();
        packet->GetPktPayload()->AttachFrame(ackFrame);
    }

    // // 没有即将发送的包，但有ack要超时了, 发送纯ACK包
    // if(pendingPackets.empty())
    // {
    //     bool flag = false;
    //     for(auto pair : connection->packetRecvTime)
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
    //         std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[connection.first]], this->pktnum++, connection->getLargestAcked());
    //         std::shared_ptr<payload::Payload> payload = std::make_shared<payload::Payload>();
    //         std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(20, connection->getACKRanges());// todo ACKDelay?
    //         connection->packetRecvTime.clear();
    //         payload->AttachFrame(ackFrame);
    //         std::shared_ptr<payload::Packet> packet = std::make_shared<payload::Packet>(header, payload, connection->getAddrTo());
    //         pendingPackets.push_back(packet);
    //     }
    // }
    return pendingPackets;
}

int QUIC::SocketLoop() {
    std::cout << "enter socket loop " << std::endl;
    for (;;) {
        auto datagram = this->socket.tryRecvMsg(10ms);
        if (datagram) {
            this->incomingMsg(std::move(datagram));
        }
        for (auto& connection : this->connections) {
            auto& pendingPackets = this->getPackets(connection.second);
            // auto& pendingPackets = connection.second->GetPendingPackets();
            while (!pendingPackets.empty()) {
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
                utils::logger::info("SEND A PACKET, NUMBER = {}", pendingPackets.front()->GetPacketNumber());
                pendingPackets.front()->MarkSendTimestamp(now);
                auto newDatagram = QUIC::encodeDatagram(pendingPackets.front());
                this->socket.sendMsg(newDatagram);
                if(pendingPackets.front()->IsACKEliciting()) connection.second->insertIntoUnAckedPackets(pendingPackets.front()->GetPacketNumber(), pendingPackets.front());
                pendingPackets.pop_front();
            }
        }
    }
    return 0;
}

uint64_t QUIC::CreateStream([[maybe_unused]] uint64_t sequence,
                            [[maybe_unused]] bool bidirectional) {
    uint64_t id;
    if(!bidirectional) {
        id = uint64_t(2)|((this->stream_count[sequence]++) << 2);
    }
    else {
        id = (this->stream_count[sequence]++) << 2;
    }
    streamID2Offset[id] = 0;
    this->connections[sequence]->aliveStreams.emplace(id);
    return id;    
}

uint64_t QUIC::CloseStream([[maybe_unused]] uint64_t sequence,
                           [[maybe_unused]] uint64_t streamID) {
    // TODO: 如果有没有发完的包，如果有的话，在这里需要全部发送
    utils::logger::info("CloseStream\n");
    auto this_connection = this->connections[sequence];
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum++, this_connection->getLargestAcked());
    std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, nullptr, 0, this->streamID2Offset[streamID], 0, true);
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
    utils::logger::info("sendData, streamID is {}, offset is {}", streamID, this->streamID2Offset[streamID]);
    auto this_connection = this->connections[sequence];
    // thquic::ConnectionID connection_id = this->connections[sequence]
    while(len > 1370)
    {
        std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], this->pktnum++, this_connection->getLargestAcked());

    }
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], this->pktnum++, this_connection->getLargestAcked());
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
    std::shared_ptr<thquic::context::Connection> connection = this->connections[sequence];
    std::list<utils::Interval> ackedIntervals = ackFrame->GetACKRanges().Intervals();
    for (utils::Interval interval : ackedIntervals) {
        utils::logger::info("ACKED PACKETS: START = {}, END = {}", interval.Start(), interval.End());
        for (uint64_t packetNumber = interval.Start(); packetNumber <= interval.End(); packetNumber++) {
            // change tracking interval
            std::shared_ptr<thquic::payload::Packet> packet = connection->getUnAckedPacket(packetNumber);
            if(packet == nullptr) continue;
            for (auto frame : packet->GetPktPayload()->GetFrames()) {
                if(frame->Type() == payload::FrameType::ACK) {
                    std::shared_ptr<payload::ACKFrame> subFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                    uint64_t largestAcked = subFrame->GetLargestACKed();
                    connection->getACKRanges().RemoveInterval(0, largestAcked);
                }
            }
            // remove acked packets
            connection->removeFromUnAckedPackets(packetNumber);
        }
    }
    uint64_t newLargetstAcked = ackFrame->GetLargestACKed();
    if (newLargetstAcked > connection->getLargestAcked()) connection->setLargestAcked(newLargetstAcked);
}


int QUICClient::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    std::cout<<std::endl;
    size_t bufferLen = datagram->BufferLen();
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), bufferLen);
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    uint64_t sequence = this->ID2Sequence[header->GetDstID()];
    payload::PacketType packetType = header->Type();

    switch (packetType) {
        case payload::PacketType::INITIAL: {
            std::shared_ptr<payload::Initial> ih = std::static_pointer_cast<payload::Initial>(header);
            ih->RestoreFullPacketNumber(0);
            utils::logger::info("RECV A INITIAL PACKET FROM SERVER");
            this->connectionReadyCallback(this->ID2Sequence[header->GetDstID()]);
            this->SrcID2DstID[header->GetDstID()] = ih->GetSrcID();
            this->connections[sequence]->initial_complete = true;
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
                        utils::logger::info("SERVER Frame Type::STREAM");
                        std::shared_ptr<payload::StreamFrame> streamFrame = std::static_pointer_cast<payload::StreamFrame>(frame);
                        uint64_t streamID = streamFrame->StreamID();

                        if (this->connections[sequence]->aliveStreams.find(streamID) == this->connections[sequence]->aliveStreams.end()) {
                            utils::logger::warn("RECV A FRAME FROM CLOSED STREAM : {}", streamID);
                            continue;
                        }
                        this->streamDataReadyCallback(sequence, streamID, streamFrame->FetchBuffer(), streamFrame->GetLength(), streamFrame->FINFlag());
                        break;
                    }
                    case payload::FrameType::CONNECTION_CLOSE: {
                        utils::logger::info("SERVER Frame Type::CONNECTION_CLOSE");
                        this->ConnectionCloseCallback(sequence, "", 0);
                        break;
                    }
                    case payload::FrameType::ACK:{
                        std::shared_ptr<payload::ACKFrame> ackFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                        this->handleACKFrame(ackFrame, sequence);
                        break;
                    }
                    case payload::FrameType::PING:{
                        utils::logger::info("SERVER Frame Type::PING");
                        ackEliciting = true;
                        break;
                    }
                    default: utils::logger::warn("UNKNOWN FRAME TYPE");
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
        default: utils::logger::warn("UNKNOWN PACKET TYPE");
    }
    return 0;
}

int QUICServer::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {

    std::cout<<std::endl;
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
            ConnectionID id;
            uint64_t sequence;
            bool flag = false;
            for(auto pair : this->connections)
            {
                if((pair.second->getAddrTo().sin_addr.s_addr == datagram->GetAddrSrc().sin_addr.s_addr) 
                    && (pair.second->getAddrTo().sin_port == datagram->GetAddrSrc().sin_port))
                {
                    sequence = pair.first;
                    id = this->Sequence2ID[sequence];
                    flag = true;
                    pair.second->packetRecvTime[recvPacketNumber] = now;
                    break;
                }
            }
            if(!flag)
            {
                std::shared_ptr<Connection> connection = std::make_shared<Connection>();
                id = ConnectionIDGenerator::Get().Generate();
                connection->setAddrTo(datagram->GetAddrSrc());
                connection->setAlive(true);
                connection->initial_complete = true;
                sequence = this->connectionSequence++;
                this->connections[sequence] = connection;
                this->Sequence2ID[sequence] = id; 
                this->ID2Sequence[id] = sequence;
                this->SrcID2DstID[id] = ih->GetSrcID();
                this->connections[sequence]->packetRecvTime[recvPacketNumber] = now;
            }
            std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, id, this->SrcID2DstID[id], this->pktnum++, 0);
            std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
            std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, datagram->GetAddrSrc());
            std::shared_ptr<utils::UDPDatagram> initial_dg = QUIC::encodeDatagram(initial_packet);
            this->socket.sendMsg(initial_dg);
            utils::logger::info("CLIENT INITIAL PACKET BACK");
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
                switch (frame->Type()) {
                    case payload::FrameType::STREAM: {
                        utils::logger::info("CLIENT Frame Type::STREAM");
                        ackEliciting = true;
                        std::shared_ptr<payload::StreamFrame> streamFrame = std::static_pointer_cast<payload::StreamFrame>(frame);
                        uint64_t streamID = streamFrame->StreamID();
                        if (this->stream_count[sequence] <= streamID) {
                            this->streamReadyCallback(sequence, streamID);
                            this->connections[sequence]->aliveStreams.emplace(streamID);
                            stream_count[sequence] = streamID + 1;
                            streamID2Offset[streamID] = 0;
                        }
                        if (this->connections[sequence]->aliveStreams.find(streamID) == this->connections[sequence]->aliveStreams.end()) {
                            utils::logger::warn("RECV A FRAME FROM CLOSED STREAM : {}", streamID);
                            continue;
                        }
                        this->streamDataReadyCallback(sequence, streamID, streamFrame->FetchBuffer(), streamFrame->GetLength(), streamFrame->FINFlag());
                        break;
                    }
                    case payload::FrameType::ACK: {
                        utils::logger::info("CLIENT Frame Type::ACK");
                        std::shared_ptr<payload::ACKFrame> ackFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                        this->handleACKFrame(ackFrame, sequence);
                        break;
                    }
                    case payload::FrameType::CONNECTION_CLOSE: {
                        utils::logger::info("CLIENT Frame Type::CONNECTION_CLOSE");
                        this->ConnectionCloseCallback(sequence, "", 0);
                        break;
                    }
                    case payload::FrameType::PING: {
                        utils::logger::info("CLIENT Frame Type::PING");
                        ackEliciting = true;
                        break;
                    }
                    default: utils::logger::warn("UNKNOWN FRAME TYPE");
                }
            }
            if (ackEliciting) {
                this->connections[sequence]->getACKRanges().AddInterval(recvPacketNumber, recvPacketNumber);
            }
            break;
        }
        case payload::PacketType::HANDSHAKE:
            utils::logger::info("SERVER PacketType::HANDSHAKE");
            break;
        case payload::PacketType::ZERO_RTT:
            utils::logger::info("SERVER PacketType::ZERO_RTT");
            break;
        case payload::PacketType::RETRY:
            utils::logger::warn("SERVER PacketType::RETRY");
            break;
        default: utils::logger::warn("UNKNOWN PACKET TYPE");
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
    connection->setAlive(true);
    uint64_t sequence = this->connectionSequence++;
    connection->sequence = sequence;
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
    connection->last_initial = std::chrono::steady_clock::now();
    return 0;
}

}  // namespace thquic::context