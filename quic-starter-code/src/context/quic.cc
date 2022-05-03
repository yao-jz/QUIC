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
    std::shared_ptr<utils::UDPDatagram> close_dg = QUIC::encodeDatagram(close_packet);
    this->socket.sendMsg(close_dg);

    // this_connection->insertIntoPending(close_packet);
    return 0;
}

int QUIC::SetConnectionCloseCallback(
    [[maybe_unused]] uint64_t sequence,
    [[maybe_unused]] ConnectionCloseCallbackType callback) {
    this->ConnectionCloseCallback = callback;
    return 0;
}

/**
 * @brief 判断是否要发送Initial 包
 * @param connection 
 */
void QUIC::checkInitialPacket(std::shared_ptr<Connection> connection, utils::timepoint& now){
    // periodically send Initial packet
    if (!connection->initial_complete && std::chrono::duration_cast<std::chrono::milliseconds>(now - connection->last_initial).count() > INITIAL_INTERVAL) {
        std::shared_ptr<payload::Initial> initial_header = std::make_shared<payload::Initial>(config::QUIC_VERSION, this->Sequence2ID[connection->sequence], ConnectionID(), this->pktnum++, connection->getLargestAcked());
        std::shared_ptr<payload::Payload> initial_payload = std::make_shared<payload::Payload>();
        std::shared_ptr<payload::Packet> initial_packet = std::make_shared<payload::Packet>(initial_header, initial_payload, connection->getAddrTo());
        connection->last_initial = utils::clock::now();
        connection->insertIntoPending(initial_packet);
    }
}

/**
 * @brief 判断是否要发送ping包
 * @param connection 需要检查的连接
 */
void QUIC::checkPingPacket(std::shared_ptr<Connection> connection, utils::timepoint& now){
    // ping的间隔时间
    if (now - connection->last_ping > config::PING_INTERVAL) {
        // 开始发送PING frame
        utils::logger::info("sending PING FRAME... packet num = {}",this->pktnum);

        std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(ConnectionID(), this->pktnum++, connection->getLargestAcked());
        std::shared_ptr<payload::PingFrame> ping_frame = std::make_shared<payload::PingFrame>();
        std::shared_ptr<payload::Payload> ping_payload = std::make_shared<payload::Payload>();
        ping_payload->AttachFrame(ping_frame);
        sockaddr_in addrTo = connection->getAddrTo();
        std::shared_ptr<payload::Packet> ping_packet = std::make_shared<payload::Packet>(header, ping_payload, addrTo);
        connection->last_ping = now;
        connection->insertIntoPending(ping_packet);
    }
}

void QUIC::checkBufferPacket(std::shared_ptr<Connection> connection)
{
    if(connection->GetPendingPackets().size() < 10)
    {
        for(size_t i = 1; i < 10 - connection->GetPendingPackets().size(); i ++)
        {
            if(connection->packetsBuffer.size() == 0) break;
            std::shared_ptr<payload::Packet> packet = connection->packetsBuffer.front();
            std::shared_ptr<payload::PacketNumberMixin> mixin = std::dynamic_pointer_cast<payload::PacketNumberMixin>(packet->GetPktHeader());
            uint64_t full = this->pktnum++;
            utils::TruncatedPacketNumber truncated = utils::encodePacketNumber(full, connection->getLargestAcked());
            mixin->ChangeTruncatedPacketNumber(truncated.first, truncated.second);
            mixin->ChangeFullPacketNumber(full);
            connection->insertIntoPending(packet);
            connection->packetsBuffer.pop_front();
        }
    }
}

/**
 * @brief 检查是否有包已经丢失，需要进行重传
 * @param connection 
 */
void QUIC::detectLossAndRetransmisson(std::shared_ptr<Connection> connection, utils::timepoint& now) {
    // get unacked packets sent by this connection
    std::map<uint64_t,std::shared_ptr<payload::Packet>>& unAckedPackets = connection->getUnAckedPackets();
    utils::duration rawThreshold = K_TIME_THRESHOLD((connection->latest_rtt > connection->smoothed_rtt ? connection->latest_rtt : connection->smoothed_rtt));
    utils::timepoint timeThreshold = now - (rawThreshold > config::loss_detection::GRANULARITY ? rawThreshold : config::loss_detection::GRANULARITY);
    uint64_t pktThreshold = (connection->getLargestAcked() > config::loss_detection::PACKET_THRESHOLD) ? 
            connection->getLargestAcked() - config::loss_detection::PACKET_THRESHOLD : 0;
    std::vector<uint64_t> packetNumsDel;
    // utils::logger::info("THRESHOLD TIME: {}, PKT: {}", utils::formatTimepoint(timeThreshold), pktThreshold);
    std::list<std::shared_ptr<payload::Packet>> lostPackets;
    for(auto packet_pair : unAckedPackets) {
        std::shared_ptr<payload::Packet> packet = packet_pair.second;
        // we don't think it is lost
        if(!packet->IsACKEliciting()) continue;
        utils::timepoint sendTime = packet_pair.second->GetSendTimestamp();
        // packet loss when: (1) packet number < largest acked - kPackethreshold (2) timeSent < now - timeThreshold
        if (packet->GetPacketNumber() < pktThreshold || sendTime < timeThreshold) {
            utils::logger::warn("PACKET LOST, NUMBER = {}", packet->GetPacketNumber());
            // ignore ping & padding packet
            lostPackets.push_back(std::make_shared<payload::Packet>(*packet));
            auto frames = packet->GetPktPayload()->GetFrames();
            // remove old ACK Frames
            for(auto frame = frames.begin(); frame != frames.end() ; frame ++) {
                switch ((*frame)->Type()) {
                    case payload::FrameType::ACK:
                    case payload::FrameType::PING:
                    case payload::FrameType::PADDING:{
                        packet->DeletePayloadFrame(std::distance(frames.begin(), frame));
                        break;
                    }
                    default:
                        break;
                }
            }
            if (!packet->GetPktPayload()->GetFrames().empty()) {
                std::shared_ptr<payload::PacketNumberMixin> mixin = std::dynamic_pointer_cast<payload::PacketNumberMixin>(packet->GetPktHeader());
                uint64_t full = this->pktnum++;
                // reencode the packet number (because the length field may be changed)
                utils::TruncatedPacketNumber truncated = utils::encodePacketNumber(full, connection->getLargestAcked());
                mixin->ChangeTruncatedPacketNumber(truncated.first, truncated.second);
                mixin->ChangeFullPacketNumber(full);
                connection->insertIntoPending(packet);
            }
            packetNumsDel.push_back(packet_pair.first);
        }
    }

    this->onPacketsLost(lostPackets, connection->sequence);

    // discard lost packets
    for(auto packetnum : packetNumsDel) {
        connection->removeFromUnAckedPackets(packetnum);
    }
}

std::list<std::shared_ptr<payload::Packet>>& QUIC::getPackets(std::shared_ptr<thquic::context::Connection> connection)
{
    utils::timepoint now = utils::clock::now();

    // check if initial packet needed
    this->checkInitialPacket(connection, now);

    // check if there's loss and retransmission
    this->detectLossAndRetransmisson(connection, now);

    // check if ping frame needed
    // this->checkPingPacket(connection, now);

    this->checkBufferPacket(connection);

    std::list<std::shared_ptr<payload::Packet>>& pendingPackets = connection->GetPendingPackets();

    // check if there're ACK frames need to be sent
    if(!connection->getACKRanges().Empty()) {
        uint64_t pktNumber = connection->getACKRanges().GetEnd();
        uint64_t delay = std::chrono::duration_cast<std::chrono::milliseconds>(utils::clock::now() - connection->packetRecvTime.find(pktNumber)->second).count();
        if (!pendingPackets.empty()) {
            std::shared_ptr<payload::Packet> packet = pendingPackets.front();
            auto frames = packet->GetPktPayload()->GetFrames();
            // remove old ACK Frames
            for(auto frame = frames.begin(); frame != frames.end() ; frame ++) {
                switch ((*frame)->Type()) {
                    case payload::FrameType::ACK:{
                        packet->DeletePayloadFrame(std::distance(frames.begin(), frame));
                        break;
                    }
                    default:
                        break;
                }
            }
            utils::logger::info("PENDING ACK HAS BEEN DELAYED FOR {} ms", delay);
            std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(delay, connection->getACKRanges());
            packet->GetPktPayload()->AttachFrame(ackFrame);
            connection->first_ack_time = config::ZERO_TIMEPOINT;
            connection->packetRecvTime.clear();
        } else if ((connection->first_ack_time + config::MAX_ACK_DELAY > utils::clock::now()) && connection->first_ack_time != config::ZERO_TIMEPOINT) {
            utils::logger::info("PENDING ACK HAS BEEN DELAYED FOR {} ms", delay);
            std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[connection->sequence]],
                    this->pktnum++, connection->getLargestAcked());
            std::shared_ptr<payload::Payload> payload = std::make_shared<payload::Payload>();
            std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(delay, connection->getACKRanges());
            payload->AttachFrame(ackFrame);
            std::shared_ptr<payload::Packet> packet = std::make_shared<payload::Packet>(header, payload, connection->getAddrTo());
            pendingPackets.push_back(packet);
            connection->first_ack_time = config::ZERO_TIMEPOINT;
            connection->packetRecvTime.clear();
        }
    }
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
            if (!connection.second->getIsAlive()) continue;
            auto& pendingPackets = this->getPackets(connection.second);
            while (!pendingPackets.empty()) {
                bool okToSend= false;
                if (pendingPackets.front()->IsByteInflight()) {
                    if (pendingPackets.front()->EncodeLen() + connection.second->bytesInFlight < connection.second->congestionWindow){
                        // smaller than congestion window, it's ok to send this package
                        okToSend = true;
                    } else { // larger than congestion window
                        okToSend = false;
                        break;
                    }
                } else {
                    okToSend = true;
                }
                if (okToSend) {
                    utils::logger::info("SEND A PACKET, NUMBER = {}", pendingPackets.front()->GetPacketNumber());
                    utils::timepoint now = utils::clock::now();
                    pendingPackets.front()->MarkSendTimestamp(now);
                    auto newDatagram = QUIC::encodeDatagram(pendingPackets.front());
                    this->socket.sendMsg(newDatagram);
                    connection.second->bytesInFlight += pendingPackets.front()->EncodeLen();
                    // if(pendingPackets.front()->IsACKEliciting()) connection.second->insertIntoUnAckedPackets(pendingPackets.front()->GetPacketNumber(), pendingPackets.front());
                    connection.second->insertIntoUnAckedPackets(pendingPackets.front()->GetPacketNumber(), pendingPackets.front());
                    pendingPackets.pop_front();
                }
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
    uint8_t *buffer = buf.release();
    while(len > MAX_SLICE_LENGTH)
    {
        std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], this->pktnum, this_connection->getLargestAcked());
        std::unique_ptr<uint8_t[]> tmp = std::make_unique<uint8_t[]>(MAX_SLICE_LENGTH);
        std::copy(buffer, buffer + MAX_SLICE_LENGTH, tmp.get());
        std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, std::move(tmp), MAX_SLICE_LENGTH, this->streamID2Offset[streamID], MAX_SLICE_LENGTH, FIN);
        this->streamID2Offset[streamID] += MAX_SLICE_LENGTH;
        buffer += MAX_SLICE_LENGTH;
        len -= MAX_SLICE_LENGTH;
        std::shared_ptr<payload::Payload> stream_payload = std::make_shared<payload::Payload>();
        stream_payload->AttachFrame(stream_frame);
        sockaddr_in addrTo = this->connections[sequence]->getAddrTo();
        std::shared_ptr<payload::Packet> stream_packet = std::make_shared<payload::Packet>(header, stream_payload, addrTo);
        this_connection->insertIntoBuffer(stream_packet);
    }
    std::shared_ptr<payload::ShortHeader> header = std::make_shared<payload::ShortHeader>(this->SrcID2DstID[this->Sequence2ID[sequence]], this->pktnum, this_connection->getLargestAcked());
    std::unique_ptr<uint8_t[]> tmp = std::make_unique<uint8_t[]>(len);
    std::copy(buffer, buffer + len, tmp.get());
    std::shared_ptr<payload::StreamFrame> stream_frame = std::make_shared<payload::StreamFrame>(streamID, std::move(tmp), len, this->streamID2Offset[streamID], len, FIN);
    this->streamID2Offset[streamID] += len;
    std::shared_ptr<payload::Payload> stream_payload = std::make_shared<payload::Payload>();
    stream_payload->AttachFrame(stream_frame);
    sockaddr_in addrTo = this->connections[sequence]->getAddrTo();
    std::shared_ptr<payload::Packet> stream_packet = std::make_shared<payload::Packet>(header, stream_payload, addrTo);
    this_connection->insertIntoBuffer(stream_packet);
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
    uint64_t largestAcked = ackFrame->GetLargestACKed();
    // check if this ACK frame is valid
    std::shared_ptr<payload::Packet> latestPacket = connection->getUnAckedPacket(largestAcked);
    if (latestPacket == nullptr) return;
    bool isNewlyAcked = (largestAcked > (connection->getLargestAcked()) || (connection->getLargestAcked() == std::numeric_limits<uint64_t>::max()));
    // check if this ACK frame can be used for RTT estimation
    if (isNewlyAcked && latestPacket->IsACKEliciting()){
        utils::duration ack_delay = std::chrono::milliseconds(ackFrame->GetACKDelay());
        if (ack_delay < config::MAX_ACK_DELAY) ack_delay = config::MAX_ACK_DELAY;
        connection->latest_rtt = utils::clock::now() - latestPacket->GetSendTimestamp();
        utils::logger::info("PATH TRIP DELAY: {}", utils::formatTimeDuration(connection->latest_rtt));
        if (connection->first_rtt_sample == utils::timepoint(std::chrono::milliseconds(0))) {
            connection->min_rtt = connection->latest_rtt;
            connection->smoothed_rtt = connection->latest_rtt;
            connection->rttvar = connection->latest_rtt / 2;
            connection->first_rtt_sample = utils::clock::now();
        }
        else {
            connection->min_rtt = (connection->min_rtt < connection->latest_rtt) ? connection->min_rtt : connection->latest_rtt;
            // TODO: Handshake
            utils::duration adjusted_rtt = connection->latest_rtt;
            if (connection->latest_rtt > connection->min_rtt + ack_delay){
                adjusted_rtt = connection->latest_rtt - ack_delay;
            }
            utils::duration diff = (connection->smoothed_rtt > adjusted_rtt) ? (connection->smoothed_rtt - adjusted_rtt) : (adjusted_rtt - connection->smoothed_rtt);
            connection->rttvar = 3 * connection->rttvar / 4 + diff / 4;
            connection->smoothed_rtt = 7 * connection->smoothed_rtt / 8 + adjusted_rtt / 8;
        }
    }
    utils::logger::info("ESTIMATE RTT: {}", utils::formatTimeDuration(connection->smoothed_rtt));
    for (utils::Interval interval : ackedIntervals) {
        utils::logger::info("ACKED PACKETS: START = {}, END = {}", interval.Start(), interval.End());
        for (uint64_t packetNumber = interval.Start(); packetNumber <= interval.End(); packetNumber++) {
            // change tracking interval
            std::shared_ptr<thquic::payload::Packet> packet = connection->getUnAckedPacket(packetNumber);
            if (packet == nullptr) continue;
            if (packet->IsByteInflight()) {
                this->connections[sequence]->bytesInFlight -= packet->EncodeLen();
                // if (this->inCongestionRecovery(sequence, packet->GetSendTimestamp())) {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(packet->GetSendTimestamp().time_since_epoch()).count() >= std::chrono::duration_cast<std::chrono::microseconds>(this->connections[sequence]->recoveryStartTime.time_since_epoch()).count()) {
                    // pass
                } else {
                    if (this->connections[sequence]->congestionWindow < this->connections[sequence]->ssthreshold) {
                        this->connections[sequence]->congestionWindow += packet->EncodeLen();
                    } else {
                        this->connections[sequence]->congestionWindow += MAX_SLICE_LENGTH * packet->EncodeLen() / this->connections[sequence]->congestionWindow;
                    }
                }
            }
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
    // uint64_t newLargetstAcked = ackFrame->GetLargestACKed();
    if (isNewlyAcked > connection->getLargestAcked()) {
        connection->setLargestAcked(largestAcked);
    }
}

void QUIC::onPacketsLost(std::list<std::shared_ptr<payload::Packet>> lostPackets, int sequence){
    auto now = utils::clock::now();
    long int sentTimeOfLastLoss = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    for (auto lostPacket : lostPackets) {
        if (lostPacket->IsByteInflight()){
            this->connections[sequence]->bytesInFlight -= lostPacket->EncodeLen();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(lostPacket->GetSendTimestamp().time_since_epoch()).count()-sentTimeOfLastLoss < 0) {
                sentTimeOfLastLoss = std::chrono::duration_cast<std::chrono::milliseconds>(lostPacket->GetSendTimestamp().time_since_epoch()).count();
            }
        }
    }
    if (sentTimeOfLastLoss != std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()) {
        this->enterRecovery(sentTimeOfLastLoss, sequence);
    }
}

void QUIC::enterRecovery(long int sentTimeOfLastLoss, int sequence) {
    if (sentTimeOfLastLoss >= std::chrono::duration_cast<std::chrono::milliseconds>(this->connections[sequence]->recoveryStartTime.time_since_epoch()).count())
        return;
    this->connections[sequence]->recoveryStartTime = utils::clock::now();
    this->connections[sequence]->ssthreshold /=2;
    this->connections[sequence]->congestionWindow = std::max(this->connections[sequence]->ssthreshold, this->connections[sequence]->minWindowSize);
    
}

int QUICClient::incomingMsg(
    [[maybe_unused]] std::unique_ptr<utils::UDPDatagram> datagram) {
    std::cout<<std::endl;
    size_t bufferLen = datagram->BufferLen();
    utils::ByteStream stream = utils::ByteStream(datagram->FetchBuffer(), bufferLen);
    std::shared_ptr<payload::Header> header = payload::Header::Parse(stream);
    uint64_t sequence = this->ID2Sequence[header->GetDstID()];
    payload::PacketType packetType = header->Type();

    std::shared_ptr<Connection> connection;
    if (!(this->connections.find(sequence) == this->connections.end())) {
        connection = this->connections.find(sequence)->second;
    }

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
            sh->RestoreFullPacketNumber(connection->getLargestAcked());
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
                        if (connection->aliveStreams.find(streamID) == connection->aliveStreams.end()) {
                            utils::logger::warn("RECV A FRAME FROM CLOSED STREAM : {}", streamID);
                            continue;
                        }
                        else if (streamFrame->FINFlag()) {
                            connection->aliveStreams.erase(streamID);
                        }
                        if(streamFrame->GetLength() != 0)
                        {
                            this->connections[sequence]->chunkStream.AddChunk(streamFrame->GetOffset(), streamFrame->FetchBuffer(), streamFrame->GetLength(), streamFrame->FINFlag());
                            uint64_t len = this->connections[sequence]->chunkStream.AvailableLen();
                            if(len > 0)
                            {
                                std::unique_ptr<uint8_t[]> buffer(new uint8_t[len]);
                                this->connections[sequence]->chunkStream.Consume(len, buffer);
                                this->streamDataReadyCallback(sequence, streamID, std::move(buffer), len, streamFrame->FINFlag());
                            }
                        }
                        if (!this->connections[sequence]->getIsAlive()) {
                            this->CloseConnection(sequence, "", 0);
                            utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
                        }
                        break;
                    }
                    case payload::FrameType::CONNECTION_CLOSE: {
                        utils::logger::info("SERVER Frame Type::CONNECTION_CLOSE");
                        if (this->connections[sequence]->getIsAlive()){
                            this->CloseConnection(sequence, "", 0);
                            this->ConnectionCloseCallback(sequence, "", 0);
                        }
                        break;
                    }
                    case payload::FrameType::ACK:{
                        std::shared_ptr<payload::ACKFrame> ackFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                        this->handleACKFrame(ackFrame, sequence);
                        if (!this->connections[sequence]->getIsAlive()) {
                            this->CloseConnection(sequence, "", 0);
                            utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
                        }
                        
                        break;
                    }
                    case payload::FrameType::PING:{
                        utils::logger::info("SERVER Frame Type::PING");
                        ackEliciting = true;
                        if (!this->connections[sequence]->getIsAlive()) {
                            this->CloseConnection(sequence, "", 0);
                            utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
                        }
                        break;
                    }
                    default: utils::logger::warn("UNKNOWN FRAME TYPE");
                }
            }
            connection->getACKRanges().AddInterval(recvPacketNumber, recvPacketNumber);
            if (ackEliciting) {
                // mark as the most earliest
                if (connection->first_ack_time == config::ZERO_TIMEPOINT)
                    connection->first_ack_time = utils::clock::now();
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

    std::shared_ptr<Connection> connection;
    if (!(this->connections.find(sequence) == this->connections.end())) {
        connection = this->connections.find(sequence)->second;
        // if (!connection->getIsAlive()) {
        //     this->ConnectionCloseCallback(sequence, "", 0);
        //     utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
        //     this->CloseConnection(sequence, "", 0);
        //     return 0;
        // }
    }
    
    payload::PacketType packetType = header->Type();
    utils::timepoint now = utils::clock::now();

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
                connection->chunkStream.init();
                id = ConnectionIDGenerator::Get().Generate();
                connection->setAddrTo(datagram->GetAddrSrc());
                connection->setAlive(true);
                connection->initial_complete = true;
                sequence = this->connectionSequence++;
                connection->sequence = sequence;
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
            sh->RestoreFullPacketNumber(connection->getLargestAcked());
            uint64_t recvPacketNumber = sh->GetPacketNumber();
            connection->packetRecvTime[recvPacketNumber] = now;
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
                        else if (connection->aliveStreams.find(streamID) == connection->aliveStreams.end()) {
                            utils::logger::warn("RECV A FRAME FROM CLOSED STREAM : {}", streamID);
                            continue;
                        }
                        else if (streamFrame->FINFlag()) {
                            connection->aliveStreams.erase(streamID);
                        }
                        if(streamFrame->GetLength() != 0)
                        {
                            this->connections[sequence]->chunkStream.AddChunk(streamFrame->GetOffset(), streamFrame->FetchBuffer(), streamFrame->GetLength(), streamFrame->FINFlag());
                            uint64_t len = this->connections[sequence]->chunkStream.AvailableLen();
                            if(len > 0)
                            {
                                std::unique_ptr<uint8_t[]> buffer(new uint8_t[len]);
                                this->connections[sequence]->chunkStream.Consume(len, buffer);
                                this->streamDataReadyCallback(sequence, streamID, std::move(buffer), len, streamFrame->FINFlag());
                            }
                        }
                        if (!this->connections[sequence]->getIsAlive()) {
                            this->CloseConnection(sequence, "", 0);
                            utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
                        }
                        break;
                    }
                    case payload::FrameType::ACK: {
                        utils::logger::info("CLIENT Frame Type::ACK");
                        std::shared_ptr<payload::ACKFrame> ackFrame = std::static_pointer_cast<payload::ACKFrame>(frame);
                        this->handleACKFrame(ackFrame, sequence);
                        if (!this->connections[sequence]->getIsAlive()) {
                            this->CloseConnection(sequence, "", 0);
                            utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
                        }
                        break;
                    }
                    case payload::FrameType::CONNECTION_CLOSE: {
                        utils::logger::info("CLIENT Frame Type::CONNECTION_CLOSE");
                        if (this->connections[sequence]->getIsAlive()){
                            this->CloseConnection(sequence, "", 0);
                            this->ConnectionCloseCallback(sequence, "", 0);
                        }
                        break;
                    }
                    case payload::FrameType::PING: {
                        utils::logger::info("CLIENT Frame Type::PING");
                        ackEliciting = true;
                        if (!this->connections[sequence]->getIsAlive()) {
                            this->CloseConnection(sequence, "", 0);
                            utils::logger::warn("CONNECTION {} ALREADY CLOSED!", sequence);
                        }
                        break;
                    }
                    default: utils::logger::warn("UNKNOWN FRAME TYPE");
                }
            }
            connection->getACKRanges().AddInterval(recvPacketNumber, recvPacketNumber);
            if (ackEliciting) {
                 // mark as the most earliest
                if (connection->first_ack_time == config::ZERO_TIMEPOINT)
                    connection->first_ack_time = utils::clock::now();
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
    connection->chunkStream.init();
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
    connection->last_ping = utils::clock::now();
    connection->last_initial = utils::clock::now();
    return 0;
}

}  // namespace thquic::context