#ifndef THQUIC_CONTEXT_CONNECTION_H
#define THQUIC_CONTEXT_CONNECTION_H

#include "payload/packet.hh"

namespace thquic::context {

class Connection {
   public:
    Connection()
    {
        this->largestAcked = -1;
        this->ACKRanges = utils::IntervalSet();
    }

    std::list<std::shared_ptr<payload::Packet>>& GetPendingPackets() {
        return this->pendingPackets;
    }

    std::list<std::shared_ptr<payload::Packet>>& getPackets()
    {
        // 超时重传
        for(auto packet_pair : unAckedPackets)
        {
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
            if(duration_cast<milliseconds>(now - packet_pair.second->GetSendTimestamp()).count() > 7500)
            {
                this->pendingPackets.push_back(packet_pair.second);
            }
        }


        if(!pendingPackets.empty() && !this->ACKRanges.Empty())
        {
            std::shared_ptr<payload::Packet> packet = pendingPackets.front();
            std::shared_ptr<payload::ACKFrame> ackFrame = std::make_shared<payload::ACKFrame>(20, this->ACKRanges);// todo ACKDelay?
            packet->GetPktPayload()->AttachFrame(ackFrame);
        }
        else
        {
            // 没有需要发送的包，但有收到的包快要超过ack时限了

        }
        return this->pendingPackets;
    }
    
    // 将待发送包加入到队列中
    int insertIntoPending(std::shared_ptr<payload::Packet> packet)
    {
        pendingPackets.push_back(packet);
        return 0;
    }

    void setAddrTo(struct sockaddr_in addr)
    {
        this->addrTo = addr;
    }

    struct sockaddr_in getAddrTo()
    {
        return this->addrTo;
    }

    void insertIntoUnAckedPackets(uint64_t packetNumber, std::shared_ptr<payload::Packet> packet)
    {
        this->unAckedPackets[packetNumber] = packet;
    }

    void removeFromUnAckedPackets(uint64_t packetNumber)
    {
        this->unAckedPackets.erase(packetNumber);
    }

    std::shared_ptr<payload::Packet> getUnAckedPacket(uint64_t packetNumber)
    {
        return this->unAckedPackets[packetNumber];
    }

    int64_t getLargestAcked() {
        return this->largestAcked;
    }

    utils::IntervalSet& getACKRanges(){
        return this->ACKRanges;
    }

    

   private:
    std::list<std::shared_ptr<payload::Packet>> pendingPackets;
    std::map<uint64_t,std::shared_ptr<payload::Packet>> unAckedPackets; // packetnum to packet
    struct sockaddr_in addrTo;
    int64_t largestAcked;
    utils::IntervalSet ACKRanges;
    public:
    std::map<int64_t, time_t> packetSendTime;
    std::map<int64_t, time_t> packetRecvTime;
};

}  // namespace thquic::context
#endif
