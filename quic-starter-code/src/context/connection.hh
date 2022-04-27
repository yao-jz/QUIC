#ifndef THQUIC_CONTEXT_CONNECTION_H
#define THQUIC_CONTEXT_CONNECTION_H

#include "payload/packet.hh"

namespace thquic::context {

class Connection {
   public:
    Connection()
    {
        this->largestAcked =0;
        this->ACKRanges = utils::IntervalSet();
    }

    std::list<std::shared_ptr<payload::Packet>>& GetPendingPackets() {
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
        if(this->unAckedPackets.find(packetNumber) != this->unAckedPackets.end())
            this->unAckedPackets.erase(packetNumber);
    }

    std::shared_ptr<payload::Packet> getUnAckedPacket(uint64_t packetNumber)
    {
        if(this->unAckedPackets.find(packetNumber) != this->unAckedPackets.end())
            return this->unAckedPackets[packetNumber];
        else
            return nullptr;
    }

    std::map<uint64_t,std::shared_ptr<payload::Packet>>& getUnAckedPackets()
    {
        return this->unAckedPackets;
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
    std::map<uint64_t, std::chrono::steady_clock::time_point> packetRecvTime;
    std::chrono::steady_clock::time_point last_ping;
};

}  // namespace thquic::context
#endif
