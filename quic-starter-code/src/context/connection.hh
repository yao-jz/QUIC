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

    int64_t getLargestAcked() {
        return this->largestAcked;
    }

    utils::IntervalSet getACKRanges(){
        return this->ACKRanges;
    }

    

   private:
    std::list<std::shared_ptr<payload::Packet>> pendingPackets;
    struct sockaddr_in addrTo;
    int64_t largestAcked;
    utils::IntervalSet ACKRanges;
    public:
    std::map<int64_t, time_t> packetSendTime;
    std::map<int64_t, time_t> packetRecvTime;
};

}  // namespace thquic::context
#endif
