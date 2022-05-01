#ifndef THQUIC_CONTEXT_CONNECTION_H
#define THQUIC_CONTEXT_CONNECTION_H

#include "payload/packet.hh"
#include <map>

#define K_INITIAL_RTT 333
#define MAX_ACK_DELAY 20
namespace thquic::context {

class Connection {
   public:
    Connection()
    {
        this->largestAcked = 0;
        this->ACKRanges = utils::IntervalSet();
        this->chunkStream = utils::ChunkStream();
        this->congestionWindow = 14720;
        this->ssthreshold = uint64_t(2147483647)*uint64_t(2147483647);
        this->bytesInFlight = 0;
        this->recoveryStartTime = std::chrono::steady_clock::now();
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

    void setLargestAcked(uint64_t newAcked) {
        this->largestAcked = newAcked;
    }

    uint64_t getLargestAcked() {
        return this->largestAcked;
    }

    utils::IntervalSet& getACKRanges(){
        return this->ACKRanges;
    }

    bool getIsAlive()
    {
        return this->alive;
    }

    void setAlive(bool flag)
    {
        this->alive = flag;
    }

    
private:
    bool alive;
    std::list<std::shared_ptr<payload::Packet>> pendingPackets;
    std::map<uint64_t,std::shared_ptr<payload::Packet>> unAckedPackets; // packetnum to packet
    struct sockaddr_in addrTo;
    uint64_t largestAcked;
    utils::IntervalSet ACKRanges;
public:
    // RTT estimation relative
    uint64_t smoothed_rtt = K_INITIAL_RTT;
    uint64_t first_rtt_sample = 0;
    uint64_t latest_rtt = 0;
    uint64_t min_rtt = 0;
    uint64_t rttvar = K_INITIAL_RTT / 2;
    std::set<uint64_t> aliveStreams;
    std::map<uint64_t, std::chrono::steady_clock::time_point> packetRecvTime;
    std::chrono::steady_clock::time_point last_ping;
    std::chrono::steady_clock::time_point last_initial;
    bool initial_complete = false;
    int sequence;
    utils::ChunkStream chunkStream;
    uint64_t congestionWindow;
    uint64_t ssthreshold;
    uint64_t bytesInFlight;
    std::chrono::steady_clock::time_point recoveryStartTime;
    uint64_t status = 0; // 0 is slow start, 1 is recovery, 2 is avoidance
    uint64_t minWindowSize = 2*MAX_SLICE_LENGTH;
};

}  // namespace thquic::context
#endif
