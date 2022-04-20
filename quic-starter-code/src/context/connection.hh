#ifndef THQUIC_CONTEXT_CONNECTION_H
#define THQUIC_CONTEXT_CONNECTION_H

#include "payload/packet.hh"

namespace thquic::context {

class Connection {
   public:
    std::list<std::shared_ptr<payload::Packet>>& GetPendingPackets() {
        return this->pendingPackets;
    }

    // 将待发送包加入到队列中
    int insertIntoPending(std::shared_ptr<payload::Packet> packet)
    {
        pendingPackets.push_back(packet);
    }

   private:
    std::list<std::shared_ptr<payload::Packet>> pendingPackets;
};

}  // namespace thquic::context
#endif
