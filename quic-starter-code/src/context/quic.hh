#ifndef THQUIC_CONTEXT_QUIC_HH
#define THQUIC_CONTEXT_QUIC_HH

#include <chrono>
#include <list>
#include <map>
#include <thread>
#include <unordered_map>
#include <utility>

#include "context/callback.hh"
#include "context/common.hh"
#include "context/connection.hh"
#include "payload/packet.hh"
#include "utils/log.hh"
#include "utils/socket.hh"
#include "utils/time.hh"

#define INITIAL_INTERVAL 2000
#define K_TIME_THRESHOLD(x) 9 * x / 8

namespace thquic::context {

class QUIC {
    friend class QUICContext;

   public:
    explicit QUIC(PeerType type);

    QUIC(PeerType type, uint16_t port, std::string address = "");

    int CloseConnection(uint64_t sequence, const std::string& reason,
                        uint64_t errorCode);

    int SetConnectionCloseCallback(uint64_t sequence,
                                   ConnectionCloseCallbackType callback);

    uint64_t CreateStream(uint64_t sequence, bool bidirectional);

    uint64_t CloseStream(uint64_t sequence, uint64_t streamID);

    uint64_t SendData(uint64_t sequence, uint64_t streamID,
                      std::unique_ptr<uint8_t[]> buf, size_t len,
                      bool FIN = false);

    int SetStreamReadyCallback(uint64_t sequence,
                               StreamReadyCallbackType callback);

    int SetStreamDataReadyCallback(uint64_t sequence, uint64_t streamID,
                                   StreamDataReadyCallbackType callback);
    void enterRecovery(long int sentTimeOfLastLoss, int sequence);
    void onPacketsLost(std::list<std::shared_ptr<payload::Packet>> lostPackets, int sequence);
    int SocketLoop();
   protected:
    static std::shared_ptr<utils::UDPDatagram> encodeDatagram(
        const std::shared_ptr<payload::Packet>& pkt);
    virtual int incomingMsg(std::unique_ptr<utils::UDPDatagram> datagram) = 0;
    bool updateRTT(std::shared_ptr<thquic::context::Connection> connection, std::shared_ptr<payload::ACKFrame> ackFrame);
    void handleACKFrame(std::shared_ptr<payload::ACKFrame> ackFrame, uint64_t sequence);
    void checkPingPacket(std::shared_ptr<Connection> connection, utils::timepoint& now);
    void checkInitialPacket(std::shared_ptr<Connection> connection, utils::timepoint& now);
    void checkBufferPacket(std::shared_ptr<Connection> connection);
    void detectLossAndRetransmisson(std::shared_ptr<Connection> connection, utils::timepoint& now);
    void checkACKFrame(std::shared_ptr<Connection> connection);
    // Connection relative
    bool alive{true};
    uint64_t pktnum = 1;
    const PeerType type;
    utils::UDPSocket socket;
    std::map<uint64_t, std::shared_ptr<Connection>> connections;
    std::map<ConnectionID, uint64_t> ID2Sequence; // srcID to sequence
    std::map<uint64_t, ConnectionID> Sequence2ID; // sequence ti srcID
    std::map<ConnectionID, ConnectionID> SrcID2DstID;
    uint64_t connectionSequence;
    uint64_t stream_count[10000];
    std::map<uint64_t, uint64_t> streamID2Offset;
    std::list<std::shared_ptr<payload::Packet>>& getPackets(std::shared_ptr<thquic::context::Connection> connection);
    StreamDataReadyCallbackType streamDataReadyCallback;
    ConnectionCloseCallbackType ConnectionCloseCallback;
};

class QUICServer : public QUIC {
   public:
    explicit QUICServer(uint16_t port, std::string localAddress = "");

    int SetConnectionReadyCallback(ConnectionReadyCallbackType callback);

    StreamReadyCallbackType streamReadyCallback;

   protected:
    int incomingMsg(std::unique_ptr<utils::UDPDatagram> datagram);

   private:
    ConnectionReadyCallbackType connectionReadyCallback;
};

class QUICClient : public QUIC {
   public:
    QUICClient();

    uint64_t CreateConnection(struct sockaddr_in& addrTo,
                              const ConnectionReadyCallbackType& callback);

   protected:
    int incomingMsg(std::unique_ptr<utils::UDPDatagram> datagram);


   private:
    ConnectionReadyCallbackType connectionReadyCallback;
    sockaddr_in addrTo;
};

}  // namespace thquic::context

#endif
