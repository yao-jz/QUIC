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

    int SocketLoop();

   protected:
    static std::shared_ptr<utils::UDPDatagram> encodeDatagram(
        const std::shared_ptr<payload::Packet>& pkt);
    virtual int incomingMsg(std::unique_ptr<utils::UDPDatagram> datagram) = 0;
    void handleACKFrame(std::shared_ptr<payload::ACKFrame> ackFrame, uint_64 sequence);


    bool alive{true};
    uint64_t pktnum = 0;
    const PeerType type;
    utils::UDPSocket socket;
    std::map<uint64_t, std::shared_ptr<Connection>> connections;
    std::map<ConnectionID, uint64_t> ID2Sequence; // srcID to sequence
    std::map<uint64_t, ConnectionID> Sequence2ID; // sequence ti srcID
    std::map<ConnectionID, ConnectionID> SrcID2DstID;
    uint64_t connectionSequence;
    uint64_t stream_count[10000];
    StreamDataReadyCallbackType streamDataReadyCallback;
    ConnectionCloseCallbackType ConnectionCloseCallback;
    uint64_t pktnum = 0;
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
