#ifndef THQUIC_CONTEXT_COMMON_HH
#define THQUIC_CONTEXT_COMMON_HH

#include <memory>

namespace thquic::context {
enum class PacketContext { INITIAL, HANDSHAKE, APPLICATION };

enum class PeerType { CLIENT, SERVER };

enum class EventType { ACK_DELAY, POTENTIAL_LOSS, DATA_SEND, PING, EVENT_NUM };

enum class StreamType {
    CLIENT_BI = 0,
    SERVER_BI = 1,
    CLIENT_UNI = 2,
    SERVER_UNI = 3
};

constexpr int MAX_SLICE_LENGTH = 1370;

constexpr size_t STREAM_TYPE_NUM = 4;

}  // namespace thquic::context
#endif