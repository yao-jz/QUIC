#ifndef THQUIC_CONFIG_HH
#define THQUIC_CONFIG_HH

#include <algorithm>
#include <cstdint>
#include <memory>

#include "utils/time.hh"

using namespace std::chrono_literals;

namespace thquic::config {
constexpr size_t LOCAL_CONNECTION_ID_LENGTH = 0;
constexpr size_t CONNECTION_ID_MAX_SIZE = 20;
constexpr uint32_t QUIC_VERSION = 0x00000001;
constexpr uint64_t UDP_MAX_BODY = 1472;
constexpr utils::clock::duration MAX_ACK_DELAY = 25ms;
constexpr utils::clock::duration PING_INTERVAL = 2s;
constexpr utils::duration ZERO_DURATION = std::chrono::milliseconds(0);
constexpr utils::timepoint ZERO_TIMEPOINT = utils::timepoint(ZERO_DURATION);


namespace loss_detection {
constexpr uint64_t PACKET_THRESHOLD = 3;
constexpr uint64_t TIME_THRESHOLD = 8;
constexpr utils::duration GRANULARITY = 1ms;
constexpr utils::duration INITIAL_RTT = 333ms;
}  // namespace loss_detection

namespace congestion_control {
constexpr uint64_t INITIAL_WINDOW =
    std::min(std::max(14720ULL, 2ULL * UDP_MAX_BODY), (10ULL * UDP_MAX_BODY));
constexpr uint64_t MINIMUM_WINDOW = 2ULL * UDP_MAX_BODY;
constexpr uint64_t LOSS_REDUCTION_SCALE = 2;
}  // namespace congestion_control

}  // namespace thquic::config

#endif