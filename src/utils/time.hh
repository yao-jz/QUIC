#ifndef THQUIC_UTILS_TIME_HH
#define THQUIC_UTILS_TIME_HH

#include <chrono>

namespace thquic::utils {
using clock = std::chrono::steady_clock;
using timepoint = clock::time_point;
using duration = clock::duration;
using namespace std::chrono_literals;
}  // namespace thquic::utils

#endif
