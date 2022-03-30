#ifndef THQUIC_CONTEXT_CALLBACK_HH
#define THQUIC_CONTEXT_CALLBACK_HH

#include <functional>
#include <memory>

namespace thquic::context {

using ConnectionReadyCallbackType = std::function<int(uint64_t)>;
using ConnectionCloseCallbackType =
    std::function<int(uint64_t, std::string, uint64_t)>;

using StreamReadyCallbackType = std::function<int(uint64_t, uint64_t)>;
using StreamAbortCallbackType = std::function<int(uint64_t, uint64_t)>;
using StreamResetCallbackType = std::function<int(uint64_t, uint64_t)>;
using StreamDataReadyCallbackType = std::function<int(
    uint64_t, uint64_t, std::unique_ptr<uint8_t[]>, size_t, bool)>;

}  // namespace thquic::context

#endif  // THQUIC_CALLBACK_HH
