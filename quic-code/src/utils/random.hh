#ifndef QUIC_UTILS_RANDOM_HH
#define QUIC_UTILS_RANDOM_HH
#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <random>

namespace thquic::utils {
// WARNING: INSECURE
// TODO: use crypto-secure random
class RandomByteGenerator {
   public:
    static RandomByteGenerator& Get();

    template <class iterator>
    int Fill(iterator begin, size_t len) {
        static constexpr auto CHARS =
            "0123456789"
            "abcdefghijklmnopqrstuvwxyz";

        static std::uniform_int_distribution dist{{}, std::strlen(CHARS) - 1};

        std::generate_n(begin, len,
                        [this]() { return CHARS[dist(this->rnd)]; });
        return 0;
    }

    uint64_t GetRandom(uint64_t minimum, uint64_t maximum) {
        std::uniform_int_distribution dist{minimum, maximum};
        return dist(this->rnd);
    }

   private:
    RandomByteGenerator();
    std::mt19937 rnd;
};

}  // namespace thquic::utils

#endif