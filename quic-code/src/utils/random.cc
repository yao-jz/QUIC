#include "utils/random.hh"

namespace thquic::utils {

RandomByteGenerator& RandomByteGenerator::Get() {
    static RandomByteGenerator generator{};
    return generator;
}

RandomByteGenerator::RandomByteGenerator() {
    auto constexpr SEED_BYTES =
        sizeof(typename std::mt19937::result_type) * std::mt19937::state_size;
    auto constexpr SEED_LENGTH =
        SEED_BYTES / sizeof(std::seed_seq::result_type);
    std::array<std::seed_seq::result_type, SEED_LENGTH> seed;
    std::random_device dev;
    std::generate_n(std::begin(seed), SEED_LENGTH, std::ref(dev));
    std::seed_seq seed_seq(std::begin(seed), std::end(seed));
    rnd.seed(seed_seq);
}

}  // namespace thquic::utils