
#include "utils/variable_codec.hh"

#include "utils/log.hh"

namespace thquic::utils {

using EncodeParam = std::pair<uint8_t, uint8_t>;
constexpr uint64_t ENCODE_UPPER_BOUND[4] = {0x3F, 0x3F'FF, 0x3F'FF'FF'FF,
                                            0x3F'FF'FF'FF'FF'FF'FF'FF};
constexpr EncodeParam ENCODE_PARAMS[4] = {
    std::make_pair(0x00, 1), std::make_pair(0x40, 2), std::make_pair(0x80, 4),
    std::make_pair(0xC0, 8)};

int encodeUInt(ByteStream& stream, uint64_t value, uint8_t intSize) {
    auto buf = stream.Consume(intSize).first;

    switch (intSize) {
        case 8:
            buf[7] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 8)));
            __attribute__((fallthrough));
        case 7:
            buf[6] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 7)));
            __attribute__((fallthrough));
        case 6:
            buf[5] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 6)));
            __attribute__((fallthrough));
        case 5:
            buf[4] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 5)));
            __attribute__((fallthrough));
        case 4:
            buf[3] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 4)));
            __attribute__((fallthrough));
        case 3:
            buf[2] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 3)));
            __attribute__((fallthrough));
        case 2:
            buf[1] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 2)));
            __attribute__((fallthrough));
        case 1:
            buf[0] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (intSize - 1)));
            break;
        default:
            throw std::invalid_argument(
                fmt::format("only support encoding interger from 8-bit to "
                            "64-bit, provide {}",
                            intSize));
    }
    return 0;
}

uint64_t decodeUint(ByteStream& stream, uint8_t intSize) {
    auto buf = stream.Consume(intSize).first;
    uint64_t value = 0;
    switch (intSize) {
        case 8:
            value |= static_cast<uint64_t>(buf[7])
                     << static_cast<uint64_t>(8 * (intSize - 8));
            __attribute__((fallthrough));
        case 7:
            value |= static_cast<uint64_t>(buf[6])
                     << static_cast<uint64_t>(8 * (intSize - 7));
            __attribute__((fallthrough));
        case 6:
            value |= static_cast<uint64_t>(buf[5])
                     << static_cast<uint64_t>(8 * (intSize - 6));
            __attribute__((fallthrough));
        case 5:
            value |= static_cast<uint64_t>(buf[4])
                     << static_cast<uint64_t>(8 * (intSize - 5));
            __attribute__((fallthrough));
        case 4:
            value |= static_cast<uint64_t>(buf[3])
                     << static_cast<uint64_t>(8 * (intSize - 4));
            __attribute__((fallthrough));
        case 3:
            value |= static_cast<uint64_t>(buf[2])
                     << static_cast<uint64_t>(8 * (intSize - 3));
            __attribute__((fallthrough));
        case 2:
            value |= static_cast<uint64_t>(buf[1])
                     << static_cast<uint64_t>(8 * (intSize - 2));
            __attribute__((fallthrough));
        case 1:
            value |= static_cast<uint64_t>(buf[0])
                     << static_cast<uint64_t>(8 * (intSize - 1));
            break;
        default:
            throw std::invalid_argument(
                "only support encoding interger from 8-bit to 64-bit");
    }
    return value;
}

size_t encodeVarIntLen(uint64_t value) {
    uint8_t encodeIndex =
        std::upper_bound(std::begin(ENCODE_UPPER_BOUND),
                         std::end(ENCODE_UPPER_BOUND), value) -
        std::begin(ENCODE_UPPER_BOUND);
    return ENCODE_PARAMS[encodeIndex].second;
}

// QUIC RFC Sec. 16 Variable-Length Integer Encoding
int encodeVarInt(ByteStream& stream, uint64_t value) {
    uint8_t encodeIndex =
        std::upper_bound(std::begin(ENCODE_UPPER_BOUND),
                         std::end(ENCODE_UPPER_BOUND), value) -
        std::begin(ENCODE_UPPER_BOUND);
    if (encodeIndex == 4) {
        throw std::invalid_argument(
            "variable encoding support integer less than "
            "0x3FFFFFFFFFFFFFFF(4611686018427387903)");
    }

    uint8_t encodeFlag = ENCODE_PARAMS[encodeIndex].first;
    uint8_t encodeSize = ENCODE_PARAMS[encodeIndex].second;

    auto buf = stream.Consume(encodeSize).first;
    switch (encodeIndex) {
        case 3:
            buf[7] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 8)));
            buf[6] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 7)));
            buf[5] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 6)));
            buf[4] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 5)));
            __attribute__((fallthrough));
        case 2:
            buf[3] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 4)));
            buf[2] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 3)));
            __attribute__((fallthrough));
        case 1:
            buf[1] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 2)));
            __attribute__((fallthrough));
        case 0:
            buf[0] = static_cast<uint8_t>(
                value >> static_cast<uint64_t>(8 * (encodeSize - 1)));
            buf[0] |= encodeFlag;
            break;
        default:
            throw std::logic_error("should not reach here");
    }
    return 0;
}

uint64_t decodeVarInt(ByteStream& stream) {
    using DecodeParam = std::pair<uint8_t, uint64_t>;
    static std::array<DecodeParam, 4> decodeParams = {
        std::make_pair(1, 0x3F), std::make_pair(2, 0x3F'FF),
        std::make_pair(4, 0x3F'FF'FF'FF),
        std::make_pair(8, 0x3F'FF'FF'FF'FF'FF'FF'FF)};

    auto buf = stream.Fetch(1).first;
    uint8_t decodeFlag = (buf[0] & 0xC0) >> 6;
    uint8_t decodeSize = decodeParams[decodeFlag].first;

    uint64_t value = 0;

    buf = stream.Consume(decodeSize).first;

    switch (decodeFlag) {
        case 3:
            value |= static_cast<uint64_t>(buf[7])
                     << static_cast<uint64_t>(8 * (decodeSize - 8));
            value |= static_cast<uint64_t>(buf[6])
                     << static_cast<uint64_t>(8 * (decodeSize - 7));
            value |= static_cast<uint64_t>(buf[5])
                     << static_cast<uint64_t>(8 * (decodeSize - 6));
            value |= static_cast<uint64_t>(buf[4])
                     << static_cast<uint64_t>(8 * (decodeSize - 5));
            [[fallthrough]];
        case 2:
            value |= static_cast<uint64_t>(buf[3])
                     << static_cast<uint64_t>(8 * (decodeSize - 4));
            value |= static_cast<uint64_t>(buf[2])
                     << static_cast<uint64_t>(8 * (decodeSize - 3));
            [[fallthrough]];
        case 1:
            value |= static_cast<uint64_t>(buf[1])
                     << static_cast<uint64_t>(8 * (decodeSize - 2));
            [[fallthrough]];
        case 0:
            value |= static_cast<uint64_t>(buf[0] & 0x3F)
                     << static_cast<uint64_t>(8 * (decodeSize - 1));
            break;
        default:
            throw std::logic_error("should not reach here");
    }
    return value;
}

int encodeBuffer(ByteStream& stream, const std::unique_ptr<uint8_t[]>& buf,
                 size_t len) {
    auto dstBuf = stream.Consume(len);
    std::copy(buf.get(), buf.get() + len, dstBuf.first);
    return 0;
}

std::unique_ptr<uint8_t[]> decodeBuffer(ByteStream& stream, size_t len) {
    auto dstBuf = std::make_unique<uint8_t[]>(len);
    auto buf = stream.Consume(len);
    std::copy(buf.first, buf.second, dstBuf.get());
    return dstBuf;
}

template <size_t SIZE>
std::array<uint8_t, SIZE> decodeBuffer(ByteStream& stream) {
    std::array<uint8_t, SIZE> dstBuf;
    auto buf = stream.Consume(SIZE);
    std::copy(buf.first, buf.second, std::begin(dstBuf));
    return dstBuf;
}

}  // namespace thquic::utils