#ifndef THQUIC_UTILS_VARIABLE_CODEC_HH
#define THQUIC_UTILS_VARIABLE_CODEC_HH

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <optional>
#include <iostream>
#include <stdexcept>

#include "utils/bytestream.hh"

namespace thquic::utils {

int encodeUInt(ByteStream& stream, uint64_t value, uint8_t intSize);
uint64_t decodeUint(ByteStream& stream, uint8_t intSize);

using TruncatedPacketNumber = std::pair<uint32_t, uint8_t>;

inline TruncatedPacketNumber encodePacketNumber(uint64_t packetNumber,
                                                uint64_t largestAcked) {
    constexpr auto DIGITS = std::numeric_limits<decltype(packetNumber)>::digits;
    uint64_t numberOfUnACKed =
        largestAcked != std::numeric_limits<decltype(largestAcked)>::max()
            ? packetNumber - largestAcked
            : packetNumber + 1;
    size_t numberOfBits = DIGITS - std::countl_zero(numberOfUnACKed) + 1;

    if (numberOfBits > 32) {
        throw std::invalid_argument(
            "the length of packet number field cannot exceed 32 bits (4 "
            "bytes)");
    }

    numberOfBits = (numberOfBits == 0)
                       ? 1
                       : numberOfBits;  // We still need one bit to store zero.
    uint8_t numberOfBytes = static_cast<uint8_t>((numberOfBits + 7) / 8);

    uint64_t mask =
        std::numeric_limits<uint64_t>::max() >> (DIGITS - 8 * numberOfBytes);
    uint32_t maskedPacketNumber = static_cast<uint32_t>(mask & packetNumber);
    return std::make_pair(maskedPacketNumber, numberOfBytes);
}

inline uint64_t decodePacketNumber(uint32_t truncatedPacketNumber,
                                   size_t numberOfBytes,
                                   uint64_t largestPacketNumber) {
    assert(numberOfBytes <= 4);

    uint64_t expectedPacketNumber =
        largestPacketNumber ==
                std::numeric_limits<decltype(largestPacketNumber)>::max()
            ? 0
            : largestPacketNumber + 1;
    uint64_t packetNumberWindow =
        1 << (numberOfBytes * std::numeric_limits<unsigned char>::digits);
    uint64_t packetNumberHalfWindow = packetNumberWindow / 2;
    uint64_t packetNumberMask = packetNumberWindow - 1;
    uint64_t candidatePacketNumber =
        (expectedPacketNumber & ~packetNumberMask) | truncatedPacketNumber;

    if ((expectedPacketNumber > packetNumberHalfWindow) &&
        (candidatePacketNumber <=
         expectedPacketNumber - packetNumberHalfWindow) &&
        (candidatePacketNumber < ((1ULL << 62) - packetNumberWindow))) {
        return candidatePacketNumber + packetNumberWindow;
    }
    if ((candidatePacketNumber >
         expectedPacketNumber + packetNumberHalfWindow) &&
        candidatePacketNumber >= packetNumberWindow) {
        return candidatePacketNumber - packetNumberWindow;
    }
    return candidatePacketNumber;
}

// QUIC RFC Sec. 16 Variable-Length Integer Encoding
int encodeVarInt(ByteStream& stream, uint64_t value);
uint64_t decodeVarInt(ByteStream& stream);
size_t encodeVarIntLen(uint64_t value);

int encodeBuffer(ByteStream& stream, const std::unique_ptr<uint8_t[]>& buf,
                 size_t len);

template <std::size_t SIZE>
void encodeBuffer(ByteStream& stream, std::array<int, SIZE>& buf) {
    auto dstBuf = stream.Consume(SIZE);
    std::copy(std::cbegin(buf), std::cend(buf), dstBuf.first);
}

std::unique_ptr<uint8_t[]> decodeBuffer(ByteStream& stream, size_t len);

}  // namespace thquic::utils
#endif
