#ifndef THQUIC_UTILS_BYTESTREAM_HH
#define THQUIC_UTILS_BYTESTREAM_HH

#include <cassert>
#include <cstdint>
#include <memory>

namespace thquic::utils {
class ByteStream {
   public:
    ByteStream(uint8_t* buffer, size_t len)
        : buffer(buffer), len{len}, pos{0} {}

    explicit ByteStream(size_t len) : len{len}, pos{0} {
        this->buffer = std::make_unique<uint8_t[]>(len);
    }

    ByteStream(std::unique_ptr<uint8_t[]> buffer, size_t len)
        : buffer(std::move(buffer)), len{len}, pos{0} {}

    ByteStream(const ByteStream& other) = delete;

    ByteStream(ByteStream&& stream) = default;

    std::pair<uint8_t*, uint8_t*> Consume(size_t n) {
        this->CheckFree(n);
        auto range = std::make_pair<uint8_t*, uint8_t*>(buffer.get() + pos,
                                                        buffer.get() + pos + n);
        pos += n;
        return range;
    }

    std::pair<uint8_t*, uint8_t*> Fetch(size_t n) {
        this->CheckFree(n);
        auto range = std::make_pair<uint8_t*, uint8_t*>(buffer.get() + pos,
                                                        buffer.get() + pos + n);
        return range;
    }

    std::unique_ptr<uint8_t[]> FetchBuffer() {
        pos = len;
        return std::move(buffer);
    }

    size_t GetBufferLen() const { return this->len; }

    size_t GetFree() const { return this->len - this->pos; }

    void CheckFree(size_t n) const { assert((this->len - pos) >= n); }

    bool Empty() const { return this->pos == this->len; }

    bool None() const { return this->len == 0; }

    size_t Pos() const { return this->pos; }

    void Reset() { this->pos = 0; }

   private:
    std::unique_ptr<uint8_t[]> buffer;
    size_t len{};
    size_t pos{};
};

}  // namespace thquic::utils

#endif