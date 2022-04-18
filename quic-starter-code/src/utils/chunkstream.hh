#ifndef THQUIC_UTILS_CHUNKSTREAM_HH
#define THQUIC_UTILS_CHUNKSTREAM_HH

#include <algorithm>
#include <list>
#include <memory>

#include "utils/bytestream.hh"
#include "utils/log.hh"

namespace thquic::utils {

class Chunk : public ByteStream {
   public:
    Chunk(uint8_t* buffer, size_t len, uint64_t offset)
        : ByteStream(buffer, len), offset{offset} {}

    Chunk(Chunk&& stream) = default;

    explicit Chunk(size_t len, size_t offset)
        : ByteStream(len), offset{offset} {}

    Chunk(std::unique_ptr<uint8_t[]> buffer, size_t len, uint64_t offset)
        : ByteStream(std::move(buffer), len), offset{offset} {}

    uint64_t MaximumOffset() const {
        return this->offset + this->GetBufferLen();
    }
    uint64_t MinimumOffset() const { return this->offset + this->Pos(); }

   private:
    const uint64_t offset{0}; // 单位是字节
};

class ChunkStream {
   public:
    ChunkStream() { this->maximumContinuousChunk = this->chunks.end(); }

    void AddChunk(std::unique_ptr<uint8_t[]> buf, size_t len,
                  bool fin = false) {
        if (this->fin) {
            throw std::runtime_error("streams has been marked as FIN");
        }
        this->chunks.emplace_back(std::move(buf), len, this->maximumOffset);
        this->maximumOffset += len;

        this->fin |= fin;
        this->checkContinuous();
    }

    void AddChunk(uint64_t offset, std::unique_ptr<uint8_t[]> buf, size_t len,
                  bool fin = false) {
        
        Chunk chunk{std::move(buf), len, offset};
        this->fin |= fin;

        if ((offset + len) <= this->ConsumedOffset()) {
            return;
        } else if (offset < this->ConsumedOffset()) {
            chunk.Consume(this->ConsumedOffset() - offset);
        }


        if (this->chunks.empty()) {
            this->chunks.push_back(std::move(chunk));
            this->checkContinuous();
            this->maximumOffset = this->chunks.back().MaximumOffset();
            return;
        }

        auto reverseRight =
            std::find_if(std::rbegin(this->chunks), std::rend(this->chunks),
                         [&chunk](const Chunk& p) -> bool {
                             return p.MaximumOffset() <= chunk.MaximumOffset();
                         });

        auto leftSearchStart = (reverseRight == this->chunks.rbegin())
                                   ? this->chunks.rbegin()
                                   : std::prev(reverseRight);
        auto reverseLeft = std::find_if(
            leftSearchStart, std::rend(this->chunks), [&chunk](const Chunk& p) {
                return p.MinimumOffset() < chunk.MinimumOffset();
            });

        auto right = reverseRight.base();
        auto left = reverseLeft == this->chunks.rend()
                        ? this->chunks.end()
                        : std::prev(reverseLeft.base());

        if (left == right) {
            if (left == this->chunks.end()) {
                this->chunks.clear();
                this->chunks.push_back(std::move(chunk));
                this->maximumContinuousChunk = this->chunks.end();
                this->checkContinuous();
            }
            return;
        }

        if (left != std::end(this->chunks)) {
            if (left->MaximumOffset() > chunk.MinimumOffset()) {
                chunk.Consume(left->MaximumOffset() - chunk.MinimumOffset());
            }
            left++;
        } else {
            left = this->chunks.begin();
        }

        if (right != std::end(this->chunks)) {
            if (right->MinimumOffset() < chunk.MaximumOffset()) {
                right->Consume(chunk.MaximumOffset() - right->MinimumOffset());
            }
        }

        if (std::distance(left, right) > 0) {
            bool recheck = false;
            for (auto iter = left; iter != right; iter++) {
                if (this->maximumContinuousChunk == iter) {
                    recheck = true;
                }
            }

            if (recheck) {
                this->maximumContinuousChunk = left == this->chunks.begin()
                                                   ? this->chunks.end()
                                                   : std::prev(left);
            }

            this->chunks.erase(left, right);
        }

        if (fin && right != std::end(this->chunks)) {
            this->chunks.erase(right, std::end(this->chunks));
            right = this->chunks.end();
        }

        this->chunks.insert(right, std::move(chunk));
        this->maximumOffset = this->chunks.back().MaximumOffset();

        assert(this->ConsumedOffset() <= this->chunks.front().MinimumOffset());
        this->checkContinuous();
    }

    std::unique_ptr<uint8_t[]> Consume(size_t len) {
        auto ptr = std::make_unique<uint8_t[]>(len);
        Consume(len, ptr);
        return ptr;
    }

    void Consume(size_t len, const std::unique_ptr<uint8_t[]>& outBuf,
                 size_t offset = 0) {
        if (len > this->AvailableLen()) {
            throw std::invalid_argument("there is no enough room");
        }
        size_t pos = 0;
        size_t remain = len;
        do {
            auto& chunk = chunks.front();
            size_t used = remain >= chunk.GetFree() ? chunk.GetFree() : remain;
            auto buf = chunk.Consume(used);
            std::copy(buf.first, buf.second, outBuf.get() + offset + pos);
            remain -= used;
            pos += used;
            this->maximumConsumedOffset += used;

            if (chunk.Empty()) {
                if (this->maximumContinuousChunk == chunks.begin()) {
                    this->maximumContinuousChunk = chunks.end();
                }
                chunks.pop_front();
            }
        } while (remain);
    }

    void checkContinuous() {
        if (this->maximumContinuousChunk == this->chunks.end()) {
            if (this->maximumConsumedOffset ==
                this->chunks.front().MinimumOffset()) {
                this->maximumContinuousChunk = this->chunks.begin();
            } else {
                return;
            }
        }

        auto next = std::next(this->maximumContinuousChunk);
        while (next != std::end(this->chunks) &&
               (this->maximumContinuousChunk->MaximumOffset() ==
                (next->MinimumOffset()))) {
            maximumContinuousChunk = next;
            next = std::next(maximumContinuousChunk);
        }
    }

    size_t AvailableLen() {
        if (maximumContinuousChunk == chunks.end()) {
            return 0;
        }
        return maximumContinuousChunk->MaximumOffset() -
               chunks.front().MinimumOffset();
    }

    uint64_t MaximumOffset() const {
        return this->chunks.back().MaximumOffset();
    }

    uint64_t MinimumOffset() const {
        return this->chunks.front().MinimumOffset();
    }

    bool Empty() { return this->chunks.empty(); }

    uint64_t ConsumedOffset() const { return maximumConsumedOffset; }

    bool FIN() const {
        bool IsAllDataConsumed =
            (this->maximumConsumedOffset) == this->maximumOffset;
        return this->fin && IsAllDataConsumed;
    }

    void Logout() {
        std::string chunksStr = "";
        uint64_t start = chunks.front().MinimumOffset();
        for (auto iter = chunks.cbegin(); iter != chunks.cend(); iter++) {
            auto next = std::next(iter);
            if (next == chunks.cend() ||
                iter->MaximumOffset() != next->MinimumOffset()) {
                chunksStr += "(" + std::to_string(start) + " : " +
                             std::to_string(iter->MaximumOffset()) + ")";
                start = next == chunks.cend() ? 0 : next->MinimumOffset();
            }
        }
        logger::warn("[QUIC] consumed: {}, max: {}, chunks: {}, {}, {}",
                     maximumConsumedOffset, this->maximumOffset, chunksStr,
                     this->fin ? "END" : "ALIVE", this->FIN() ? "EMPTY" : " ");
    }

   private:
    std::list<Chunk> chunks;
    decltype(chunks)::iterator maximumContinuousChunk;

    bool fin{false};

    uint64_t maximumOffset{};
    uint64_t maximumConsumedOffset{};
};

}  // namespace thquic::utils

#endif
