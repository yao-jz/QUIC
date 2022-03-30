#ifndef THQUIC_PAYLOAD_FRAME_HH
#define THQUIC_PAYLOAD_FRAME_HH

/*
 * There are four types of frames
 * 1) no context
 *    * PADDING Frame
 *    * PING Frame
 * 2) connection context
 *    * ACK Frame
 *    * CRYPTO Frame
 *    * NEW_TOKEN Frame
 *    * NEW_CONNECTION_ID Frame
 *    * RETIRE_CONNECTION_ID Frame
 *    * PATH_CHALLENGE
 *    * PATH_RESPONSE
 *    * CONNECTION_CLOSE
 *    * HANDSHAKE_DONE
 * 3). streams context
 *    * MAX_DATA Frame
 *    * MAX_STREAMS Frame
 *    * DATA_BLOCKED Frame
 *    * STREAMS_BLOCKED Frame
 * 4). stream context
 *    * RESET_STREAM Frame
 *    * STOP_SENDING Frame
 *    * STREAM Frame
 *    * MAXIMUM_STREAM_DATA Frame
 *    * STREAM_DATA_BLOCKED Frame
 * */

#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <sstream>

#include "context/connection_id.hh"
#include "payload/common.hh"
#include "utils/bytestream.hh"
#include "utils/interval.hh"
#include "utils/variable_codec.hh"

namespace thquic::payload {

enum class FrameType {
    PADDING,
    PING,
    ACK,
    RESET_STREAM,
    STOP_SENDING,
    CRYPTO,
    NEW_TOKEN,
    STREAM,
    MAX_DATA,
    MAX_STREAM_DATA,
    MAX_STREAMS,
    DATA_BLOCKED,
    STREAM_DATA_BLOCKED,
    STREAMS_BLOCKED,
    NEW_CONNECTION_ID,
    RETIRE_CONNECTION_ID,
    PATH_CHALLENGE,
    PATH_RESPONSE,
    CONNECTION_CLOSE,
    HANDSHAKE_DONE
};

class PaddingFrame;
class PingFrame;
class ACKFrame;
class ACKECNFrame;
class ResetStreamFrame;
class StopSendingFrame;
class CryptoFrame;
class NewTokenFrame;
class StreamFrame;
class MaxDataFrame;
class MaxStreamDataFrame;
class MaxStreamsFrame;
class DataBlockedFrame;
class StreamDataBlockedFrame;
class StreamsBlockedFrame;
class NewConnectionIDFrame;
class RetireConnectionIDFrame;
class PathChallengeFrame;
class PathResponseFrame;
class ConnectionCloseQUICFrame;
class ConnectionCloseAppFrame;
class HandshakeDoneFrame;

class Frame : public Serialization {
   public:
    static std::shared_ptr<Frame> Parse(utils::ByteStream& stream) {
        auto buf = stream.Fetch(1).first;
        switch (*buf) {
            case 0x00:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<PaddingFrame>(stream));
            case 0x01:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<PingFrame>(stream));
            case 0x02:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<ACKFrame>(stream));
            case 0x03:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<ACKECNFrame>(stream));
            case 0x04:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<ResetStreamFrame>(stream));
            case 0x05:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<StopSendingFrame>(stream));
            case 0x06:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<CryptoFrame>(stream));
            case 0x07:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<NewTokenFrame>(stream));
            case 0x08:
            case 0x09:
            case 0x0A:
            case 0x0B:
            case 0x0C:
            case 0x0D:
            case 0x0E:
            case 0x0F:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<StreamFrame>(stream));
            case 0x10:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<MaxDataFrame>(stream));
            case 0x11:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<MaxStreamDataFrame>(stream));
            case 0x12:
            case 0x13:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<MaxStreamsFrame>(stream));
            case 0x14:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<DataBlockedFrame>(stream));
            case 0x15:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<StreamDataBlockedFrame>(stream));
            case 0x16:
            case 0x17:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<StreamsBlockedFrame>(stream));
            case 0x18:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<NewConnectionIDFrame>(stream));
            case 0x19:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<RetireConnectionIDFrame>(stream));
            case 0x1A:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<PathChallengeFrame>(stream));
            case 0x1B:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<PathResponseFrame>(stream));
            case 0x1C:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<ConnectionCloseQUICFrame>(stream));
            case 0x1D:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<ConnectionCloseAppFrame>(stream));
            case 0x1E:
                return std::static_pointer_cast<Frame>(
                    std::make_shared<HandshakeDoneFrame>(stream));
            default:
                throw std::invalid_argument("parse error");
        }
    }
    virtual uint8_t ID() const = 0;
    virtual FrameType Type() const = 0;
    virtual const char* Name() const = 0;
    virtual std::string Str() const override {
        return std::string(this->Name());
    }
};

// RESET_STREAM / STOP_SENDING / STREAM / MAX_STREAM_DATA / STREAM_DATA_BLOCKED
class StreamSpecificFrame : public Frame {
   public:
    virtual uint64_t StreamID() const = 0;
};

class PaddingFrame : public Frame {
   public:
    explicit PaddingFrame(utils::ByteStream& stream) : len{0} {
        while (*stream.Fetch(1).first == 0x00) {
            len++;
            stream.Consume(1);
        }
    }

    explicit PaddingFrame(size_t len) : len(len) {}

    uint8_t ID() const override { return 0x00; };

    FrameType Type() const override { return FrameType::PADDING; }

    const char* Name() const override { return "PADDING"; }

    int Encode(utils::ByteStream& stream) override {
        auto buf = stream.Consume(len).first;
        std::memset(buf, 0, len);
        return 0;
    }

    size_t EncodeLen() const override { return this->len; }

   private:
    size_t len;
};

class PingFrame : public Frame {
   public:
    PingFrame() = default;

    explicit PingFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
    }

    uint8_t ID() const override { return 0x01; }

    FrameType Type() const override { return FrameType::PING; }

    const char* Name() const override { return "PING"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        return 0;
    }

    size_t EncodeLen() const override { return 1; }
};

// we don't use gap, range pair as specified in the RFC in protocol processing
// and only transform lazily when encoding.
class ACKFrame : public Frame {
   public:
    ACKFrame(uint64_t ACKDelay, utils::IntervalSet ACKRange)
        : ACKDelay{ACKDelay}, ACKRange{ACKRange} {}

    explicit ACKFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        uint64_t largestACKed = utils::decodeVarInt(stream);
        this->ACKDelay = utils::decodeVarInt(stream);
        uint64_t ACKRangeCount = utils::decodeVarInt(stream);

        uint64_t firstACKRange = utils::decodeVarInt(stream);
        uint64_t smallestACKed = largestACKed - firstACKRange;

        this->ACKRange.AddInterval(smallestACKed, largestACKed);

        for (unsigned i = 0; i < ACKRangeCount; i++) {
            uint64_t gap = utils::decodeVarInt(stream);
            uint64_t range = utils::decodeVarInt(stream);

            largestACKed = smallestACKed - gap - 2;
            smallestACKed = largestACKed - range;
            this->ACKRange.AddInterval(smallestACKed, largestACKed);
        }
    }

    std::string Str() const override {
        return std::string("ack ") + this->ACKRange.Dump();
    }

    uint8_t ID() const override { return 0x02; };

    FrameType Type() const override { return FrameType::ACK; }

    const char* Name() const override { return "ACK"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        if (ACKRange.Intervals().size() > 0) {
            auto iter = ACKRange.Intervals().cbegin();
            utils::encodeVarInt(stream, iter->End());
            utils::encodeVarInt(stream, this->ACKDelay);
            utils::encodeVarInt(stream, ACKRange.Intervals().size() - 1);
            utils::encodeVarInt(stream, iter->End() - iter->Start());
            iter++;
            while (iter != ACKRange.Intervals().cend()) {
                uint64_t gap = std::prev(iter)->Start() - iter->End() - 2;
                uint64_t range = iter->End() - iter->Start();
                utils::encodeVarInt(stream, gap);
                utils::encodeVarInt(stream, range);
                iter++;
            }
        }
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        if (ACKRange.Intervals().size() > 0) {
            auto iter = ACKRange.Intervals().cbegin();

            len += utils::encodeVarIntLen(iter->End());
            len += utils::encodeVarIntLen(this->ACKDelay);
            len += utils::encodeVarIntLen(ACKRange.Intervals().size() - 1);
            len += utils::encodeVarIntLen(iter->End() - iter->Start());

            iter++;
            while (iter != ACKRange.Intervals().cend()) {
                uint64_t gap = std::prev(iter)->Start() - iter->End() - 2;
                uint64_t range = iter->End() - iter->Start();

                len += utils::encodeVarIntLen(gap);
                len += utils::encodeVarIntLen(range);

                iter++;
            }
        }

        return len;
    }

    uint64_t GetLargestACKed() const {
        return this->ACKRange.Intervals().front().End();
    }

    uint64_t GetACKDelay() const { return this->ACKDelay; }

    const utils::IntervalSet& GetACKRanges() const { return this->ACKRange; }

   private:
    uint64_t ACKDelay;
    utils::IntervalSet ACKRange;
};

class ACKECNFrame : public ACKFrame {
   public:
    struct ECNCount_t {
        uint64_t ECT0Count;
        uint64_t ECT1Count;
        uint64_t ECTCECount;
    };

    ACKECNFrame(uint64_t ACKDelay, utils::IntervalSet ACKRange,
                uint64_t ECT0Count, uint64_t ECT1Count, uint64_t ECTCECount)
        : ACKFrame(ACKDelay, ACKRange),
          ECNCount{ECT0Count, ECT1Count, ECTCECount} {}

    explicit ACKECNFrame(utils::ByteStream& stream) : ACKFrame(stream) {
        this->ECNCount.ECT0Count = utils::decodeVarInt(stream);
        this->ECNCount.ECT1Count = utils::decodeVarInt(stream);
        this->ECNCount.ECTCECount = utils::decodeVarInt(stream);
    }

    int Encode(utils::ByteStream& stream) override {
        this->ACKFrame::Encode(stream);
        utils::encodeVarInt(stream, this->ECNCount.ECT0Count);
        utils::encodeVarInt(stream, this->ECNCount.ECT1Count);
        utils::encodeVarInt(stream, this->ECNCount.ECTCECount);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += this->ACKFrame::EncodeLen();
        len += utils::encodeVarIntLen(this->ECNCount.ECT0Count);
        len += utils::encodeVarIntLen(this->ECNCount.ECT1Count);
        len += utils::encodeVarIntLen(this->ECNCount.ECTCECount);
        return len;
    }

    uint8_t ID() const override { return 0x03; }

    FrameType Type() const override { return FrameType::ACK; }

    const char* Name() const override { return "ACK"; }

    uint64_t GetECT0Count() const { return this->ECNCount.ECT0Count; }

    uint64_t GetECT1Count() const { return this->ECNCount.ECT1Count; }

    uint64_t GetECTCECount() const { return this->ECNCount.ECTCECount; }

    struct ECNCount_t ECNCount;
};

class ResetStreamFrame : public StreamSpecificFrame {
   public:
    ResetStreamFrame(uint64_t streamID, uint64_t errorCode, uint64_t size)
        : streamID{streamID}, appProtoErrCode{errorCode}, finalSize{size} {}

    explicit ResetStreamFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->streamID = utils::decodeVarInt(stream);
        this->appProtoErrCode = utils::decodeVarInt(stream);
        this->finalSize = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x04; }

    FrameType Type() const override { return FrameType::RESET_STREAM; }

    const char* Name() const override { return "RESET_STREAM"; }

    uint64_t StreamID() const override { return this->streamID; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->streamID);
        utils::encodeVarInt(stream, this->appProtoErrCode);
        utils::encodeVarInt(stream, this->finalSize);
        return 0;
    }

    size_t EncodeLen() const override {
        return utils::encodeVarIntLen(this->ID()) +
               utils::encodeVarIntLen(this->streamID) +
               utils::encodeVarIntLen(this->appProtoErrCode) +
               utils::encodeVarIntLen(this->finalSize);
    }

    uint64_t GetAppProtoErrCode() const { return this->appProtoErrCode; }

    uint64_t GetFinalSize() const { return this->finalSize; }

   private:
    uint64_t streamID;
    uint64_t appProtoErrCode;
    uint64_t finalSize;
};

class StopSendingFrame : public StreamSpecificFrame {
   public:
    StopSendingFrame(uint64_t stream, uint64_t errorCode)
        : streamID{stream}, appProtoErrCode{errorCode} {}

    explicit StopSendingFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->streamID = utils::decodeVarInt(stream);
        this->appProtoErrCode = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x05; }

    FrameType Type() const override { return FrameType::STOP_SENDING; }

    const char* Name() const override { return "STOP_SENDING"; }

    uint64_t StreamID() const override { return this->streamID; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->streamID);
        utils::encodeVarInt(stream, this->appProtoErrCode);
        return 0;
    }

    size_t EncodeLen() const override {
        return utils::encodeVarIntLen(this->ID()) +
               utils::encodeVarIntLen(this->streamID) +
               utils::encodeVarIntLen(this->appProtoErrCode);
    }

    uint64_t GetErrorCode() const { return this->appProtoErrCode; }

   private:
    uint64_t streamID;
    uint64_t appProtoErrCode;
};

class CryptoFrame : public Frame {
   public:
    CryptoFrame(uint64_t offset, uint64_t length,
                std::unique_ptr<uint8_t[]> buf)
        : offset{offset}, length{length}, cryptoData{std::move(buf)} {}

    explicit CryptoFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->offset = utils::decodeVarInt(stream);
        this->length = utils::decodeVarInt(stream);
        auto buf = stream.Consume(length);
        this->cryptoData = std::make_unique<uint8_t[]>(this->length);
        std::copy(buf.first, buf.second, this->cryptoData.get());
    }

    uint8_t ID() const override { return 0x06; }

    FrameType Type() const override { return FrameType::CRYPTO; }

    const char* Name() const override { return "CRYPTO"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->offset);
        utils::encodeVarInt(stream, this->length);
        auto buf = stream.Consume(this->length).first;
        std::copy(cryptoData.get(), cryptoData.get() + this->length, buf);
        return 0;
    }

    size_t EncodeLen() const override {
        return utils::encodeVarIntLen(this->ID()) +
               utils::encodeVarIntLen(this->offset) +
               utils::encodeVarIntLen(this->offset) + this->length;
    }

    uint64_t GetOffset() const { return this->offset; }

    uint64_t GetLength() const { return this->length; }

    std::unique_ptr<uint8_t[]> FetchBuffer() {
        return std::move(this->cryptoData);
    }

    const std::unique_ptr<uint8_t[]>& Buffer() { return this->cryptoData; }

   private:
    uint64_t offset;
    uint64_t length;
    std::unique_ptr<uint8_t[]> cryptoData;
};

class NewTokenFrame : public Frame {
   public:
    NewTokenFrame(std::unique_ptr<uint8_t[]> buf, uint64_t size)
        : tokenLength{size}, token{std::move(buf)} {}

    explicit NewTokenFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->tokenLength = utils::decodeVarInt(stream);
        auto buf = stream.Consume(this->tokenLength);
        this->token = std::make_unique<uint8_t[]>(this->tokenLength);
        std::copy(buf.first, buf.second, this->token.get());
    }

    uint8_t ID() const override { return 0x07; }

    FrameType Type() const override { return FrameType::NEW_TOKEN; }

    const char* Name() const override { return "NEW_TOKEN"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->tokenLength);
        auto buf = stream.Consume(this->tokenLength).first;
        std::copy(token.get(), token.get() + this->tokenLength, buf);
        return 0;
    }

    size_t EncodeLen() const override {
        return utils::encodeVarIntLen(this->ID()) +
               utils::encodeVarIntLen(this->tokenLength) + this->tokenLength;
    }

    uint64_t GetLength() const { return this->tokenLength; }

    std::unique_ptr<uint8_t[]> FetchBuffer() { return std::move(this->token); }

    const std::unique_ptr<uint8_t[]>& Buffer() { return this->token; }

   private:
    uint64_t tokenLength;
    std::unique_ptr<uint8_t[]> token;
};

class StreamFrame : public StreamSpecificFrame {
   public:
    static size_t StreamFrameLen(uint64_t streamID, uint64_t bufLen,
                                 uint64_t offset, bool len) {
        return StreamFrameNonDataLen(streamID, bufLen, offset, len) + bufLen;
    }

    static size_t StreamFrameNonDataLen(uint64_t streamID, uint64_t bufLen,
                                        uint64_t offset, bool len) {
        size_t predictedLen = 1;
        predictedLen += utils::encodeVarIntLen(streamID);
        if (offset != 0) {
            predictedLen += utils::encodeVarIntLen(offset);
        }
        if (len) {
            predictedLen += utils::encodeVarIntLen(bufLen);
        }
        return predictedLen;
    }

    StreamFrame(uint64_t streamID, std::unique_ptr<uint8_t[]> buf,
                size_t bufLen, size_t offset, bool len, bool fin)
        : OFF(offset != 0),
          LEN(len),
          FIN(fin),
          streamID(streamID),
          offset(offset),
          length(bufLen),
          streamData(std::move(buf)) {}

    explicit StreamFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert((ID & 0x08) == 0x08);
        this->OFF = (ID & 0x04) >> 2;
        this->LEN = (ID & 0x02) >> 1;
        this->FIN = (ID & 0x01);
        this->streamID = utils::decodeVarInt(stream);
        if (this->OFF) {
            this->offset = utils::decodeVarInt(stream);
        } else {
            this->offset = 0;
        }
        if (this->LEN) {
            this->length = utils::decodeVarInt(stream);
        } else {
            this->length = stream.GetFree();
        }
        auto buf = stream.Consume(this->length);
        this->streamData = std::make_unique<uint8_t[]>(this->length);
        std::copy(buf.first, buf.second, this->streamData.get());
    }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->streamID);

        if (this->OFF) {
            utils::encodeVarInt(stream, this->offset);
        }
        if (this->LEN) {
            utils::encodeVarInt(stream, this->length);
        }

        auto buf = stream.Consume(this->length).first;
        std::copy(streamData.get(), streamData.get() + this->length, buf);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->streamID);

        if (this->OFF) {
            len += utils::encodeVarIntLen(this->offset);
        }
        if (this->LEN) {
            len += utils::encodeVarIntLen(this->length);
        }
        len += this->length;
        return len;
    }

    std::string Str() const override {
        std::stringstream ss;
        ss << "stream (" << this->offset << ":" << this->offset + this->length
           << ") [" << this->length << "]" << (this->FIN ? " FIN " : "");
        return ss.str();
    }

    uint8_t ID() const override {
        return 0x08 | (this->OFF << 2) | (this->LEN << 1) | (this->FIN);
    }

    FrameType Type() const override { return FrameType::STREAM; }

    const char* Name() const override { return "STREAM"; }

    uint64_t StreamID() const override { return this->streamID; }

    std::unique_ptr<uint8_t[]> FetchBuffer() {
        return std::move(this->streamData);
    }

    uint64_t GetOffset() const { return this->offset; }

    uint64_t GetLength() const { return this->length; }

    bool FINFlag() const { return this->FIN != 0; }

    bool LENFlag() const { return this->LEN != 0; }

    std::unique_ptr<uint8_t[]> FetchStreamData() {
        return std::move(this->streamData);
    }

    uint8_t OFF : 1;
    uint8_t LEN : 1;
    uint8_t FIN : 1;
    uint64_t streamID;
    uint64_t offset;
    uint64_t length;
    std::unique_ptr<uint8_t[]> streamData;
};

class MaxDataFrame : public Frame {
   public:
    explicit MaxDataFrame(uint64_t maximumData) : maximumData{maximumData} {}

    explicit MaxDataFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->maximumData = utils::decodeVarInt(stream);
    }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->maximumData);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->maximumData);
        return len;
    }

    uint8_t ID() const override { return 0x10; }

    FrameType Type() const override { return FrameType::MAX_DATA; }

    const char* Name() const override { return "MAX_DATA"; }

    uint64_t GetMaximumData() const { return this->maximumData; }

   private:
    uint64_t maximumData;
};

class MaxStreamDataFrame : public StreamSpecificFrame {
   public:
    MaxStreamDataFrame(uint64_t streamID, uint64_t maximum)
        : streamID{streamID}, maximumStreamData{maximum} {}

    explicit MaxStreamDataFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->streamID = utils::decodeVarInt(stream);
        this->maximumStreamData = utils::decodeVarInt(stream);
    }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->streamID);
        utils::encodeVarInt(stream, this->maximumStreamData);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->streamID);
        len += utils::encodeVarIntLen(this->maximumStreamData);
        return len;
    }

    uint8_t ID() const override { return 0x11; }

    FrameType Type() const override { return FrameType::MAX_STREAM_DATA; }

    const char* Name() const override { return "MAX_STREAM_DATA"; }

    uint64_t StreamID() const override { return this->streamID; }

    uint64_t GetMaximumStreamData() const { return this->maximumStreamData; }

   private:
    uint64_t streamID;
    uint64_t maximumStreamData;
};

class MaxStreamsFrame : public Frame {
   public:
    MaxStreamsFrame(uint64_t streams, bool unidirectional)
        : unidirectional{unidirectional}, streams{streams} {}
    explicit MaxStreamsFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == 0x12 || ID == 0x13);
        this->unidirectional = ID & 0x1;
        this->streams = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x12 | this->unidirectional; }

    FrameType Type() const override { return FrameType::MAX_STREAMS; }

    const char* Name() const override { return "MAX_STREAMS"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->streams);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->streams);
        return len;
    }

    uint64_t GetStreamsNum() const { return this->streams; }

    bool IsUnidirectional() const { return this->unidirectional == 1; }

   private:
    int8_t unidirectional;
    uint64_t streams;
};

class DataBlockedFrame : public Frame {
   public:
    explicit DataBlockedFrame(uint64_t maximum) : maximumData{maximum} {}

    explicit DataBlockedFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->maximumData = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x14; }

    FrameType Type() const override { return FrameType::DATA_BLOCKED; }

    const char* Name() const override { return "DATA_BLOCKED"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->maximumData);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->maximumData);
        return len;
    }

    uint64_t GetMaximumData() const { return this->maximumData; }

   private:
    uint64_t maximumData;
};

class StreamDataBlockedFrame : public StreamSpecificFrame {
   public:
    StreamDataBlockedFrame(uint64_t streamID, uint64_t maximum)
        : streamID{streamID}, maximumStreamData{maximum} {}

    explicit StreamDataBlockedFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->streamID = utils::decodeVarInt(stream);
        this->maximumStreamData = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x15; }

    FrameType Type() const override { return FrameType::STREAM_DATA_BLOCKED; }

    const char* Name() const override { return "STREAM_DATA_BLOCKED"; }

    uint64_t StreamID() const override { return this->streamID; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->streamID);
        utils::encodeVarInt(stream, this->maximumStreamData);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->streamID);
        len += utils::encodeVarIntLen(this->maximumStreamData);
        return len;
    }

    uint64_t GetMaximumStreamData() const { return this->maximumStreamData; }

   private:
    uint64_t streamID;
    uint64_t maximumStreamData;
};

class StreamsBlockedFrame : public Frame {
   public:
    StreamsBlockedFrame(uint64_t maximumStreams, bool unidirectional)
        : unidirectional{unidirectional}, maximumStreams{maximumStreams} {}

    explicit StreamsBlockedFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == 0x16 || ID == 0x17);
        this->unidirectional = ID & 0x1;
        this->maximumStreams = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x16 & this->unidirectional; };

    FrameType Type() const override { return FrameType::STREAMS_BLOCKED; }

    const char* Name() const override { return "STREAMS_BLOCKED"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->maximumStreams);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->maximumStreams);
        return len;
    }

    uint64_t GetMaximumStreams() const { return this->maximumStreams; }

    bool IsUnidirectional() const { return this->unidirectional == 1; }

   private:
    uint8_t unidirectional : 1;
    uint64_t maximumStreams;
};

class NewConnectionIDFrame : public Frame {
   public:
    NewConnectionIDFrame(uint64_t sequence, uint64_t retirePriorTo,
                         std::array<uint8_t, 16> statelessResetToken)
        : sequenceNumber{sequence},
          retirePriorTo{retirePriorTo},
          statelessResetToken{statelessResetToken} {}

    explicit NewConnectionIDFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->sequenceNumber = utils::decodeVarInt(stream);
        this->retirePriorTo = utils::decodeVarInt(stream);
        this->connectionID = ConnectionID(stream);
        auto buf = stream.Consume(statelessResetToken.size());
        std::copy(buf.first, buf.second, std::begin(statelessResetToken));
    }

    uint8_t ID() const override { return 0x18; }

    FrameType Type() const override { return FrameType::NEW_CONNECTION_ID; }

    const char* Name() const override { return "NEW_CONNECTION_ID"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->sequenceNumber);
        utils::encodeVarInt(stream, this->retirePriorTo);
        this->connectionID.Encode(stream, true);
        auto buf = stream.Consume(statelessResetToken.size());
        std::copy(std::begin(statelessResetToken),
                  std::end(statelessResetToken), buf.first);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->sequenceNumber);
        len += utils::encodeVarIntLen(this->retirePriorTo);
        len += this->connectionID.EncodeLen(true);
        len += statelessResetToken.size();
        return len;
    }

    uint64_t GetSequenceNumber() const { return this->sequenceNumber; }

    uint64_t GetRetirePriorTo() const { return this->retirePriorTo; }

    const ConnectionID& GetConnectionID() const { return this->connectionID; }

    std::array<uint8_t, 16> GetStatelessResetToken() const {
        return this->statelessResetToken;
    }

   private:
    uint64_t sequenceNumber;
    uint64_t retirePriorTo;
    ConnectionID connectionID;

    std::array<uint8_t, 16> statelessResetToken;
};

class RetireConnectionIDFrame : public Frame {
   public:
    explicit RetireConnectionIDFrame(uint64_t sequenceNum)
        : sequenceNumber{sequenceNum} {}

    explicit RetireConnectionIDFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->sequenceNumber = utils::decodeVarInt(stream);
    }

    uint8_t ID() const override { return 0x19; }

    FrameType Type() const override { return FrameType::RETIRE_CONNECTION_ID; }
    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->sequenceNumber);
        return 0;
    }

    const char* Name() const override { return "RETIRE_CONNECTION_ID"; }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->sequenceNumber);
        return len;
    }

    uint64_t GetSequenceNumber() const { return this->sequenceNumber; }

   private:
    uint64_t sequenceNumber;
};

class PathChallengeFrame : public Frame {
   public:
    explicit PathChallengeFrame(uint64_t data) : data{data} {}

    explicit PathChallengeFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->data = utils::decodeUint(stream, sizeof(uint64_t));
    }
    uint8_t ID() const override { return 0x1a; }

    FrameType Type() const override { return FrameType::PATH_CHALLENGE; }

    const char* Name() const override { return "PATH_CHALLENGE"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeUInt(stream, this->data, sizeof(uint64_t));
        return 0;
    }
    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += sizeof(uint64_t);
        return len;
    }

    uint64_t GetData() const { return this->data; }

   private:
    uint64_t data;
};

class PathResponseFrame : public Frame {
   public:
    explicit PathResponseFrame(uint64_t data) : data{data} {}

    explicit PathResponseFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->data = utils::decodeUint(stream, sizeof(uint64_t));
    }

    uint8_t ID() const override { return 0x1b; }

    FrameType Type() const override { return FrameType::PATH_RESPONSE; }

    const char* Name() const override { return "PATH_RESPONSE"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeUInt(stream, this->data, sizeof(uint64_t));
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += sizeof(uint64_t);
        return len;
    }

    uint64_t GetData() const { return this->data; }

   private:
    uint64_t data;
};

class ConnectionCloseQUICFrame : public Frame {
   public:
    ConnectionCloseQUICFrame(uint64_t errorCode, uint64_t frameType,
                             const std::string& reason)
        : errorCode{errorCode}, frameType{frameType} {
        this->reasonPhrase = std::make_unique<uint8_t[]>(reason.size());
        this->reasonPhraseLength = reason.size();
        std::copy(std::cbegin(reason), std::cend(reason),
                  this->reasonPhrase.get());
    }

    explicit ConnectionCloseQUICFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->errorCode = utils::decodeVarInt(stream);
        this->frameType = utils::decodeVarInt(stream);
        this->reasonPhraseLength = utils::decodeVarInt(stream);
        auto buf = stream.Consume(this->reasonPhraseLength);
        this->reasonPhrase =
            std::make_unique<uint8_t[]>(this->reasonPhraseLength);
        std::copy(buf.first, buf.second, this->reasonPhrase.get());
    }

    uint8_t ID() const override { return 0x1c; }

    FrameType Type() const override { return FrameType::CONNECTION_CLOSE; }

    const char* Name() const override { return "CONNECTION_CLOSE"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->errorCode);
        utils::encodeVarInt(stream, this->frameType);
        utils::encodeVarInt(stream, this->reasonPhraseLength);
        auto buf = stream.Consume(this->reasonPhraseLength).first;
        std::copy(reasonPhrase.get(),
                  reasonPhrase.get() + this->reasonPhraseLength, buf);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->errorCode);
        len += utils::encodeVarIntLen(this->frameType);
        len += utils::encodeVarIntLen(this->reasonPhraseLength);
        len += this->reasonPhraseLength;
        return len;
    }

    uint64_t GetErrorCode() const { return this->errorCode; }

    uint64_t GetFrameType() const { return this->frameType; }

    std::string GetReasonPhrase() const {
        return std::string(reasonPhrase.get(),
                           reasonPhrase.get() + reasonPhraseLength);
    }

   private:
    uint64_t errorCode;
    uint64_t frameType;
    uint64_t reasonPhraseLength;
    std::unique_ptr<uint8_t[]> reasonPhrase;
};

class ConnectionCloseAppFrame : public Frame {
   public:
    ConnectionCloseAppFrame(uint64_t errorCode, const std::string& reason)
        : errorCode{errorCode} {
        this->reasonPhrase = std::make_unique<uint8_t[]>(reason.size());
        this->reasonPhraseLength = reason.size();
        std::copy(std::cbegin(reason), std::cend(reason),
                  this->reasonPhrase.get());
    }

    explicit ConnectionCloseAppFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
        this->errorCode = utils::decodeVarInt(stream);
        this->reasonPhraseLength = utils::decodeVarInt(stream);
        auto buf = stream.Consume(this->reasonPhraseLength);
        this->reasonPhrase =
            std::make_unique<uint8_t[]>(this->reasonPhraseLength);
        std::copy(buf.first, buf.second, this->reasonPhrase.get());
    }

    uint8_t ID() const override { return 0x1d; }

    FrameType Type() const override { return FrameType::CONNECTION_CLOSE; }

    const char* Name() const override { return "CONNECTION_CLOSE"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        utils::encodeVarInt(stream, this->errorCode);
        utils::encodeVarInt(stream, this->reasonPhraseLength);
        auto buf = stream.Consume(this->reasonPhraseLength).first;
        std::copy(reasonPhrase.get(),
                  reasonPhrase.get() + this->reasonPhraseLength, buf);
        return 0;
    }

    size_t EncodeLen() const override {
        size_t len = 0;
        len += utils::encodeVarIntLen(this->ID());
        len += utils::encodeVarIntLen(this->errorCode);
        len += utils::encodeVarIntLen(this->reasonPhraseLength);
        len += this->reasonPhraseLength;
        return len;
    }

    uint64_t GetErrorCode() const { return this->errorCode; }

    std::string GetReasonPhrase() const {
        return std::string(reasonPhrase.get(),
                           reasonPhrase.get() + reasonPhraseLength);
    }

   private:
    uint64_t errorCode;
    uint64_t reasonPhraseLength;
    std::unique_ptr<uint8_t[]> reasonPhrase;
};

class HandshakeDoneFrame : public Frame {
   public:
    HandshakeDoneFrame() = default;

    explicit HandshakeDoneFrame(utils::ByteStream& stream) {
        auto ID = utils::decodeVarInt(stream);
        assert(ID == this->ID());
    }
    uint8_t ID() const override { return 0x1e; }

    FrameType Type() const override { return FrameType::HANDSHAKE_DONE; }

    const char* Name() const override { return "HANDSHAKE_DONE"; }

    int Encode(utils::ByteStream& stream) override {
        utils::encodeVarInt(stream, this->ID());
        return 0;
    }
    size_t EncodeLen() const override {
        return utils::encodeVarIntLen(this->ID());
    }
};

}  // namespace thquic::payload
#endif