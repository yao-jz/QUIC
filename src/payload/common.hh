#ifndef THQUIC_PAYLOAD_COMMON_HH
#define THQUIC_PAYLOAD_COMMON_HH

#include <cassert>
#include <memory>

#include "utils/bytestream.hh"

namespace thquic::payload {

class Serialization {
   public:
    virtual int Encode(utils::ByteStream& stream) = 0;
    virtual size_t EncodeLen() const = 0;
    virtual std::string Str() const = 0;

   protected:
    void CheckBufferRoom(utils::ByteStream& stream) const {
        stream.CheckFree(this->EncodeLen());
    }
};
}  // namespace thquic::payload
#endif