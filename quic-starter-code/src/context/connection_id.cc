#include "connection_id.hh"

namespace thquic {

ConnectionID ConnectionIDGenerator::Generate() {
    if (this->connectionIDLen == 0) {
        return ConnectionID{IDType(), this->connectionIDLen};
    }

    for (uint32_t i = 0; i < MAX_REGENERATION; i++) {
        IDType IDLiteral{};
        utils::RandomByteGenerator::Get().Fill(std::begin(IDLiteral),
                                               this->connectionIDLen);
        ConnectionID ID(IDLiteral, this->connectionIDLen);
        auto insertResult = this->usedID.insert(ID);
        if (insertResult.second) {
            return ID;
        }
    }
    throw std::runtime_error("connection id exhausted");
}

ConnectionIDGenerator& ConnectionIDGenerator::Get() {
    static ConnectionIDGenerator generator(config::LOCAL_CONNECTION_ID_LENGTH);
    return generator;
}

ConnectionIDGenerator::ConnectionIDGenerator(size_t localConnectionIDLen)
    : connectionIDLen(localConnectionIDLen) {}

ConnectionID::ConnectionID() : id{0}, valid{0}, len{0} {}

ConnectionID::ConnectionID(IDType id, size_t len)
    : id(id), valid(1), len(len) {}

ConnectionID::ConnectionID(utils::ByteStream& stream) : id{0}, valid{1} {
    this->len = utils::decodeUint(stream, sizeof(uint8_t));
    assert(this->len <= 20);
    auto buf = stream.Consume(this->len);
    std::copy(buf.first, buf.second, std::begin(this->id));
}

ConnectionID::ConnectionID(utils::ByteStream& stream, uint8_t connectionIDLen)
    : id{0}, valid{1}, len{connectionIDLen} {
    assert(this->len <= 20);
    auto buf = stream.Consume(this->len);
    std::copy(buf.first, buf.second, std::begin(this->id));
}

bool ConnectionID::operator==(const ConnectionID& other) const {
    return this->len == other.len && id == other.id;
}

bool ConnectionID::operator<(const ConnectionID& other) const {
    return (this->len < other.len) ||
           ((this->len == other.len) && (this->id < other.id));
}

int ConnectionID::Encode(utils::ByteStream& stream, bool withIDLen) {
    stream.CheckFree(this->EncodeLen(withIDLen));
    if (withIDLen) {
        utils::encodeUInt(stream, this->len, sizeof(uint8_t));
    }
    auto buf = stream.Consume(this->len).first;
    std::copy(std::cbegin(this->id), std::cbegin(this->id) + this->IDLen(),
              buf);
    return 0;
}

uint8_t ConnectionID::EncodeLen(bool withIDLen) const {
    return this->len + (withIDLen ? 1 : 0);
}

const IDType& ConnectionID::ID() const { return this->id; }

uint8_t ConnectionID::IDLen() const { return this->len; }

bool ConnectionID::Valid() const { return this->valid == 1; }

std::string ConnectionID::ToString() const {
    char ConnectionID[config::CONNECTION_ID_MAX_SIZE + 1];
    std::copy(std::cbegin(id), std::cbegin(id) + len, ConnectionID);
    ConnectionID[len] = '\0';
    return std::string(ConnectionID);
}

}  // namespace thquic