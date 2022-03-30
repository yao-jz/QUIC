#include "context/common.hh"
#include "context/quic.hh"
#include "utils/log.hh"

using namespace std::chrono_literals;
constexpr size_t BUFFER_SIZE = 8 * 1024 * 1024;
constexpr size_t TEMP_BUFFER_SIZE = 8 * 1024;

class Client {
   public:
    explicit Client(struct sockaddr_in& dstAddr) : client() {
        this->buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE);
        this->temporaryBuffer = std::make_unique<uint8_t[]>(TEMP_BUFFER_SIZE);
        client.CreateConnection(
            dstAddr,
            std::bind(&Client::ConnectionReady, this, std::placeholders::_1));
    }

    int ConnectionReady(uint64_t connection) {
        thquic::utils::logger::warn(
            "[APP] connection {} ready, create a stream.", connection);
        uint64_t stream = client.CreateStream(connection, true);

        client.SetStreamDataReadyCallback(
            connection, stream,
            std::bind(&Client::StreamDataReady, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3,
                      std::placeholders::_4, std::placeholders::_5));

        client.SetConnectionCloseCallback(
            connection,
            []([[maybe_unused]] uint64_t sequence, std::string reason,
               uint64_t errorCode) -> int {
                thquic::utils::logger::warn(
                    "[App] connection close by the peer due to {}, error code: "
                    "{}",
                    reason, errorCode);
                return 0;
            });

        thquic::utils::logger::info("[App] request file digest");
        Send(connection, stream, "GET DIGEST");
        phase = Phase::REQUEST_DIGEST;
        return 0;
    }

    int StreamDataReady(uint64_t sequence, uint64_t stream,
                        std::unique_ptr<uint8_t[]> buf, size_t len, bool FIN) {
        if (FIN) {
            thquic::utils::logger::warn(
                "[APP] peer unexpectedly close the stream");
            thquic::utils::logger::warn("[APP] close the connection");
            client.CloseConnection(sequence, std::string("unexpected close"),
                                   -1);
            return 0;
        }

        switch (phase) {
            case Phase::READY:
                thquic::utils::logger::error("has not issue any request");
                break;
            case Phase::REQUEST_DIGEST:
                std::copy(buf.get(), buf.get() + len,
                          temporaryBuffer.get() + temporaryLength);
                temporaryLength += len;
                if (temporaryLength == sizeof(uint64_t)) {
                    digest =
                        *reinterpret_cast<uint64_t*>(temporaryBuffer.get());
                    thquic::utils::logger::info(
                        "[App] receive digest {:x}, request file", digest);
                    Send(sequence, stream, "GET FILE");
                    phase = Phase::REQUEST_FILE;
                }
                break;
            case Phase::REQUEST_FILE:
                std::copy(buf.get(), buf.get() + len,
                          buffer.get() + bufferLength);
                bufferLength += len;
                if (bufferLength == BUFFER_SIZE) {
                    thquic::utils::logger::info("[App] receive all data");
                    Send(sequence, stream, "DONE");
                    phase = Phase::DONE;
                    if (ValidateDigest()) {
                        thquic::utils::logger::warn(
                            "receive all data successfully");
                    } else {
                        thquic::utils::logger::error("digest validation fail");
                    }
                }
                thquic::utils::logger::info("[App] receive {} bytes from",
                                            bufferLength);
                break;
            case Phase::DONE:
                thquic::utils::logger::error(
                    "may not receive any more data from the server");
                break;
        }

        return 0;
    }

    void Send(uint64_t sequence, uint64_t streamID, const char* str) {
        std::string literal{str};
        auto buf = std::make_unique<uint8_t[]>(literal.length());
        std::copy(literal.begin(), literal.end(), buf.get());
        client.SendData(sequence, streamID, std::move(buf), literal.length());
    }

    bool ValidateDigest() {
        uint64_t recvDigest{0};
        for (uint32_t i = 0; i < BUFFER_SIZE / sizeof(uint64_t); i++) {
            recvDigest ^= reinterpret_cast<uint64_t*>(buffer.get())[i];
        }
        return recvDigest == this->digest;
    }

    void Start() { client.SocketLoop(); }

   private:
    thquic::context::QUICClient client;
    enum class Phase { READY, REQUEST_DIGEST, REQUEST_FILE, DONE };
    Phase phase{Phase::READY};
    std::unique_ptr<uint8_t[]> temporaryBuffer;
    size_t temporaryLength{0};

    std::unique_ptr<uint8_t[]> buffer;
    size_t bufferLength{0};

    uint64_t digest;
};

int main() {
    thquic::utils::initLogger();
    spdlog::warn("start client.");

    struct sockaddr_in addrTo {
        AF_INET, 13556, {inet_addr("127.0.0.1")}, { 0 }
    };

    Client client(addrTo);
    client.Start();

    return 0;
}