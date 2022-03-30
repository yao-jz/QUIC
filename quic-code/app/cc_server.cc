#include <functional>
#include <map>
#include <memory>

#include "context/common.hh"
#include "context/quic.hh"
#include "utils/log.hh"
#include "utils/random.hh"

using namespace std::chrono_literals;
constexpr size_t BUFFER_SIZE = 8 * 1024 * 1024;
constexpr size_t TEMP_BUFFER_SIZE = 8 * 1024;
class Server {
   public:
    explicit Server(uint16_t localPort, std::string localAddress = "")
        : server(localPort, localAddress) {
        this->buffer = std::make_unique<uint8_t[]>(BUFFER_SIZE);
        this->temporaryBuffer = std::make_unique<uint8_t[]>(TEMP_BUFFER_SIZE);

        thquic::utils::RandomByteGenerator::Get().Fill(this->buffer.get(),
                                                       BUFFER_SIZE);

        for (uint32_t i = 0; i < BUFFER_SIZE / sizeof(uint64_t); i++) {
            this->digest ^= reinterpret_cast<uint64_t*>(buffer.get())[i];
        }

        server.SetConnectionReadyCallback(
            std::bind(&Server::ConnectionReady, this, std::placeholders::_1));
    }

    int ConnectionReady(uint64_t sequence) {
        thquic::utils::logger::warn("[App] new connection {} established",
                                    sequence);

        this->connectionPhase.emplace(sequence, Phase::READY);
        server.SetStreamReadyCallback(
            sequence, std::bind(&Server::StreamReady, this,
                                std::placeholders::_1, std::placeholders::_2));

        server.SetConnectionCloseCallback(
            sequence,
            [this]([[maybe_unused]] uint64_t sequence, std::string reason,
                   uint64_t errorCode) -> int {
                this->connectionPhase.erase(sequence);
                this->connectionStreamMap.erase(sequence);
                thquic::utils::logger::warn(
                    "[App] connection close by the peer due to {}, error code: "
                    "{}",
                    reason, errorCode);
                return 0;
            });

        return 0;
    }

    // TODO: check that data trigger streamReadyCallback can be handled by
    // streamDataReadyCallback
    int StreamReady(uint64_t sequence, uint64_t streamID) {
        thquic::utils::logger::warn(
            "[App] stream {} in connection {} established", streamID, sequence);

        connectionStreamMap.emplace(sequence, streamID);

        server.SetStreamDataReadyCallback(
            sequence, streamID,
            std::bind(&Server::StreamDataReady, this, std::placeholders::_1,
                      std::placeholders::_2, std::placeholders::_3,
                      std::placeholders::_4, std::placeholders::_5));

        return 0;
    }

    int StreamDataReady(uint64_t sequence, uint64_t stream,
                        std::unique_ptr<uint8_t[]> buf, size_t len, bool fin) {
        try {
            if (len != 0 && !fin) {
                std::copy(buf.get(), buf.get() + len,
                          temporaryBuffer.get() + temporaryBufferLen);
                temporaryBufferLen += len;

                switch (connectionPhase.at(sequence)) {
                    case Phase::READY:
                        if (UntilReceive("GET DIGEST")) {
                            connectionPhase.at(sequence) = Phase::REQUEST_RECV;
                            temporaryBufferLen = 0;
                            [[fallthrough]];
                        } else {
                            break;
                        }
                    case Phase::REQUEST_RECV: {
                        thquic::utils::logger::info("[App] send digest {:x}",
                                                    digest);
                        auto buf =
                            std::make_unique<uint8_t[]>(sizeof(uint64_t));
                        *reinterpret_cast<uint64_t*>(buf.get()) = digest;
                        server.SendData(sequence,
                                        connectionStreamMap.at(sequence),
                                        std::move(buf), sizeof(uint64_t));
                        connectionPhase.at(sequence) = Phase::DIGEST_SENT;
                        break;
                    }
                    case Phase::DIGEST_SENT: {
                        if (UntilReceive("GET FILE")) {
                            temporaryBufferLen = 0;
                            auto buf = std::make_unique<uint8_t[]>(BUFFER_SIZE);
                            std::copy(buffer.get(), buffer.get() + BUFFER_SIZE,
                                      buf.get());
                            server.SendData(sequence,
                                            connectionStreamMap.at(sequence),
                                            std::move(buf), BUFFER_SIZE);
                            connectionPhase.at(sequence) = Phase::FILE_SENT;
                        }
                        break;
                    }
                    case Phase::FILE_SENT:
                        if (UntilReceive("DONE")) {
                            temporaryBufferLen = 0;
                            connectionPhase.at(sequence) = Phase::DONE;
                            [[fallthrough]];
                        } else {
                            break;
                        }
                    case Phase::DONE:
                        server.CloseConnection(sequence,
                                               std::string("transfer done"), 0);
                }
            }

            if (fin) {
                thquic::utils::logger::warn(
                    "[App] close connection {} stream {} as the peer close it",
                    sequence, stream);
                server.CloseStream(sequence, stream);
            }

        } catch (std::out_of_range& ex) {
            thquic::utils::logger::error(
                "there should be something error, as callback is not "
                "registered");
        }
        return 0;
    }

    bool UntilReceive(const char* str) {
        std::string received(temporaryBuffer.get(),
                             temporaryBuffer.get() + temporaryBufferLen);
        if (received == std::string(str)) {
            temporaryBufferLen = 0;
            return true;
        } else {
            if (std::string(str).rfind(received, 0) != 0) {
                thquic::utils::logger::error("[APP] receive {}", received);
                temporaryBufferLen = 0;
                exit(-1);
            }
            return false;
        }
    }

    void Start() { server.SocketLoop(); }

   private:
    std::unique_ptr<uint8_t[]> buffer;
    uint64_t digest{0};

    thquic::context::QUICServer server;

    enum class Phase { READY, REQUEST_RECV, DIGEST_SENT, FILE_SENT, DONE };

    std::unique_ptr<uint8_t[]> temporaryBuffer;
    size_t temporaryBufferLen{0};

    std::map<uint64_t, Phase> connectionPhase;
    std::map<uint64_t, uint64_t> connectionStreamMap;
};

int main() {
    thquic::utils::initLogger();
    spdlog::warn("start server.");

    Server server(13556, "127.0.0.1");
    server.Start();
    return 0;
}