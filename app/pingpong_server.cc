#include <functional>
#include <map>

#include "context/common.hh"
#include "context/quic.hh"
#include "utils/log.hh"

using namespace std::chrono_literals;

class PingPongServer {
   public:
    explicit PingPongServer(uint16_t localPort, std::string localAddress = "")
        : server(localPort, localAddress) {
        server.SetConnectionReadyCallback(std::bind(
            &PingPongServer::ConnectionReady, this, std::placeholders::_1));
    }

    int ConnectionReady(uint64_t sequence) {
        thquic::utils::logger::warn("[App] new connection {} established",
                                    sequence);
        server.SetStreamReadyCallback(
            sequence, std::bind(&PingPongServer::StreamReady, this,
                                std::placeholders::_1, std::placeholders::_2));

        server.SetConnectionCloseCallback(
            sequence,
            []([[maybe_unused]] uint64_t sequence, std::string reason,
               uint64_t errorCode) -> int {
                thquic::utils::logger::warn(
                    "[App] connection close by the peer due to {}, error code: "
                    "{}",
                    reason, errorCode);
                return 0;
            });

        return 0;
    }

    int StreamReady(uint64_t sequence, uint64_t streamID) {
        thquic::utils::logger::warn(
            "[App] stream {} in connection {} established", streamID, sequence);

        pingPongMap.emplace(std::piecewise_construct,
                            std::forward_as_tuple(sequence, streamID),
                            std::forward_as_tuple(streamID));

        server.SetStreamDataReadyCallback(
            sequence, streamID,
            std::bind(&PingPongServer::StreamDataReady, this,
                      std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4,
                      std::placeholders::_5));

        return 0;
    }

    int StreamDataReady(uint64_t sequence, uint64_t stream,
                        std::unique_ptr<uint8_t[]> buf, size_t len, bool fin) {
        try {
            uint64_t pongStream =
                pingPongMap.at(std::make_pair(sequence, stream));

            if (len != 0 && !fin) {
                std::string literal(buf.get(), buf.get() + len);
                thquic::utils::logger::warn(
                    "[App] receive {} ({}), bounce back!", literal, len);
                server.SendData(sequence, pongStream, std::move(buf), len);
            }

            if (fin) {
                thquic::utils::logger::warn(
                    "[App] close connection {} stream {} as the peer close it",
                    sequence, stream);
                server.CloseStream(sequence, pongStream);
            }

        } catch (std::out_of_range& ex) {
            thquic::utils::logger::error(
                "there should be something error, as callback is not "
                "registered");
        }
        return 0;
    }

    void Start() { server.SocketLoop(); }

   private:
    thquic::context::QUICServer server;
    std::map<std::pair<uint64_t, uint64_t>, uint64_t> pingPongMap;
};

int main() {
    thquic::utils::initLogger();
    spdlog::warn("start server.");

    PingPongServer server(13556, "127.0.0.1");
    server.Start();
    return 0;
}