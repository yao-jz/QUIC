#include "context/common.hh"
#include "context/quic.hh"
#include "utils/log.hh"
#include <iostream>
using namespace std::chrono_literals;

class PingPongClient {
   public:
    explicit PingPongClient(struct sockaddr_in& dstAddr, int maxRepeatNum)
        : client(), maxRepeatNum(maxRepeatNum) {
        client.CreateConnection(
            dstAddr, std::bind(&PingPongClient::ConnectionReady, this,
                               std::placeholders::_1));
    }

    int ConnectionReady(uint64_t connection) {
        thquic::utils::logger::warn(
            "[APP] connection {} ready, create a stream.", connection);
        uint64_t stream = client.CreateStream(connection, true);
        client.SetStreamDataReadyCallback(
            connection, stream,
            std::bind(&PingPongClient::StreamDataReady, this,
                      std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3, std::placeholders::_4,
                      std::placeholders::_5));

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

        std::string literal{"hello, world"};
        auto buf = std::make_unique<uint8_t[]>(literal.length());
        std::copy(literal.begin(), literal.end(), buf.get());
        client.SendData(connection, stream, std::move(buf), literal.length());
        return 0;
    }

    int StreamDataReady(uint64_t sequence, uint64_t stream,
                        std::unique_ptr<uint8_t[]> buf, size_t len, bool FIN) {
        if (FIN) {
            thquic::utils::logger::warn("[APP] peer close the stream as well");
            thquic::utils::logger::warn("[APP] close the connection");
            client.CloseConnection(sequence, std::string("pingpong finish"), 0);
            return 0;
        }

        if (repeatNum < maxRepeatNum) {
            std::string literal(buf.get(), buf.get() + len);
            thquic::utils::logger::warn(
                "[APP] {}: receive {} ({}), bounce back!", repeatNum, literal,
                len);
            client.SendData(sequence, stream, std::move(buf), len);
            repeatNum++;
        } else {
            std::string literal(buf.get(), buf.get() + len);
            thquic::utils::logger::warn("[App] receive {} ({}) {} times, exit.",
                                        literal, len, repeatNum);
            client.CloseStream(sequence, stream);
        }
        return 0;
    }

    void Start() { client.SocketLoop(); }

   private:
    thquic::context::QUICClient client;
    int repeatNum{0};
    int maxRepeatNum;
};

int main() {
    thquic::utils::initLogger();
    spdlog::warn("start client.");

    struct sockaddr_in addrTo {
        AF_INET, 13556, {inet_addr("127.0.0.1")}, { 0 }
    };

    PingPongClient client(addrTo, 10);
    client.Start();

    return 0;
}