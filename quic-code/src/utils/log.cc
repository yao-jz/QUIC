#include "utils/log.hh"

namespace thquic::utils {

int initLogger() {
    logger::set_pattern("[%H:%M:%S %z] %^[%l]%$ %v");
    return 0;
}

std::string formatNetworkAddress(const struct sockaddr_in& addr) {
    char ipAddress[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ipAddress, sizeof(ipAddress));
    return std::string(ipAddress) + ":" + std::to_string(addr.sin_port);
}

std::string formatTimepoint(timepoint time) {
    if (time == utils::timepoint::min()) {
        return std::string{"immediately"};
    }
    auto system_time =
        std::chrono::system_clock::now() + (time - utils::clock::now());
    const std::time_t epoch = std::chrono::system_clock::to_time_t(system_time);
    std::tm tm = *std::localtime(&epoch);

    std::stringstream ss;
    ss << std::put_time(&tm, "%FT%T");

    auto truncated = std::chrono::system_clock::from_time_t(epoch);
    auto delta_us = std::chrono::duration_cast<std::chrono::microseconds>(
                        system_time - truncated)
                        .count();
    ss << "." << std::fixed << std::setw(6) << std::setfill('0') << delta_us;
    return ss.str();
}

std::string formatTimeDuration(duration d) {
    auto second = std::chrono::duration_cast<std::chrono::seconds>(d);
    auto millsecond =
        std::chrono::duration_cast<std::chrono::milliseconds>(d - second);
    auto microsecond = std::chrono::duration_cast<std::chrono::microseconds>(
        d - second - millsecond);
    std::stringstream ss;
    ss << second.count() << "." << millsecond.count() << microsecond.count()
       << "s";
    return ss.str();
}

}  // namespace thquic::utils
