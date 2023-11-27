#include "worker.h"

void traffic(u_char *args, const pcap_pkthdr *header, const u_char *packet);

void work_traffic(const std::string& src, const std::string& desc) {
    pcap_t* s_dev = open_dev(src);
    pcap_t* d_dev = open_dev(desc);
    if(s_dev == nullptr || d_dev == nullptr) {
        return;
    }
    pcap_loop(s_dev, -1, traffic, reinterpret_cast<u_char*>(d_dev));
    // TODO pcap_freecode(&fp);
    pcap_close(s_dev);
    pcap_close(d_dev);
}

void traffic(u_char *args, const pcap_pkthdr *header, const u_char *packet) {
    auto* desc = reinterpret_cast<pcap_t*>(args);
    // Send package
    if(pcap_sendpacket(desc, packet, static_cast<int>(header->caplen)) != 0) {
        spdlog::warn("sendpacket error: {}", pcap_geterr(desc));
    }
}
