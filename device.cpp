#include "device.h"

// get devices list description
std::string get_dev_desc() {
    std::string dev_tip;
    pcap_if_t *alldevs;
    char err_buff[PCAP_ERRBUF_SIZE];
    // Get all devs
    if(pcap_findalldevs(&alldevs, err_buff) == PCAP_ERROR) {
        dev_tip = "Failed to get device list: ";
        dev_tip.append(err_buff);
    } else {
        dev_tip = "List of optional device: ";
        for(const pcap_if_t *current = alldevs; current != nullptr; current = current->next) {
            if(current != alldevs) {
                dev_tip.append(", ");
            }
            dev_tip.append(current->name);
        }
        pcap_freealldevs(alldevs);
    }
    return dev_tip;
}

// open device with options and filter
pcap_t *open_dev(const std::string& name, std::string filter) {
    bpf_u_int32 mask; /* The netmask of our sniffing device */
    bpf_u_int32 net;  /* The IP of our sniffing device */
    bpf_program fp{}; /* The compiled filter expression */
    int err = 0;
    char err_buff[PCAP_ERRBUF_SIZE];
    // Create
    pcap_t *dev = pcap_create(name.c_str(), err_buff);
    if(dev == nullptr) {
        spdlog::error("initial {} error: {}", name, err_buff);
        return nullptr;
    }

    // TODO set options
    // pcap_set_snaplen(dev, 65535);
    // pcap_set_promisc(dev, 0);
    // pcap_set_timeout(dev, 1000);

    // Activate
    err = pcap_activate(dev); // maybe PERM_DENIED, need root
    if(err != 0) {
        spdlog::error("activate {} error: {}({})", name, pcap_geterr(dev), pcap_statustostr(err));
        pcap_close(dev);
        return nullptr;
    }

    // Filter
    if(!filter.empty()) {
        if (pcap_lookupnet(name.c_str(), &net, &mask, err_buff) == -1) {
            spdlog::warn("can't get netmask for device {}: {}", name, err_buff);
            net = PCAP_NETMASK_UNKNOWN;
        }
        if(pcap_compile(dev, &fp, filter.c_str(), 1, net) == PCAP_ERROR) {
            spdlog::error("compile {} filter \"{}\" error: {}", name, filter, pcap_geterr(dev));
            pcap_close(dev);
            return nullptr;
        }
        if(pcap_setfilter(dev, &fp) != 0) {
            spdlog::error("install {} filter \"{}\" error: {}", name, filter, pcap_geterr(dev));
            pcap_close(dev);
            return nullptr;
        }
    }
    return dev;
}
