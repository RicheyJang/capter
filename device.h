//
// Created by Administrator on 2023/11/26.
//

#ifndef DEVICE_H
#define DEVICE_H

#include <string>
#include <pcap/pcap.h>
#include "spdlog/spdlog.h"

#define DEFAULT_SNAP_LEN 65535
#define DEFAULT_BUFF_TIMEOUT 1000

typedef struct {
    bool promisc;
    bool monitor;
    int  snaplen;
    int  timeout; // packet buffer timeout(ms), a negative value means immediate mode is used
    int  bufflen;
} dev_options;

std::string get_dev_desc(); // get devices list description
pcap_t *open_dev(const std::string& name, dev_options options = {}, std::string filter = "", bpf_program* fpvp = nullptr); // open device

#endif //DEVICE_H
