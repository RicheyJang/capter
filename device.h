//
// Created by Administrator on 2023/11/26.
//

#ifndef DEVICE_H
#define DEVICE_H

#include <string>
#include <pcap/pcap.h>
#include "spdlog/spdlog.h"

std::string get_dev_desc(); // get devices list description
pcap_t *open_dev(const std::string& name, std::string filter = ""); // open device

#endif //DEVICE_H
