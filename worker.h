#ifndef WORKER_H
#define WORKER_H

#include <string>
#include "device.h"
#include "spdlog/spdlog.h"

void work_traffic(const std::string& src, const std::string& desc, dev_options src_options, const std::string& src_filter);

#endif //WORKER_H
