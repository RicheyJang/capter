#ifndef WORKER_H
#define WORKER_H

#include <string>
#include "device.h"
#include "spdlog/spdlog.h"

void work_traffic(const std::string& src, const std::string& desc);

#endif //WORKER_H
