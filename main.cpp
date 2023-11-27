#include <iostream>
#include <vector>
#include <thread>
#include "device.h"
#include "worker.h"
#include "args.hxx"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"

int main(int argc, char *argv[])
{
    std::vector<std::thread> workers;
    char err_buff[PCAP_ERRBUF_SIZE];

    // Parse args
    args::ArgumentParser parser("Forward traffic from multiple NIC to a single NIC, based on libpcap.", get_dev_desc());
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
    args::ValueFlagList<std::string> src_NICs(parser, "src", "Source NICs, required", { 's' });
    args::Positional<std::string> desc(parser, "desc", "Desc NIC", args::Options::Required);
    args::Group options(parser, "device options:", args::Group::Validators::DontCare, args::Options::Global);
    args::ValueFlag<std::string> filter_str(options, "filter", "Filter string", { 'f' });
    args::Flag promisc(options, "promisc", "Use promiscuous mode", {'p', "promisc"});
    try {
        parser.ParseCLI(argc, argv);
    } catch (args::Help&) {
        std::cout << parser;
        return 0;
    } catch (args::Error &e) {
        std::cerr << e.what() << std::endl;
        std::cout << parser;
        return 1;
    }
    if(src_NICs->empty()) {
        std::cout << parser;
        return 0;
    }

    // Init SPDLog | MAX 5MB * 3 files
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/capter.log", 1048576 * 5, 3);
    spdlog::logger logger("multi_sink", {console_sink, file_sink});
    spdlog::set_default_logger(std::make_shared<spdlog::logger>(logger));

    // Init PCAP
    if(pcap_init(PCAP_CHAR_ENC_UTF_8, err_buff) == PCAP_ERROR) {
        spdlog::error("init libpcap error: {}", err_buff);
        return 0;
    }

    // TODO singal INT to quit

    // Worker threads
    for(const std::string& src : src_NICs) {
        workers.emplace_back(work_traffic, src, desc.Get());
    }
    std::for_each(workers.begin(), workers.end(),
        std::mem_fn(&std::thread::join));
}
