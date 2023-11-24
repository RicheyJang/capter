#include <iostream>
#include <pcap/pcap.h>
#include "args.hxx"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

int main(int argc, char *argv[])
{
    char err_buff[PCAP_ERRBUF_SIZE];

    // Parse args
    args::ArgumentParser parser("Forward traffic from multiple NIC to a single NIC, based on libpcap.");
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
    args::ValueFlagList<std::string> src_NICs(parser, "src", "Source NICs", { 's' });
    args::Flag promisc(parser, "promisc", "use promiscuous mode", {'p', "promisc"});
    args::Positional<std::string> desc(parser, "desc", "Desc NIC");
    try {
        parser.ParseCLI(argc, argv);
    } catch (args::Help&) {
        std::cout << parser;
        return 0;
    } catch (args::Error &e) {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    }

    // Init SPDLog | MAX 5MB * 3 files
    const auto logger = spdlog::rotating_logger_mt("capter", "logs/capter.txt", 1048576 * 5, 3);
    spdlog::set_default_logger(logger);

    // Init PCAP
    if(pcap_init(PCAP_CHAR_ENC_UTF_8, err_buff) == PCAP_ERROR) {
        spdlog::error("pcap_init error: {}", err_buff);
    }

    // TODO main logic
}
