#include "BpfConnectHandler.h"

namespace vizer::inputs::bpf {
std::string BpfConnectDataV4::_ip_str(uint32_t ip) {
    uint8_t[4] octets;
    for (int i = 0; i < 4; i++) {
        octets.append(ip >> (i*8));
    }
    return Corrade::Utilify::formatString("{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]);
}

std::string BpfConnectDataV6::_ip_str(const uint64_t[2] ip) {
    // TODO
}

BpfConnectReader::BpfConnectReader(){}

BpfConnectReader::~BpfConnectReader(){}

BpfConnectReader::_read_connect_count4(int map_fd) {
    static struct ipv4_flow_key[MAX_MAP_ENTRIES];
    size_t value_size = sizeof(uint64_t);
    size_t key_size = sizeof(keys[0]);
    static struct ipv4_flow_key zero;
    static uint64_t counts[MAX_MAP_ENTRIES];
}

BpfConnectData BpfConnectReader::read_connect_count(int ipv4_map_fd, int ipv6_map_fd) {
    
}
}
