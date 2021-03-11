#pragma once

namespace vizer::inputs::bpf {

struct ipv4_flow_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t dport;
};

struct ipv6_flow_key {
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint16_t dport;
};

class BpfConnectData {
    protected:
        virtual std::string src_ip_str();
        virtual std::string dst_ip_str();
    public:
        uint32_t pid;
        uint32_t uid;
        std::string src_ip()
        {
            return src_ip_str();
        }

        std::string dst_ip()
        {
            return dst_ip_str();
        }
};

class BpfConnectDataV4 : BpfConnectData {
    private:
        uint32_t _src_ip;
        uint32_t _dst_ip;
        std::string _ip_str(uint32_t ip);
    protected:
        std::string src_ip_str() override;
        std::string dst_ip_str() override;
};

class BpfConnectDataV6 : BpfConnectData {
    private:
        uint8_t _src_ip[16];
        uint8_t _dst_ip[16];
        std::string _ip_str(uint64_t[8] ip);
    protected:
        std::string src_ip_str() override;
        std::string dst_ip_str() override;
};


class BpfConnectReader {
    public:
        BpfConnectReader();
        ~BpfConnectReader();
        void read_connect_count(int ipv4_map_fd, int ipv6_map_fd);
        void read_connect_trace(int fd);
};
}
