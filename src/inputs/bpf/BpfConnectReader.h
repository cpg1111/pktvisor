namespace vizer::inputs::bpf {
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
        uint64_t _src_ip[2];
        uint64_t _dst_ip[2];
        std::string _ip_str(uint64_t[2] ip);
    protected:
        std::string src_ip_str() override;
        std::string dst_ip_str() override;
};


class BpfConnectReader {
    private:
#ifndef __BCC__
        void _start_libbpf_connect(bool do_count, pid_t pid, uid_t uid, int n_ports, int ports[MAX_PORTS]);
#endif
    public:
        BpfConnectReader();
        ~BpfConnectReader();
        void start_count();
        void start_trace();
        void read_connect_count(int ipv4_map_fd, int ipv6_map_fd);
        void read_connect_trace(int ipv4_map_fd, int ipv6_map_fd);
};
}
