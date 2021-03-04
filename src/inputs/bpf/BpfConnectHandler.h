namespace vizer::inputs::bpf {
class BpfConnectHandler {
    private:
#ifndef __BCC__
        void _start_libbpf_connect(bool do_count, pid_t pid, uid_t uid, int n_ports, int ports[MAX_PORTS]);
#endif
    public:
        BpfConnectHandler();
        ~BpfConnectHandler();
        void start_count();
        void start_trace();
        void read_connect_count(int ipv4_map_fd, int ipv6_map_fd);
        void read_connect_trace(int ipv4_map_fd, int ipv6_map_fd);
};
}
