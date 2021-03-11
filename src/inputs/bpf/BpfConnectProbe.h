#pragma once

#define MAX_PORTS 64 // max filterable ports

namespace vizer::inputs::bpf {
class BpfConnectProbe : BpfProbe {
    private:
        bool do_count;
        pid_t pid;
        uid_t uid;
        int n_ports;
        int32_t ports[];
        std::tuple<int, int> fds;

#ifdef __BCC__
        void _start_bcc_count();
        void _start_bcc_trace();
#else
        void _start_libbpf_connect();
#endif
    public:
        BpfConnectProbe(bool count);
        BpfConnectProbe(bool count, pid_t pid);
        BpfConnectProbe(bool count, uid_t uid);
        BpfConnectProbe(bool count, std::vec<int32_t> ports);
        BpfConnectProbe(bool count, pid_t pid, uid_t uid, std::vec<int32_t> ports);
        ~BpfConnectProbe();
        void start() override;
        std::tuple<int, int> probe_fds() override;
};
}
