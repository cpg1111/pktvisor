#include "BpfConnectProbe.h"

namespace vizer::inputs::bpf {
BpfConnectProbe::BpfConnectProbe(bool count) {
    this->do_count = count;
}

BpfConnectProbe::BpfConnectProbe(bool count, pid_t pid) {
    this->do_count = count;
    this->pid = pid;
}

BpfConnectProbe::BpfConnectProbe(bool count, uid_t uid) {
    this->do_count = count;
    this->uid = uid;
}

BpfConnectProbe::BpfConnectProbe(bool count, std::vec<int32_t> ports) {
    this->do_count = count;
    this->n_ports = ports.size();
    int32_t ports[this->n_ports];
    int idx = 0;
    for (int32_t p : ports) {
        ports[idx] = p;
    }
    this->ports = ports;
}

BpfConnectProbe::BpfConnectProbe(bool count, pid_t pid, uid_t uid, std::vec<int32_t> ports) {
    this->do_count = count;
    this->pid = pid;
    this->uid = uid;
    this->n_ports = ports.size();
    int32_t ports[this->n_ports];
    int idx = 0;
    for (int32_t p : ports) {
        ports[idx] = p;
    }
    this->ports = ports;
}

BpfConnectProbe::~BpfConnectProbe() {
    for (int fd : fds) {
        close(fd);
    }
    tcpconnect_bpf__destroy(_probe);
}

#ifdef __BCC__
void BpfConnectProbe::_start_bcc_count() {
    ebpf::BPF probe;    
}

void BpfConnectProbe::_start_bcc_trace() {

}
#else
void BpfConnectProbe::_start_libbpf_connect() {
    auto probe = tcpconnect_bpf__open();
    if (!probe) {
        throw Exception("tcpconnect probe unable to instantiate")
    }
    probe->rodata->do_count = do_count;
    if (pid) {
        probe->rodata->pid = pid;
    }
    if (uid) {
        probe->rodata->uid = uid;
    }
    if (n_ports > 0) {
        probe->rodata->ports_filter_len = n_ports;
        for (int i = 0; i < n_ports; i++) {
            probe->rdata->ports_filter[i] = htons(ports[i]);
        }
    }

    int ret;
    if (ret = tcpconnect_bpf__load(probe); ret != 0) {
        throw Exception("tcpconnect probe unable to load");
    }
    if (ret = tcpconnect_bpf__attach(probe); ret != 0) {
        throw Exception("tcpconnect probe unable to attach");
    }
    if (do_count) {
        fds = std::make_tuple(bpf_map__fd(probe->maps.ipv4_count),
            bpf_map__fd(probe->maps.ipv6__count));
    } else {
        fds = std::make_tuple(bpf_map__fd(probe->maps.events), 0);
    }
    _probe = probe;
}
#endif
}
