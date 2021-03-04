#include "BpfConnectHandler.h"

namespace vizer::inputs::bpf {
    BpfConnectHandler::BpfConnectHandler(){}

    BpfConnectHandler::~BpfConnectHandler(){}

#ifndef __BCC__
    void BpfConnectHandler::_start_libbpf_connect(bool do_count, pid_t pid, uid_t uid, int ports, int ports[MAX_PORTS]) {
        struct tcpconnect_bpf *prog = tcpconnect_bpf__open();
        if (!prog) {
            throw Exception("error instantiating bpf connect program");
        }

        prog->rodata->count = do_count;
        prog->rodata->pid = pid;
        prog->rodata->uid = uid;
        prog->rodata->ports_filter_len = n_ports;
        for (int i = 0; i < n_ports; i++) {
            prog->rodata->ports_filter[i] = htons(ports[i]);
        }

        int ret;

        ret = tcpconnect_bpf__load(prog);
        if (ret != 0) {
            throw Exception("error loading tcpconnect bpf program");
        }
        ret = tcpconnect_bpf__attach(prog);
        if (ret != 0) {
            throw Exception("error attaching tcpconnect bpf program");
        }
        if (do_count) {
            this->read_connect_count(prog->maps.ipv4_count, prog->maps.ipv6_count);
        } else {
            this->read_connect_trace(prog->maps.ipv4_connect_events, prog->maps.ipv6_connect_events);
        }
    }
#endif

    BpfConnectHandler::start_count() {
#ifdef __BCC__
#else
        this->_start_libbpf_connect(true);
#endif
    }

    BpfConnectHandler::start_trace() {
#ifdef __BCC__
#else
        this->_start_libbpf_trace(false);
#endif
    }
}
