#include "BpfInputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace vizer::input::bpf {
BpfInputStream::BpfInputStream(const std::string &name) {
    // TODO
}

#ifndef __BCC__
void BpfInputStream::_start_libbpf_connect(
    bool do_count,
    pid_t pid,
    uid_t uid,
    int n_ports,
    int ports[MAX_PORTS]
) {
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
        obj->rodata->ports_filter_len = n_ports;
        for (int i = 0; i < n_ports; i++) {
            obj->rdata->ports_filter[i] = htons(ports[i]);
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
        this->probe_fds.push_back(bpf_map__fd(obj->maps.ipv4_count));
        this->probe_fds.push_back(bpf_map__fd(obj->maps.ipv6__count));
    } else {
        this->probe_fds.push_back(obj->maps.events);
    }
}
#endif

void BpfInputStream::_start_count_connect() {
    
}

void BpfInputStream::start() {
    if (_running) {
        return;
    }

    _cur_bpf_source = BpfInputStream::DefaultBpfProgram;

    if (config_exists("bpf_program")) {
        auto req_source = config_get<std::string>("bpf_program");
        switch (req_source) {
            case "count_connect":
                _cur_bpf_program = BpfProgram::count_connect;
                break;
            case "trace_connect":
                _cur_bpf_program = BpfProgram::trace_connect;
                break;
            default:
                _cur_bpf_program = BpfProgram::unknown;
                break;
        }
    }
    switch _cur_bpf_program {
        case BpfProgram::unknown:
            throw Exception("unknown bpf program");
        case BpfProgram::count_connect:
            this->count_connect_handler = BpfCountConnectHandler();
            break;
        case BpfProgram::trace_connect:
            this->_start_trace_connect();
            break;
    }
}
}
