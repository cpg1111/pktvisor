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
