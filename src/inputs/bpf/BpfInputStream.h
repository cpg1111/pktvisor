#pragma once

#include "InputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

namespace vizer::input::bpf {
#ifdef __linux__
enum class BpfProgram {
    unknown,
    count_connect,
    trace_connect
};

class BpfInputStream: public vizer::InputStream
{

private:
    static const BpfSource DefaultBpfProgram = BpfProgram::count_connect; // TODO set default source
    BpfSource _cur_bpf_program{BpfProgram::unknown};
#ifndef __BCC__
    void _start_libbpf_connect(bool do_count);
#endif
    void _start_count_connect();
    void _start_trace_connect();

public:
    BpfInputStream(const std::string &name);
    ~BpfInputStream();

    void start() override;
    void stop() override;
    json info_json() const override;
    // TODO consumer_count
    
};
#endif
}
