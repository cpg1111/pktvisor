#pragma once

#include "InputStream.h"
//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <sigslot/signal.>

namespace vizer::input::bpf {
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

    std::vec<std::string> enabled_probes;
    std::vec<int> probe_fds;
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
    size_t consumer_count()
    {
        return enabled_probes.size();
    }

    mutable sigslot::signal<const BpfConnectData &> tcp_connect_signal;
};

class BpfProbe {
    private:
        std::tuple<int, int> fds;
    public:
        virtual void start();
        std::tuple<int, int> probe_fds(){
            return fds;
        };
};
}
