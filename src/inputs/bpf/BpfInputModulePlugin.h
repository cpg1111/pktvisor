#pragma once

#include "InputModulePlugin.h"
#include "BpfInputStream.h"

namespace vizer::input::bpf {

class BpfInputModulePlugin : public vizer::InputModulePlugin
{
protected:
    void _setup_reoutes(HttpServer &svr) override;
public:
    explicit BpfInputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : vizer::InputModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "BpfInputModulePlugin";
    }
};

}
