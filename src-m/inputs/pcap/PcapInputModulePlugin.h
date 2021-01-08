#ifndef PKTVISORD_PCAPINPUTMODULEPLUGIN_H
#define PKTVISORD_PCAPINPUTMODULEPLUGIN_H

#include "InputModulePlugin.h"

namespace pktvisor {
namespace input {

class PcapInputModulePlugin : public pktvisor::InputModulePlugin
{
protected:
    void _setup_routes(httplib::Server &svr) override;

public:
    explicit PcapInputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : pktvisor::InputModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "PcapInputModulePlugin";
    }

    // CRUD interface
    // TODO move to base class, virtual?
    const pktvisor::InputStream *op_create(const std::string &name, const std::string &iface);
    void op_delete(const std::string &name);
};

}
}

#endif //PKTVISORD_PCAPINPUTMODULEPLUGIN_H