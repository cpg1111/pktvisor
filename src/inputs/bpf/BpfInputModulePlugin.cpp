#include "BpfInputModulePlugin.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <Corrade/Utility/FormatStl.h>

CORRADE_PLUGIN_REGISTER(VizerInputBpf, vizer::input::bpf::BpfInputModulePlugin,
    "dev.vizer.module.input/1.0")

namespace vizer::input::bpf {

void BpfInputModulePlugin::_setup_routes(HttpServer &svr)
{
    // CREATE
    srv.Post("/api/v1/inputs/bpf", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto body = json::parse(req.body);
            std::unordered_map<std::string, std::string> schema = {
                {"name", "\\w+"},
                {"probe_type", "[_a-z]+"}};
            // TODO optional settings
            try {
                _check_schema(body, schema, /* TODO optional schema */);
            } catch (const SchemaException &e) {
                res.status = 400;
                result["erro"] = e.what();
                res.set_content(result.dump(), "text/json");
                return;
            }
            if (_input_manager->module_exists(body["name"])) {
                res.status = 400;
                result["error"] = "input name already exists";
                res.set_content(result.dump(), "text/json");
            }
            
            {
                auto input_stream = std::make_unique<BpfInputStream>(body["name"]);
                input_stream->config_set("probe_type", body["probe_type"].get<std::string>());
                // TODO set additional options
                _input_manager->module_add(std::move(input_stream));
            }

            auto [input_stream, stream_mgr_lock] = _input_manager->module_get_locked(body["name"]);
            assert(input_stream);
            result["name"] = body["name"];
            result["config"] = input_stream->config_json();
            result["info"] = input_stream->info_json();
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });

    // DELETE
    srv.Delete("/api/v1/inputs/bpf/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto name = req.matches[1];
            if (!_input_manager->module_exists(name)) {
                res.status = 404;
                result["result"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto [input_stream, stream_mgr_lock] = _input_manager->module_get_locked(name);
            assert(input_stream);
            auto count = input_stream->consumder_count();
            if (count) {
                res.status = 400;
                result["error"] = Corrade::Utilify::formatString("input stream has existing consumers ({}), remove them first", count);
                res.set_content(result.dump(), "text/json");
                return;
            }
            stream_mgr_lock.unlock();
            _input_manager->module_remove(name);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["result"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });

    //GET
    svr.Get("/api/v1/inputs/bpf/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto name = req.matches[1];
            if (!_input_manager->module_exists(name)) {
                res.status = 404;
                result["result"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto [input_stream, stream_mgr_lock] = _input_manager->module_get_locked(name);
            assert(input_stream);
            result["consumers"] = input_stream->consumer_count();
            result["running"] = input_stream->running();
            result["config"] = input_stream->config_json();
            result["info"] = input_stream->info_json();
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["result"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
}

}
