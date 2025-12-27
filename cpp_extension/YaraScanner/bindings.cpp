#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>
#include "YaraScanner.h"
#include <iostream>

namespace py = pybind11;

static void safe_invoke_py_callback(const Result& res, const py::function &py_cb) {
    py::gil_scoped_acquire gil;
    try {
        py::dict d;
        d["isMalware"] = res.isMalware;
        d["date"] = res.date;
        d["nameDesktop"] = res.nameDesktop;
        d["severity"] = res.severity;
        d["filename"] = res.filename;
        d["filepath"] = res.filepath;
        d["desc"] = res.desc;
        d["hash"] = res.hash;
        d["hash_type"] = res.hash_type;
        // Newly-exposed explicit digest fields
        d["md5"] = res.md5;
        d["sha1"] = res.sha1;
        d["sha256"] = res.sha256;
        d["detection_source"] = res.detection_source;
        d["malware_name"] = res.malware_name;
        d["matched_rules_count"] = res.matched_rules_count;
        d["matched_rules"] = res.matched_rules;

        py::module types = py::module::import("types");
        py::object ns = types.attr("SimpleNamespace")();

        // Assign attributes from the dict to the namespace
        ns.attr("isMalware") = d["isMalware"];
        ns.attr("date") = d["date"];
        ns.attr("nameDesktop") = d["nameDesktop"];
        ns.attr("severity") = d["severity"];
        ns.attr("filename") = d["filename"];
        ns.attr("filepath") = d["filepath"];
        ns.attr("desc") = d["desc"];
        ns.attr("hash") = d["hash"];
        ns.attr("hash_type") = d["hash_type"];
        // Attach explicit digest attributes to the namespace
        ns.attr("md5") = d["md5"];
        ns.attr("sha1") = d["sha1"];
        ns.attr("sha256") = d["sha256"];
        ns.attr("detection_source") = d["detection_source"];
        ns.attr("malware_name") = d["malware_name"];
        ns.attr("matched_rules_count") = d["matched_rules_count"];
        ns.attr("matched_rules") = d["matched_rules"];

        py::object to_dict_fn = py::cpp_function([d]() -> py::dict {
            return d;
        });

        ns.attr("to_dict") = to_dict_fn;

        py_cb(ns);
    } catch (py::error_already_set &e) {
        std::cerr << "Python callback raised: " << e.what() << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Exception in Python callback: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception in Python callback" << std::endl;
    }
}

// Helper to convert a Python callable (or None) to a C++ ResultCallback
static YaraScanner::ResultCallback make_cpp_callback(py::object maybe_callable) {
    if (maybe_callable.is_none()) {
        // return no-op
        return YaraScanner::ResultCallback();
    }
    py::function py_cb = maybe_callable.cast<py::function>();
    // Keep py_cb alive by copying into lambda capture
    return [py_cb](const Result& res) {
        safe_invoke_py_callback(res, py_cb);
    };
}

PYBIND11_MODULE(yarascanner, m) {
    m.doc() = "YARA-based scanner module with hash DB checks and realtime monitoring";

    // Bind the Result struct
    py::class_<Result>(m, "Result")
        .def(py::init<>())
        .def_readwrite("isMalware", &Result::isMalware)
        .def_readwrite("date", &Result::date)
        .def_readwrite("nameDesktop", &Result::nameDesktop)
        .def_readwrite("severity", &Result::severity)
        .def_readwrite("filename", &Result::filename)
        .def_readwrite("filepath", &Result::filepath)
        .def_readwrite("desc", &Result::desc)
        .def_readwrite("hash", &Result::hash)
        .def_readwrite("hash_type", &Result::hash_type)
        // Newly-exposed explicit digest fields
        .def_readwrite("md5", &Result::md5)
        .def_readwrite("sha1", &Result::sha1)
        .def_readwrite("sha256", &Result::sha256)
        .def_readwrite("detection_source", &Result::detection_source)
        .def_readwrite("malware_name", &Result::malware_name)
        // Expose aggregation fields for YARA matches
        .def_readwrite("matched_rules_count", &Result::matched_rules_count)
        .def_readwrite("matched_rules", &Result::matched_rules)
        .def("to_dict", [](const Result &r) {
            py::dict d;
            d["isMalware"] = r.isMalware;
            d["date"] = r.date;
            d["nameDesktop"] = r.nameDesktop;
            d["severity"] = r.severity;
            d["filename"] = r.filename;
            d["filepath"] = r.filepath;
            d["desc"] = r.desc;
            d["hash"] = r.hash;
            d["hash_type"] = r.hash_type;
            // Include explicit digest fields in the to_dict representation
            d["md5"] = r.md5;
            d["sha1"] = r.sha1;
            d["sha256"] = r.sha256;
            d["detection_source"] = r.detection_source;
            d["malware_name"] = r.malware_name;
            d["matched_rules_count"] = r.matched_rules_count;
            d["matched_rules"] = r.matched_rules;
            return d;
        })
        .def("__repr__", [](const Result &r) {
            std::ostringstream oss;
            oss << "<Result isMalware=" << (r.isMalware ? "True" : "False")
                << " file=\"" << r.filename << "\" desc=\"" << r.desc << "\">";
            return oss.str();
        });

    // Bind YaraScanner class
    py::class_<YaraScanner>(m, "YaraScanner")
        .def(py::init<>())

        // init may produce status notifications via callback. Accept None.
        .def("init",
            [](YaraScanner &self, const std::string &rules_path, const std::string &db_path, py::object status_cb) {
                auto cb = make_cpp_callback(status_cb);
                // Release GIL since init may be blocking (loading rules, opening DB)
                py::gil_scoped_release release;
                return self.init(rules_path, db_path, cb);
            },
            py::arg("rules_path"), py::arg("db_path"), py::arg("status_callback") = py::none())

        // scan_file: run a synchronous scan on a single file; callback will be called for detections.
        .def("scan_file",
            [](YaraScanner &self, const std::string &file_path, py::object py_cb) {
                auto cb = make_cpp_callback(py_cb);
                py::gil_scoped_release release;
                self.scan_file(file_path, cb);
            },
            py::arg("file_path"), py::arg("callback"))

        // scan_folder: recursively scan folder
        .def("scan_folder",
            [](YaraScanner &self, const std::string &scan_path, py::object py_cb) {
                auto cb = make_cpp_callback(py_cb);
                py::gil_scoped_release release;
                self.scan_folder(scan_path, cb);
            },
            py::arg("scan_path"), py::arg("callback"))

        // start_realtime: start background monitor. Release GIL so thread can run.
        .def("start_realtime",
            [](YaraScanner &self, const std::string &watch_path, py::object py_cb) {
                auto cb = make_cpp_callback(py_cb);
                // start_realtime will spawn a thread; release GIL to avoid blocking Python
                py::gil_scoped_release release;
                return self.start_realtime(watch_path, cb);
            },
            py::arg("watch_path"), py::arg("callback"))

        .def("stop_realtime",
            [](YaraScanner &self) {
                // stopping is fast; keep GIL to avoid races with Python finalization
                py::gil_scoped_acquire acquire;
                self.stop_realtime();
            })

        .def("shutdown",
            [](YaraScanner &self) {
                // shutdown may block briefly; keep GIL to avoid races with Python finalization
                py::gil_scoped_acquire acquire;
                self.shutdown();
            })

        // Progress helpers — expose a simple `get_progress` (returns 0..100) and `reset_progress`.
        // These are thin, safe wrappers around the native scanner methods used by the Python model/UI.
        .def("get_progress",
            [](YaraScanner &self) -> int {
                try {
                    int p = self.get_progress_percent();
                    if (p < 0) return 0;
                    if (p > 100) return 100;
                    return p;
                } catch (...) {
                    return 0;
                }
            })
        .def("reset_progress",
            [](YaraScanner &self) {
                try {
                    self.reset_progress();
                } catch (...) {
                    // swallow any errors - progress is an optional UI helper
                }
            })

        // Throttle configuration bindings: allow Python to adjust lightweight
        // time-slicing throttle applied between files in scan_folder.
        .def("set_throttle_duty",
            [](YaraScanner &self, double duty) {
                try {
                    self.set_throttle_duty(duty);
                } catch (...) {
                    // ignore errors - best-effort
                }
            },
            py::arg("duty"))
        .def("set_throttle_max_sleep_ms",
            [](YaraScanner &self, int max_sleep_ms) {
                try {
                    self.set_throttle_max_sleep_ms(max_sleep_ms);
                } catch (...) {
                    // ignore errors
                }
            },
            py::arg("max_sleep_ms"))
        .def("get_throttle_settings",
            [](YaraScanner &self) {
                try {
                    double duty = 0.0;
                    int max_ms = 0;
                    self.get_throttle_settings(duty, max_ms);
                    return py::make_tuple(duty, max_ms);
                } catch (...) {
                    return py::make_tuple(0.0, 0);
                }
            })

        // Full-scan control: allow Python to request bypassing signature/size policies.
        // These are best-effort bindings; if the underlying native scanner/binding
        // does not support the toggle it will be ignored.
        .def("set_full_scan", [](YaraScanner &self, bool enabled) {
            try { self.set_full_scan(enabled); } catch (...) { }
        }, py::arg("enabled"))
        .def("is_full_scan", [](YaraScanner &self) {
            try { return self.is_full_scan(); } catch (...) { return false; }
        })

        // Provide a convenience context manager support in Python:
        .def("__enter__", [](YaraScanner &self) -> YaraScanner& { return self; })
        .def("__exit__", [](YaraScanner &self, py::object, py::object, py::object) {
            // Ensure resources cleaned up
            py::gil_scoped_acquire acquire;
            self.shutdown();
        })
        ;

    m.def("create_scanner", []() {
        return std::make_unique<YaraScanner>();
    });
}
