#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>
#include "YaraScanner.h"

namespace py = pybind11;

void safe_callback(const Result& res, YaraScanner::ResultCallback py_callback) {
    py::gil_scoped_acquire gil;
    py_callback(res);
}

PYBIND11_MODULE(yarascanner, m) {
    py::class_<Result>(m, "Result")
        .def_readonly("isMalware", &Result::isMalware)
        .def_readonly("date", &Result::date)
        .def_readonly("nameDesktop", &Result::nameDesktop)
        .def_readonly("severity", &Result::severity)
        .def_property_readonly("filename", [](const Result& r) { return py::str(r.filename); })
        .def_property_readonly("filepath", [](const Result& r) { return py::str(r.filepath); })
        .def_property_readonly("desc",     [](const Result& r) { return py::str(r.desc); });

    py::class_<YaraScanner>(m, "YaraScanner")
    .def(py::init<>())
    .def("init", [](YaraScanner& self, py::bytes py_rules, YaraScanner::ResultCallback cb) -> bool {
        std::string path = py_rules.cast<std::string>();
        auto gil_cb = [cb](const Result& res) { safe_callback(res, cb); };
        return self.init(path, gil_cb);
    }, py::arg("rules_path"), py::arg("callback"),
       py::call_guard<py::gil_scoped_release>())
    .def("scan_folder", [](YaraScanner& self, py::bytes py_scan, YaraScanner::ResultCallback cb) {
        std::string path = py_scan.cast<std::string>();
        auto gil_cb = [cb](const Result& res) { safe_callback(res, cb); };
        self.scan_folder(path, gil_cb);
    }, py::arg("scan_path"), py::arg("callback"),
       py::call_guard<py::gil_scoped_release>())
    .def("scan_file", [](YaraScanner& self, py::bytes py_file, YaraScanner::ResultCallback cb) {
        std::string path = py_file.cast<std::string>();
        auto gil_cb = [cb](const Result& res) { safe_callback(res, cb); };
        self.scan_file(path, gil_cb);
    }, py::arg("file_path"), py::arg("callback"),
       py::call_guard<py::gil_scoped_release>())
    .def("shutdown", &YaraScanner::shutdown);

}