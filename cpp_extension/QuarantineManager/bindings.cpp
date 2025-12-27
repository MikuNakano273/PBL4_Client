#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "QuarantineManager.h"

namespace py = pybind11;

PYBIND11_MODULE(quarantinemanager, m) {
    m.doc() = "Quarantine manager native extension for PBL4 (quarantinemanager)";

    // Bind the QuarantineManager C++ class to Python
    py::class_<pbl4::av::QuarantineManager>(m, "QuarantineManager")
        // Expose constructor taking the path to the DB (quarantine folder uses default unless provided)
        .def(py::init<const std::string&>(),
             py::arg("db_path"),
             "Create a QuarantineManager with the given sqlite DB path.")
        // Quarantine a file: release GIL while performing IO/DB work
        .def("quarantine",
             [](pbl4::av::QuarantineManager &self, const std::string &file_path) {
                 py::gil_scoped_release release;
                 return self.quarantine(file_path);
             },
             py::arg("file_path"),
             "Quarantine the given file. Returns a human-readable status string.")
        // Whitelist a file (compute hash and insert into DB)
        .def("whitelist",
             [](pbl4::av::QuarantineManager &self, const std::string &file_path) {
                 py::gil_scoped_release release;
                 return self.whitelist(file_path);
             },
             py::arg("file_path"),
             "Compute hash (sha256) of the file and add it to the whitelist. Returns a status string.")
        // Restore a quarantined file (provide stored filename or stored path)
        .def("restore",
             [](pbl4::av::QuarantineManager &self, const std::string &stored_name_or_path) {
                 py::gil_scoped_release release;
                 return self.restore(stored_name_or_path);
             },
             py::arg("stored_name_or_path"),
             "Restore the quarantined file back to its original location and add hash to whitelist. "
             "Argument may be the stored filename or the full path inside the quarantine folder.")
        // Shutdown/cleanup
        .def("shutdown",
             [](pbl4::av::QuarantineManager &self) {
                 // shutdown is quick but may touch resources; release GIL for consistency
                 py::gil_scoped_release release;
                 self.shutdown();
             },
             "Shutdown the manager and release resources.");

    // Convenience factory
    m.def("create_quarantine_manager",
          [](const std::string &db_path) {
              return std::make_unique<pbl4::av::QuarantineManager>(db_path);
          },
          py::arg("db_path"),
          "Factory helper to create a QuarantineManager instance.");
}