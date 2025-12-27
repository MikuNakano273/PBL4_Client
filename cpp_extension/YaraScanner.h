#pragma once

#include <string>
#include <functional>
#include <yara.h>
#include <filesystem>

namespace fs = std::filesystem;   // <-- alias used in .cpp

struct Result {
    bool        isMalware;
    std::string date;
    std::string nameDesktop;
    std::string severity;
    std::string filename;
    std::string filepath;
    std::string desc;
};

class YaraScanner {
public:
    using ResultCallback = std::function<void(const Result&)>;

    YaraScanner();
    ~YaraScanner();

    bool init(const std::string& rules_path, ResultCallback callback);
    void scan_folder(const std::string& scan_path, ResultCallback callback);
    void scan_file(const std::string& file_path, ResultCallback callback); // quét file riêng
    void shutdown();

private:
    YR_RULES* rules = nullptr;
    bool      initialized = false;
};