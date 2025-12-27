#include "YaraScanner.h"
#include <chrono>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------
static std::string currentDateTime() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y/%m/%d %H:%M:%S");
    return oss.str();
}

static std::string getComputerName() {
    char name[256]{};
#ifdef _WIN32
    DWORD sz = sizeof(name);
    GetComputerNameA(name, &sz);
#else
    gethostname(name, sizeof(name));
#endif
    return name;
}

// ---------------------------------------------------------------------
// YARA Callbacks
// ---------------------------------------------------------------------
struct CallbackData {
    YaraScanner::ResultCallback* callback;
    const char*                 filepath;
};

static void compiler_error_callback(int, const char* file_name,
                                   int line_number, const YR_RULE*,
                                   const char* message, void* user_data) {
    auto* cb = static_cast<YaraScanner::ResultCallback*>(user_data);
    std::string desc = "Compile error in " + std::string(file_name) +
                       "(" + std::to_string(line_number) + "): " + message;
    Result r{false, currentDateTime(), getComputerName(),
             "ERROR", "", "", desc};
    (*cb)(r);
}

static int rule_match_callback(YR_SCAN_CONTEXT*, int message,
                               void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    auto* data = static_cast<CallbackData*>(user_data);
    auto* rule = static_cast<YR_RULE*>(message_data);

    // <-- these two variables are defined in the scan loop
    extern std::string filename_utf8;
    extern std::string filepath_utf8;

    Result r{
        true,
        currentDateTime(),
        getComputerName(),
        "Warning",
        filename_utf8,                     // <-- plain std::string
        filepath_utf8,                     // <-- plain std::string
        "Matched by rule: " + std::string(rule->identifier)
    };

    (*data->callback)(r);
    return CALLBACK_CONTINUE;
}

// ---------------------------------------------------------------------
// YaraScanner implementation
// ---------------------------------------------------------------------
YaraScanner::YaraScanner() = default;
YaraScanner::~YaraScanner() { shutdown(); }

bool YaraScanner::init(const std::string& rules_path, ResultCallback callback) {
    Result log_start{false, currentDateTime(), getComputerName(),
                    "NOTICE", "", "", "Initializing YARA scanner..."};
    callback(log_start);

    if (yr_initialize() != ERROR_SUCCESS) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", "YARA library initialization failed"};
        callback(err);
        return false;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", "Failed to create YARA compiler"};
        callback(err);
        return false;
    }

    // --- Capture REAL compile errors here ---
    std::string compile_error_msg = "Unknown compilation error";
    bool has_compile_error = false;

    yr_compiler_set_callback(compiler, [](int error_level, const char* file_name,
                                         int line_number, const YR_RULE* rule,
                                         const char* message, void* user_data) {
        auto* msg_ptr = static_cast<std::string*>(user_data);
        std::string line_info = (file_name && line_number > 0)
            ? std::string(file_name) + ":" + std::to_string(line_number) + ": "
            : "";
        *msg_ptr = line_info + (message ? message : "unknown error");
    }, &compile_error_msg);

    FILE* f = nullptr;
#ifdef _WIN32
    fopen_s(&f, rules_path.c_str(), "r");
#else
    f = fopen(rules_path.c_str(), "r");
#endif

    if (!f) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", "Cannot open rules file: " + rules_path};
        callback(err);
        yr_compiler_destroy(compiler);
        return false;
    }

    int err_cnt = yr_compiler_add_file(compiler, f, nullptr, rules_path.c_str());
    fclose(f);

    if (err_cnt > 0) {
        // Use the REAL captured error message
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", compile_error_msg};
        callback(err);
        yr_compiler_destroy(compiler);
        return false;
    }
    // --- End of compile error capture ---

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", "Failed to extract compiled rules"};
        callback(err);
        yr_compiler_destroy(compiler);
        return false;
    }

    yr_compiler_destroy(compiler);
    initialized = true;

    Result success{false, currentDateTime(), getComputerName(),
                   "NOTICE", "", "", "YARA rules loaded successfully"};
    callback(success);
    return true;
}

// ---------------------------------------------------------------------
// NOTE: the two UTF-8 strings are **local** to this function
// ---------------------------------------------------------------------
std::string filename_utf8;   // visible to rule_match_callback (extern)
std::string filepath_utf8;   // visible to rule_match_callback (extern)

void YaraScanner::scan_folder(const std::string& scan_path, ResultCallback callback) {
    if (!initialized) return;

    fs::path dir_path = fs::u8path(scan_path);

    Result log_start{false, currentDateTime(), getComputerName(),
                     "NOTICE", "", "", "Scanning folder: " + scan_path};
    callback(log_start);

    try {
        for (const auto& entry : fs::recursive_directory_iterator(
                dir_path, fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file()) continue;

            fs::path file_path = entry.path();

            // ---- safe UTF-8 conversion ----
            auto to_utf8 = [](const std::wstring& ws) -> std::string {
                if (ws.empty()) return {};
                int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                             nullptr, 0, nullptr, nullptr);
                std::string out(sz - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                    &out[0], sz - 1, nullptr, nullptr);
                return out;
            };

            std::wstring w_filepath = file_path.wstring();
            std::wstring w_filename = file_path.filename().wstring();

            filepath_utf8 = to_utf8(w_filepath);
            filename_utf8 = to_utf8(w_filename);

            CallbackData data{ &callback, filepath_utf8.c_str() };

            // --- Callback trước mỗi file (INFO) ---
            Result r{false, currentDateTime(), getComputerName(),
                     "INFO", filename_utf8, filepath_utf8, "Scanning file..."};
            callback(r);

            // --- Scan file ---
            yr_rules_scan_file(rules, filepath_utf8.c_str(),
                               SCAN_FLAGS_FAST_MODE,
                               rule_match_callback, &data, 0);
        }
    }
    catch (const fs::filesystem_error&) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", "Access denied or path error"};
        callback(err);
    }

    Result log_done{false, currentDateTime(), getComputerName(),
                    "NOTICE", "", "", "Scan complete"};
    callback(log_done);
}

void YaraScanner::scan_file(const std::string& file_path, ResultCallback callback) {
    if (!initialized) return;

    fs::path path = fs::u8path(file_path);
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", "", "", "File does not exist or is not a regular file"};
        callback(err);
        return;
    }

    // ---- UTF-8 conversion ----
    auto to_utf8 = [](const std::wstring& ws) -> std::string {
        if (ws.empty()) return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                     nullptr, 0, nullptr, nullptr);
        std::string out(sz - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                            &out[0], sz - 1, nullptr, nullptr);
        return out;
    };

    std::wstring w_filepath = path.wstring();
    std::wstring w_filename = path.filename().wstring();

    filepath_utf8 = to_utf8(w_filepath);
    filename_utf8 = to_utf8(w_filename);

    CallbackData data{ &callback, filepath_utf8.c_str() };

    // --- Callback trước scan file ---
    Result r{false, currentDateTime(), getComputerName(),
             "INFO", filename_utf8, filepath_utf8, "Scanning file..."};
    callback(r);

    int scan_result = yr_rules_scan_file(rules, filepath_utf8.c_str(),
                                         SCAN_FLAGS_FAST_MODE,
                                         rule_match_callback, &data, 0);

    if (scan_result != ERROR_SUCCESS) {
        Result err{false, currentDateTime(), getComputerName(),
                   "ERROR", filename_utf8, filepath_utf8,
                   "Failed to scan file"};
        callback(err);
    } else {
        Result log_done{false, currentDateTime(), getComputerName(),
                        "NOTICE", filename_utf8, filepath_utf8, "Scan complete"};
        callback(log_done);
    }
}

void YaraScanner::shutdown() {
    if (rules) yr_rules_destroy(rules);
    if (initialized) yr_finalize();
    rules = nullptr;
    initialized = false;
}