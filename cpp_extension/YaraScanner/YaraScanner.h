#pragma once

#include <string>
#include <functional>
#include <filesystem>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <unordered_map>
#include <vector>
#include <optional>
#include <cstdint>

#if defined(_WIN32)
#include <windows.h>
#endif

#include <yara.h>
#include <sqlite3.h>

namespace fs = std::filesystem;

class YaraScanner;
struct Result
{
    bool        isMalware{false};
    std::string date;
    std::string nameDesktop;
    std::string severity;
    std::string filename;
    std::string filepath;
    std::string desc;

    //All three hashes are in lowercase hex format
    std::string md5;
    std::string sha1;
    std::string sha256;

    // `hash` with `hash_type` describing which was used for the match.
    std::string hash;            // matched hash value (hex) when applicable
    std::string hash_type;       // "MD5" | "SHA1" | "SHA256"

    std::string detection_source;// "HASH" or "YARA"
    std::string malware_name;    // name from DB if matched

    // Aggregation info for YARA: number of matched rules and identifiers.
    // When multiple rules match a single file the scanner can populate these
    // and emit a single aggregated Result to the user callback.
    int matched_rules_count{0};
    std::vector<std::string> matched_rules;
};

struct ScanContext
{
    std::function<void(const Result&)> callback;

    YaraScanner* owner{nullptr};

    std::string filename;
    std::string filepath;

    std::optional<std::string> md5;
    std::optional<std::string> sha1;
    std::optional<std::string> sha256;

    std::vector<std::string> matched_rules;

    std::mutex matches_mutex;
};

class YaraScanner
{
public:
    using ResultCallback = std::function<void(const Result&)>;

    YaraScanner();
    ~YaraScanner();

    // Initialize: load rules file and open sqlite DB.
    // - rules_path: path to compiled rules (.yarc) or rules text acceptable to yr_rules_load
    // - db_path: path to sqlite3 DB with tables sig_md5, sig_sha1, sig_sha256
    // - status_callback: optional callback to receive NOTICE/ERROR messages during init
    //
    // Blocking call: per your design, init will load rules synchronously.
    bool init(const std::string& rules_path,
              const std::string& db_path,
              ResultCallback status_callback = nullptr);

    // Shutdown: stop realtime, free rules, close DB. Safe to call multiple times.
    void shutdown();

    // Synchronous scanning API
    // - scan_file: scan a single file (calls callback for detections)
    // - scan_folder: recursively scan a directory
    void scan_file(const std::string& file_path, ResultCallback callback);
    void scan_folder(const std::string& scan_path, ResultCallback callback);

    // Real-time protection API (cross-platform)
    // - start_realtime: start background monitor for path; callback invoked for detections.
    //   Returns true if monitoring was successfully started, or false if monitoring is
    //   already active or the request could not be honored (e.g. initialization/state errors).
    // - stop_realtime: stop monitoring and worker threads
    bool start_realtime(const std::string& watch_path, ResultCallback callback);
    void stop_realtime();

    // Utility accessors
    static std::string currentDateTime();
    static std::string getComputerName();



    // Public accessor for callback-enabled flag so non-member helpers can
    // query without accessing private members directly.
    bool are_callbacks_enabled() const { return callbacks_enabled.load(); }

    // Progress accessors (exposed for UI polling)
    // - get_progress_percent(): returns an int 0..100 representing scan percent.
    // - get_completed_count(), get_total_count(): raw counters when available.
    // - get_progress_counts(): pair<int,int> convenience wrapper.
    // - reset_progress(): reset/clear counters prior to a new scan.
    int get_progress_percent() const;
    uint64_t get_completed_count() const;
    uint64_t get_total_count() const;
    std::pair<int, int> get_progress_counts() const;
    void reset_progress();

    // Throttle configuration API
    //
    // Configure a lightweight time-slicing throttle applied between files when
    // scanning folders. These are intended to be non-invasive defaults that
    // reduce CPU duty-cycle for multi-file workloads.
    //
    // - duty_cycle: fraction of time spent working (0.0 < duty_cycle < 1.0),
    //   e.g. 0.5 for ~50% CPU duty. Default is 0.5.
    // - max_sleep_ms: clamp for the sleep inserted after each file (milliseconds).
    //   Default is 500 ms.
    //
    // These setters only affect the simple time-slicing throttle that runs
    // between files in `scan_folder`. They are safe to call at runtime prior
    // to starting a scan.
    void set_throttle_duty(double duty_cycle);
    void set_throttle_max_sleep_ms(int max_sleep_ms);
    void get_throttle_settings(double &out_duty, int &out_max_sleep_ms) const;
    // Full-scan override: when enabled the native scanner should bypass
    // signature and file-size policy checks and perform hash + YARA on all files.
    // This is a best-effort toggle; bindings may choose to ignore if unsupported.
    void set_full_scan(bool enabled);
    bool is_full_scan() const;

private:
    // Core synchronous scan implementation (shared)
    void scan_file_internal(const std::string& file_path, ResultCallback& callback);

    // Database helpers
    bool prepare_db_statements();
    void finalize_db_statements();
    bool check_hash_in_db(const std::string& hex_hash, const std::string& hash_type, std::string& out_malware_name);
    bool check_hash_whitelist(const std::string& hex_hash, const std::string& hash_type);

    // Hash helpers (return lowercase hex)
    static std::optional<std::string> compute_md5_hex(const std::string& file_path);
    static std::optional<std::string> compute_sha1_hex(const std::string& file_path);
    static std::optional<std::string> compute_sha256_hex(const std::string& file_path);
    static std::tuple<std::optional<std::string>, std::optional<std::string>, std::optional<std::string>>
        compute_all_hashes(const std::string& file_path);

    // File policy helpers
    // - skip files larger than MAX_FILE_SIZE_SKIP bytes entirely
    // - sample behavior: if file <= SMALL_FILE_MAX scan full;
    //   if SMALL_FILE_MAX < size <= PARTIAL_FILE_MAX, scan prefix+suffix;
    //   else skip
    bool should_skip_file_by_size(const std::string& file_path, uint64_t& out_size) const;
    bool is_trusted_publisher(const std::string& file_path) const; // Windows Authenticode check (platform-specific)

    // Read helpers for partial scanning:
    // - read first PREFIX_SIZE bytes and last SUFFIX_SIZE bytes into buffers
    // Implementation currently reads default prefix/suffix sizes (PARTIAL_PREFIX_SIZE / PARTIAL_SUFFIX_SIZE).
    bool read_prefix_suffix(const std::string& file_path,
                            std::vector<uint8_t>& out_prefix,
                            std::vector<uint8_t>& out_suffix) const;

    // YARA scanning helpers: supports scanning entire file via yr_rules_scan_file,
    // and scanning in-memory buffers via yr_rules_scan_mem (if desired)
    bool yara_scan_file(const std::string& file_path, ScanContext* ctx);
    bool yara_scan_memory(const uint8_t* data, size_t len, const std::string& origin_file, ScanContext* ctx);

    // Realtime monitoring internals
    void monitor_loop(std::string path);         // cross-platform polling fallback
    void monitor_worker_loop();                         // worker that processes queued events (debounce + throttle)

#if defined(_WIN32)
    // Windows specific helpers (ReadDirectoryChangesW based watcher)
    void start_windows_watcher(const std::string& watch_path);
    void stop_windows_watcher();
    void windows_watcher_thread_func(const std::string& watch_path);

    // Authenticate publisher using Authenticode (returns true if publisher in allow-list and signature valid)
    bool windows_is_trusted_publisher(const std::string& file_path) const;
#endif

private:
    // YARA rules handle
    YR_RULES* rules = nullptr;

    // SQLite DB handle + prepared statements
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt_check_md5 = nullptr;
    sqlite3_stmt* stmt_check_sha1 = nullptr;
    sqlite3_stmt* stmt_check_sha256 = nullptr;
    sqlite3_stmt* stmt_check_whitelist = nullptr;

    // Initialization flag
    bool initialized = false;

    // Thread safety
    std::mutex scan_mutex;           // protects DB and rules access during scan
    std::mutex queue_mutex;          // protects path_queue
    std::condition_variable queue_cv;

    // Realtime monitoring threads and state
    std::thread monitor_thread;          // watches filesystem (either polling or ReadDirectoryChangesW)
    std::thread monitor_worker_thread;   // consumes queued events and performs scans
    // Monitor lifecycle state to avoid races when starting/stopping repeatedly.
    enum class MonitorState : int { Stopped = 0, Starting = 1, Running = 2, Stopping = 3 };
    std::atomic<MonitorState> monitor_state{MonitorState::Stopped};
    // Backwards-compatible boolean flag that indicates monitoring is active (convenience).
    std::atomic<bool> monitoring{false};
    std::atomic<bool> callbacks_enabled{false}; // whether realtime callbacks are currently allowed
    std::mutex callback_mutex;     // Protects access to realtime_callback
    ResultCallback realtime_callback;    // stored Python callback for realtime detections

    // Progress counters used by scanning routines. Keep these atomic to avoid
    // taking a mutex on every update since UI polling expects low-overhead reads.
    // These are manipulated by scanner internals (increment/store) and observed
    // via the public accessors declared above.
    std::atomic<uint64_t> total_count{0};
    std::atomic<uint64_t> completed_count{0};

    // Throttle configuration (time-slicing applied between files in scan_folder).
    // Defaults chosen to provide a sensible reduction in CPU for multi-file scans.
    // These members are read by the scanning implementation; setters are exposed
    // in the public API above so the controller can adjust them before starting.
    double throttle_duty_cycle{0.5};   // fraction (0.0..1.0) of time spent working
    int    throttle_max_sleep_ms{500}; // maximum sleep inserted after each file (ms)
    // Runtime override flag for full-scan mode; when true, native code may skip
    // signature and size-based skips and scan every file fully for hash + YARA checks.
    std::atomic<bool> full_scan_override{false};

#if defined(_WIN32)
    // Per-instance watcher handles so stop_realtime can cancel IO promptly
    // without relying on a global registry. These are protected by
    // `watchers_mutex`.
    std::mutex watchers_mutex;
    std::vector<HANDLE> watcher_dir_handles;
    std::vector<HANDLE> watcher_events;
#endif

    // Queue for detected file paths (debounced)
    std::deque<std::string> path_queue;
    // Map to store last event time for a path to implement debounce
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_event_time;

    // Policy configuration (sizes in bytes)
    static constexpr uint64_t MAX_FILE_SIZE_SKIP = 500ULL * 1024ULL * 1024ULL; // 500 MB: skip
    static constexpr uint64_t PARTIAL_FILE_MIN = 10ULL * 1024ULL * 1024ULL;    // 10 MB
    static constexpr uint64_t PARTIAL_FILE_MAX = 500ULL * 1024ULL * 1024ULL;   // 500 MB
    static constexpr size_t   PARTIAL_PREFIX_SIZE = 4ULL * 1024ULL * 1024ULL;  // 4 MB prefix
    static constexpr size_t   PARTIAL_SUFFIX_SIZE = 1ULL * 1024ULL * 1024ULL;  // 1 MB suffix

    // Debounce threshold (milliseconds) before processing a queued event
    std::chrono::milliseconds debounce_threshold{800};

    // Internal helper to push a path into queue with dedup/debounce
    void enqueue_path_for_scan(const std::string& path);

    // Internal helper used by worker to pop and process paths
    bool pop_queued_path(std::string& out_path);

    // Helper to perform policy-driven scan (size/issuer checks and then appropriate scan)
    void process_queued_path(const std::string& path);

    // Helper to check signature trust (delegates to platform-specific implementation)
    bool check_trusted_publisher_and_skip(const std::string& path);

    // Helper to normalize hex strings, etc.
    static std::string normalize_hex(const std::string& hex);

    // Internal: default scan callback wrapper that forwards to user callback (used in worker)
    void invoke_callback_safe(ResultCallback& cb, const Result& r);
};
