
#include "YaraScanner.h"
#include <Python.h>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#endif

#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <optional>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <map>
#include <mutex>

#if defined(_WIN32)
#include <openssl/evp.h>
#else
#include <openssl/evp.h>
#endif

namespace {
    static std::string wide_to_utf8(const std::wstring &w) {
#if defined(_WIN32)
        if (w.empty()) return std::string();
        int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
        if (n <= 0) return std::string();
        std::string out;
        out.resize(n - 1);
        if (::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], n, NULL, NULL) == 0) {
            return std::string();
        }
        return out;
#else
        std::string s;
        s.reserve(w.size());
        for (wchar_t wc : w) {
            s.push_back(static_cast<char>(wc & 0xFF));
        }
        return s;
#endif
    }

    // Diagnostic logging helper - prefix with scanner tag and timestamp.
    static void log_diag(const std::string &msg) {
        try {
            std::cerr << "[YaraScanner] " << YaraScanner::currentDateTime() << " - " << msg << std::endl;
        } catch (...) {
            std::cerr << "[YaraScanner] (no-time) - " << msg << std::endl;
        }
    }

    static void call_callback_if_python_ready(const YaraScanner::ResultCallback &cb, const Result &r, YaraScanner *owner = nullptr) {
        if (!cb) return;
        if (owner && !owner->are_callbacks_enabled()) return;
        #ifdef Py_LIMITED_API
        #else
        if (!Py_IsInitialized()) return;
        #endif
        try {
            cb(r);
        } catch (const std::exception &e) {
            std::cerr << "[YaraScanner] callback threw exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[YaraScanner] callback threw unknown exception" << std::endl;
        }
    }

    static inline void throttle_after_work(std::chrono::steady_clock::time_point work_start,
                                           double duty_cycle = 0.5,
                                           int max_sleep_ms = 500,
                                           int min_work_ms_to_throttle = 2) {
        using namespace std::chrono;
        auto work_end = steady_clock::now();
        auto work_dur = duration_cast<milliseconds>(work_end - work_start).count();
        if (work_dur < min_work_ms_to_throttle) return;
        if (duty_cycle <= 0.0 || duty_cycle >= 1.0) return;

        double W = static_cast<double>(work_dur);
        double S = W * (1.0 - duty_cycle) / duty_cycle;
        int sleep_ms = static_cast<int>(std::min<double>(S, static_cast<double>(max_sleep_ms)));
        if (sleep_ms > 0) {
            std::this_thread::sleep_for(milliseconds(sleep_ms));
        }
    }

#if defined(_WIN32)
    #include <DbgHelp.h>

    static void write_minidump(EXCEPTION_POINTERS* exInfo) {
        std::ostringstream oss;
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char timestr[64];
        // Correct string literal
        std::strftime(timestr, sizeof(timestr), "%Y%m%d_%H%M%S", std::localtime(&t));
        oss << "yarascanner_crash_" << timestr << ".dmp";
        std::string fname = oss.str();

        // Convert to wide
        int n = MultiByteToWideChar(CP_UTF8, 0, fname.c_str(), -1, NULL, 0);
        if (n <= 0) return;
        std::wstring wname; wname.resize(n - 1);
        if (MultiByteToWideChar(CP_UTF8, 0, fname.c_str(), -1, &wname[0], n) == 0) return;

        HANDLE fh = CreateFileW(wname.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh == INVALID_HANDLE_VALUE) return;

        // Dynamically load MiniDumpWriteDump to avoid link-time errors if DbgHelp is not present.
        HMODULE hDbg = ::LoadLibraryA("DbgHelp.dll");
        if (!hDbg) { CloseHandle(fh); return; }
        typedef BOOL (WINAPI *MiniDumpWriteDumpT)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
        auto pMiniDumpWriteDump = (MiniDumpWriteDumpT)::GetProcAddress(hDbg, "MiniDumpWriteDump");
        if (!pMiniDumpWriteDump) { FreeLibrary(hDbg); CloseHandle(fh); return; }

        MINIDUMP_EXCEPTION_INFORMATION mei;
        mei.ThreadId = GetCurrentThreadId();
        mei.ExceptionPointers = exInfo;
        mei.ClientPointers = TRUE;

        BOOL ok = pMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), fh, MiniDumpWithFullMemory, &mei, NULL, NULL);
        if (!ok) {
            std::cerr << "[YaraScanner] MiniDumpWriteDump failed\n";
        } else {
            std::cerr << "[YaraScanner] Minidump written: " << fname << "\n";
        }

        FreeLibrary(hDbg);
        CloseHandle(fh);
    }

    static LONG WINAPI yarascanner_unhandled_exception_filter(EXCEPTION_POINTERS* exInfo) {
        try {
            write_minidump(exInfo);
        } catch (...) {
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
#endif // _WIN32

    static void yarascanner_terminate_handler() {
        try {
            std::ostringstream oss;
            oss << "[YaraScanner] terminate() called. Writing basic diagnostics to yarascanner_terminate.log\n";
            std::ofstream f("yarascanner_terminate.log", std::ios::app);
            if (f.is_open()) {
                auto now = std::chrono::system_clock::now();
                std::time_t t = std::chrono::system_clock::to_time_t(now);
                f << "---- terminate at " << std::ctime(&t) << "----\n";
                f << oss.str();
                f.close();
            } else {
                std::cerr << oss.str();
            }
        } catch (...) {
        }
        std::abort();
    }

    static void install_crash_handlers() {
        try {
            std::set_terminate(&yarascanner_terminate_handler);
        } catch (...) {
            // ignore
        }
#if defined(_WIN32)
        SetUnhandledExceptionFilter(yarascanner_unhandled_exception_filter);
#endif
    }

} // namespace

// --------------------------- Helpers -------------------------------------

// Read first PREFIX and last SUFFIX bytes from file into provided buffers.
// Returns true on success and false on failure.
bool YaraScanner::read_prefix_suffix(const std::string& file_path,
                                    std::vector<uint8_t>& out_prefix,
                                    std::vector<uint8_t>& out_suffix) const
{
    std::error_code ec;
    uint64_t size = 0;
    try {
        size = static_cast<uint64_t>(fs::file_size(file_path, ec));
    } catch (...) {
        return false;
    }
    if (ec) return false;

    // Determine how many bytes to read for prefix and suffix given file size.
    size_t prefix_to_read = static_cast<size_t>(std::min<uint64_t>(PARTIAL_PREFIX_SIZE, size));
    size_t suffix_to_read = 0;
    if (size > prefix_to_read) {
        suffix_to_read = static_cast<size_t>(std::min<uint64_t>(PARTIAL_SUFFIX_SIZE, size - prefix_to_read));
    }

    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs.is_open()) return false;

    out_prefix.clear();
    out_suffix.clear();

    if (prefix_to_read > 0) {
        out_prefix.resize(prefix_to_read);
        ifs.read(reinterpret_cast<char*>(out_prefix.data()), static_cast<std::streamsize>(prefix_to_read));
        if (static_cast<size_t>(ifs.gcount()) != prefix_to_read) {
            // If file is smaller than requested prefix, shrink to actual read size.
            out_prefix.resize(static_cast<size_t>(ifs.gcount()));
            // Continue; not fatal.
        }
    }

    if (suffix_to_read > 0) {
        // Seek to suffix start from file end
        std::streamoff off = static_cast<std::streamoff>(size - suffix_to_read);
        ifs.clear();
        ifs.seekg(off, std::ios::beg);
        if (!ifs.good()) return false;
        out_suffix.resize(suffix_to_read);
        ifs.read(reinterpret_cast<char*>(out_suffix.data()), static_cast<std::streamsize>(suffix_to_read));
        if (static_cast<size_t>(ifs.gcount()) != suffix_to_read) {
            out_suffix.resize(static_cast<size_t>(ifs.gcount()));
        }
    }

    return true;
}

// Worker thread that consumes queued file paths and processes them with debounce.
void YaraScanner::monitor_worker_loop()
{
    log_diag("monitor_worker_loop: started");
    try {
        while (monitoring.load()) {
            std::string path;
            {
                std::unique_lock<std::mutex> lk(queue_mutex);
                // Wait until either signalled or debounce timeout elapses.
                queue_cv.wait_for(lk, debounce_threshold, [this]() {
                    return !path_queue.empty() || !monitoring.load();
                });

                if (!monitoring.load() && path_queue.empty()) break;

                if (!path_queue.empty()) {
                    path = std::move(path_queue.front());
                    path_queue.pop_front();
                }
            }

            if (!path.empty()) {
                try {
                    log_diag(std::string("monitor_worker_loop: processing queued path: ") + path);
                    process_queued_path(path);
                } catch (const std::exception &e) {
                    std::cerr << "monitor_worker_loop: exception processing path: " << e.what() << std::endl;
                } catch (...) {
                    std::cerr << "monitor_worker_loop: unknown exception processing path" << std::endl;
                }
            }
        }

        // Drain remaining items if any
        std::string leftover;
        while (pop_queued_path(leftover)) {
            try {
                log_diag(std::string("monitor_worker_loop: draining leftover: ") + leftover);
                process_queued_path(leftover);
            } catch (...) {
                // ignore
            }
        }
    } catch (const std::exception &e) {
        // Log and swallow to prevent thread termination from leaking an exception
        std::cerr << "monitor_worker_loop: exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "monitor_worker_loop: unknown exception" << std::endl;
    }
    log_diag("monitor_worker_loop: exiting");
}

// On Windows we use ReadDirectoryChangesW.
void YaraScanner::windows_watcher_thread_func(const std::string& watch_path)
{
#if defined(_WIN32)
    std::string expanded;
    DWORD expLen = ExpandEnvironmentStringsA(watch_path.c_str(), NULL, 0);
    if (expLen > 0) {
        expanded.resize(expLen);
        ExpandEnvironmentStringsA(watch_path.c_str(), &expanded[0], expLen);
        if (!expanded.empty() && expanded.back() == '\0') expanded.pop_back();
    } else {
        expanded = watch_path;
    }

    // split by ';' or '|'
    std::vector<std::string> paths;
    size_t pos = 0;
    while (pos < expanded.size()) {
        size_t p = expanded.find_first_of(";|", pos);
        if (p == std::string::npos) p = expanded.size();
        std::string part = expanded.substr(pos, p - pos);
        // trim whitespace
        size_t start = 0;
        while (start < part.size() && std::isspace((unsigned char)part[start])) ++start;
        size_t end = part.size();
        while (end > start && std::isspace((unsigned char)part[end-1])) --end;
        if (end > start) paths.push_back(part.substr(start, end - start));
        pos = p + 1;
    }

    if (paths.empty()) {
        log_diag(std::string("windows_watcher_thread_func: no paths parsed, falling back to monitor_loop for: ") + watch_path);
        monitor_loop(watch_path);
        return;
    }

    // Worker lambda that watches a single directory (wide path) and enqueues events.
    auto worker = [this](const std::wstring &wdir) {
        std::string dir_utf8 = wide_to_utf8(wdir);
        log_diag(std::string("windows watcher worker: starting for: ") + dir_utf8);

        const DWORD BUF_SIZE = 64 * 1024;
        std::vector<BYTE> buffer(BUF_SIZE);

        HANDLE hDir = INVALID_HANDLE_VALUE;
        HANDLE hEvent = NULL;
        OVERLAPPED ov;
        ZeroMemory(&ov, sizeof(ov));

        try {
            hDir = CreateFileW(wdir.c_str(),
                               FILE_LIST_DIRECTORY,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                               NULL);
            if (hDir == INVALID_HANDLE_VALUE) {
                log_diag(std::string("windows watcher worker: CreateFileW failed for: ") + dir_utf8);
                return;
            }

            hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!hEvent) {
                log_diag(std::string("windows watcher worker: CreateEventW failed for: ") + dir_utf8);
                CloseHandle(hDir);
                return;
            }

            ov.hEvent = hEvent;

            // Register handles in this instance so stop_realtime can cancel pending IO for this scanner
            {
                std::lock_guard<std::mutex> lk(this->watchers_mutex);
                this->watcher_dir_handles.push_back(hDir);
                this->watcher_events.push_back(ov.hEvent);
            }
            log_diag(std::string("windows watcher worker: registered handles for: ") + dir_utf8);

            while (this->monitoring.load()) {
                DWORD bytesReturned = 0;
                // Issue overlapped read; lpBytesReturned must be NULL when using overlapped structure
                BOOL ok = ReadDirectoryChangesW(
                    hDir,
                    buffer.data(),
                    BUF_SIZE,
                    TRUE, // watch subtree
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
                    NULL,
                    &ov,
                    NULL);

                if (!ok) {
                    // transient error; sleep briefly and retry
                    log_diag(std::string("windows watcher worker: ReadDirectoryChangesW returned false, sleeping"));
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    ResetEvent(ov.hEvent);
                    continue;
                }

                // Wait with timeout so we can check monitoring flag periodically
                DWORD waitRes = WaitForSingleObject(ov.hEvent, 250); // 250ms

                if (waitRes == WAIT_OBJECT_0) {
                    // IO completed, obtain number of bytes
                    if (!GetOverlappedResult(hDir, &ov, &bytesReturned, FALSE)) {
                        ResetEvent(ov.hEvent);
                        continue;
                    }

                    DWORD offset = 0;
                    while (offset < bytesReturned) {
                        FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
                        int nameLen = static_cast<int>(fni->FileNameLength / sizeof(WCHAR));
                        std::wstring fname;
                        if (nameLen > 0) {
                            fname.assign(fni->FileName, fni->FileName + nameLen);
                        } else {
                            fname.clear();
                        }

                        // Build full path (ensure separator)
                        std::wstring full = wdir;
                        if (!full.empty() && full.back() != L'\\' && full.back() != L'/') {
                            full.push_back(L'\\');
                        }
                        full += fname;

                        // Convert wide path -> UTF-8 using helper
                        std::string utf8path = wide_to_utf8(full);
                        if (!utf8path.empty()) {
                            // Only enqueue for file create/modify/renamed-new events.
                            // Ignore deletions and old-name renames and avoid enqueueing directories.
                            DWORD action = fni->Action;
                            if (action == FILE_ACTION_ADDED ||
                                action == FILE_ACTION_MODIFIED ||
                                action == FILE_ACTION_RENAMED_NEW_NAME)
                            {
                                try {
                                    std::error_code ec;
                                    // If we can stat the path and it's a regular file, enqueue.
                                    if (fs::exists(utf8path, ec) && fs::is_regular_file(utf8path, ec)) {
                                        this->enqueue_path_for_scan(utf8path);
                                    } else {
                                        log_diag(std::string("windows watcher worker: ignored non-file event: ") + utf8path);
                                    }
                                } catch (...) {
                                    // Best-effort: if stat fails (transient), still enqueue so the
                                    // monitor worker can attempt to handle it gracefully.
                                    this->enqueue_path_for_scan(utf8path);
                                }
                            } else {
                                log_diag(std::string("windows watcher worker: ignored action ") + std::to_string(action) + " for: " + utf8path);
                            }
                        }

                        if (fni->NextEntryOffset == 0) break;
                        offset += fni->NextEntryOffset;
                    }

                    // Prepare for the next overlapped call
                    ResetEvent(ov.hEvent);
                } else if (waitRes == WAIT_TIMEOUT) {
                    // Timed out; if monitoring stopped, cancel outstanding IO and exit
                    if (!this->monitoring.load()) {
                        CancelIoEx(hDir, &ov);
                        // Wait for cancellation to complete (should be quick)
                        WaitForSingleObject(ov.hEvent, INFINITE);
                        break;
                    }
                    // otherwise loop to issue another ReadDirectoryChangesW
                } else {
                    // Wait failed; sleep and retry
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    ResetEvent(ov.hEvent);
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "windows watcher worker exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "windows watcher worker unknown exception" << std::endl;
        }

        // Unregister and cleanup handles from this instance (always attempt cleanup)
        if (hEvent || hDir != INVALID_HANDLE_VALUE) {
            {
                std::lock_guard<std::mutex> lk(this->watchers_mutex);
                for (size_t i = 0; i < this->watcher_dir_handles.size(); ++i) {
                    if (this->watcher_dir_handles[i] == hDir && this->watcher_events[i] == ov.hEvent) {
                        this->watcher_dir_handles.erase(this->watcher_dir_handles.begin() + i);
                        this->watcher_events.erase(this->watcher_events.begin() + i);
                        break;
                    }
                }
            }
        }
        if (hEvent) CloseHandle(hEvent);
        if (hDir != INVALID_HANDLE_VALUE) CloseHandle(hDir);
        log_diag(std::string("windows watcher worker: exiting for: ") + dir_utf8);
    };

    // Launch worker threads for each path
    std::vector<std::thread> workers;
    for (const auto &p : paths) {
        if (p.empty()) continue;
        // Convert to wide
        int n = MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, NULL, 0);
        if (n <= 0) continue;
        std::wstring w; w.resize(n - 1);
        if (MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, &w[0], n) == 0) continue;
        log_diag(std::string("windows_watcher_thread_func: launching worker for: ") + p);
        workers.emplace_back(std::thread(worker, w));
    }

    // Join workers (this function blocks until workers exit)
    for (auto &t : workers) {
        if (t.joinable()) {
            log_diag("windows_watcher_thread_func: joining a worker thread");
            t.join();
        }
    }
#else
    monitor_loop(watch_path);
#endif
}

// Stop watchers: cancel outstanding IO and signal events so overlapped waits return.
void YaraScanner::stop_windows_watcher()
{
#if defined(_WIN32)
    log_diag("stop_windows_watcher: called");
    // Copy handles under lock then cancel IO and signal events to wake threads.
    std::vector<HANDLE> dirs;
    std::vector<HANDLE> evs;
    {
        std::lock_guard<std::mutex> lk(this->watchers_mutex);
        dirs = this->watcher_dir_handles;
        evs = this->watcher_events;
    }

    log_diag(std::string("stop_windows_watcher: cancelling ") + std::to_string(dirs.size()) + " dir handles and signalling " + std::to_string(evs.size()) + " events");

    // Cancel outstanding IO on directory handles (no-op if none pending).
    for (auto hDir : dirs) {
        if (hDir && hDir != INVALID_HANDLE_VALUE) {
            CancelIoEx(hDir, NULL);
        }
    }

    // Signal events so any WaitForSingleObject wakes.
    for (auto ev : evs) {
        if (ev) SetEvent(ev);
    }
#endif
}

void YaraScanner::enqueue_path_for_scan(const std::string& path)
{
    if (path.empty()) return;
    {
        std::lock_guard<std::mutex> lk(queue_mutex);

        // Deduplicate: if last_event_time says this path was seen recently, update the timestamp
        auto now = std::chrono::steady_clock::now();
        auto it = last_event_time.find(path);
        if (it == last_event_time.end()) {
            path_queue.push_back(path);
            last_event_time[path] = now;
        } else {
            // Update last seen time; keep at most one entry in queue for this path.
            it->second = now;
            // If not already queued, push it
            bool already_in_queue = false;
            for (const auto& p : path_queue) {
                if (p == path) { already_in_queue = true; break; }
            }
            if (!already_in_queue) path_queue.push_back(path);
        }
        log_diag(std::string("enqueue_path_for_scan: enqueued '") + path + "'; queue_size=" + std::to_string(path_queue.size()));
    }

    queue_cv.notify_one();
}

// Pop a queued path into out_path; returns true if a path was popped.
bool YaraScanner::pop_queued_path(std::string& out_path)
{
    std::lock_guard<std::mutex> lk(queue_mutex);
    if (path_queue.empty()) return false;
    out_path = std::move(path_queue.front());
    path_queue.pop_front();
    return true;
}

// Process a single queued path using policy: honor size/publisher/hash then scan as required.
void YaraScanner::process_queued_path(const std::string& path)
{
    // Copy callback locally under lock to avoid data-race if stop/ start races with invocation.
    ResultCallback cb;
    {
        std::lock_guard<std::mutex> lk(this->callback_mutex);
        cb = realtime_callback;
    }
    if (!cb) return;

    // FILE-STABLE CHECK
    try {
        std::error_code ec;
        if (!fs::exists(path, ec) || !fs::is_regular_file(path, ec)) {
            log_diag(std::string("process_queued_path: path not exists or not a file: ") + path);
            return;
        }

        const int MAX_STABLE_RETRIES = 5;
        const auto STABLE_WAIT = std::chrono::milliseconds(150);
        bool stable = false;
        uint64_t last_size = 0;

        for (int i = 0; i < MAX_STABLE_RETRIES; ++i) {
            std::error_code ec2;
            uint64_t sz = 0;
            if (fs::exists(path, ec2) && fs::is_regular_file(path, ec2)) {
                try {
                    sz = static_cast<uint64_t>(fs::file_size(path, ec2));
                } catch (...) {
                    // transient error reading size; retry
                    sz = UINT64_MAX;
                }
            } else {
                log_diag(std::string("process_queued_path: file disappeared during stable check: ") + path);
                return;
            }

            if (i > 0 && sz != UINT64_MAX && sz == last_size) {
                stable = true;
                break;
            }
            last_size = sz;
            std::this_thread::sleep_for(STABLE_WAIT);
        }

        if (!stable) {
            log_diag(std::string("process_queued_path: file did not stabilize within retries, proceeding with best-effort scan: ") + path);
        } else {
            log_diag(std::string("process_queued_path: file stable, size=") + std::to_string(last_size) + " for: " + path);
        }
    } catch (const std::exception &e) {
        std::cerr << "process_queued_path: exception during stable-check: " << e.what() << std::endl;
        // fall through to best-effort scan
    } catch (...) {
        std::cerr << "process_queued_path: unknown exception during stable-check" << std::endl;
    }

    ResultCallback guarded_cb = [cb, this](const Result& r) {
        call_callback_if_python_ready(cb, r, this);
    };

    scan_file_internal(path, guarded_cb);
}

void YaraScanner::invoke_callback_safe(ResultCallback& cb, const Result& r)
{
    ResultCallback cb_copy;
    {
        std::lock_guard<std::mutex> lk(this->callback_mutex);
        cb_copy = cb;
    }
    if (!cb_copy) return;
    try {
        cb_copy(r);
    } catch (const std::exception &e) {
        std::cerr << "invoke_callback_safe: callback threw: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "invoke_callback_safe: callback threw unknown exception" << std::endl;
    }
}

bool YaraScanner::check_trusted_publisher_and_skip(const std::string& path)
{
#if defined(_WIN32)
    return windows_is_trusted_publisher(path);
#else
    (void)path;
    return false;
#endif
}

#if defined(_WIN32)
// Verify the Authenticode signature of a file and check the signer's display
// name against a small allow-list. Returns true if the file is signed by a
// trusted publisher and signature validation succeeded.
bool YaraScanner::windows_is_trusted_publisher(const std::string& file_path) const
{
    // Convert UTF-8 path to wide string
    std::wstring wpath;
    if (!file_path.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, NULL, 0);
        if (n <= 0) return false;
        wpath.resize(n - 1);
        if (MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, &wpath[0], n) == 0) return false;
    } else {
        return false;
    }

    // Prepare WINTRUST structures
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wpath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA wtd;
    memset(&wtd, 0, sizeof(wtd));
    wtd.cbStruct = sizeof(wtd);
    wtd.pPolicyCallbackData = NULL;
    wtd.pSIPClientData = NULL;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    // Use VERIFY action so WinVerifyTrust populates the hWVTStateData for inspection
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.hWVTStateData = NULL;
    wtd.pwszURLReference = NULL;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    wtd.dwUIContext = 0;

    // Validate signature (populate state data)
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &action, &wtd);
    if (status != ERROR_SUCCESS) {
        // Ensure we close state data if any and return false
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);
        return false;
    }

    // Extract provider data created by WinVerifyTrust
    CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(wtd.hWVTStateData);
    if (!provData) {
        // Close state data and return
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);
        return false;
    }

    // Get signer chain (0 = first signer)
    CRYPT_PROVIDER_SGNR* provSigner = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
    if (!provSigner) {
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);
        return false;
    }

    // Get signer certificate (0 = signer certificate)
    CRYPT_PROVIDER_CERT* provCert = WTHelperGetProvCertFromChain(provSigner, 0);
    if (!provCert || !provCert->pCert) {
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);
        return false;
    }
    PCCERT_CONTEXT certCtx = provCert->pCert;

    // Query display name from cert
    WCHAR nameBuf[512];
    DWORD nameLen = CertGetNameStringW(certCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nameBuf, (DWORD)std::size(nameBuf));
    std::string signerNameUtf8;
    if (nameLen > 1) {
        // Convert to UTF-8
        int need = WideCharToMultiByte(CP_UTF8, 0, nameBuf, -1, NULL, 0, NULL, NULL);
        if (need > 0) {
            signerNameUtf8.resize(need - 1);
            WideCharToMultiByte(CP_UTF8, 0, nameBuf, -1, &signerNameUtf8[0], need, NULL, NULL);
        }
    }

    // Normalize to lowercase for substring matching
    for (auto &c : signerNameUtf8) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Allow-list of large trusted vendors (substring matching)
    const std::vector<std::string> trusted_substrings = {
        "microsoft",
        "google",
        "apple",
        "intel",
        "amazon"
    };

    bool trusted = false;
    for (const auto &s : trusted_substrings) {
        if (!s.empty() && signerNameUtf8.find(s) != std::string::npos) {
            trusted = true;
            break;
        }
    }

    // Close WinVerifyTrust state to free provider data
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wtd);

    return trusted;
}
#endif

// --------------------------- Utility helpers -----------------------------

static std::string bytes_to_hex(const unsigned char* bytes, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

std::string YaraScanner::currentDateTime() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    char buf[64];
    std::tm tm;
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

std::string YaraScanner::getComputerName() {
    if (const char* env = std::getenv("COMPUTERNAME")) {
        return std::string(env);
    }
    if (const char* env2 = std::getenv("HOSTNAME")) {
        return std::string(env2);
    }
    return "unknown";
}

// --------------------------- Hashing -------------------------------------

static std::optional<std::string> compute_file_digest_openssl(const std::string& path,
                                                               const EVP_MD* evp) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::nullopt;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;

    if (EVP_DigestInit_ex(ctx, evp, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::nullopt;
    }

    const std::size_t BUF_SIZE = 16 * 1024;
    std::vector<char> buf(BUF_SIZE);
    while (ifs.good()) {
        ifs.read(buf.data(), static_cast<std::streamsize>(BUF_SIZE));
        std::streamsize read_bytes = ifs.gcount();
        if (read_bytes > 0) {
            if (EVP_DigestUpdate(ctx, buf.data(), static_cast<size_t>(read_bytes)) != 1) {
                EVP_MD_CTX_free(ctx);
                return std::nullopt;
            }
        }
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::nullopt;
    }

    std::string hex = bytes_to_hex(md_value, md_len);
    EVP_MD_CTX_free(ctx);
    return hex;
}

std::optional<std::string> YaraScanner::compute_md5_hex(const std::string& file_path) {
    return compute_file_digest_openssl(file_path, EVP_md5());
}
std::optional<std::string> YaraScanner::compute_sha1_hex(const std::string& file_path) {
    return compute_file_digest_openssl(file_path, EVP_sha1());
}
std::optional<std::string> YaraScanner::compute_sha256_hex(const std::string& file_path) {
    return compute_file_digest_openssl(file_path, EVP_sha256());
}

std::tuple<std::optional<std::string>, std::optional<std::string>, std::optional<std::string>>
YaraScanner::compute_all_hashes(const std::string& file_path) {
    auto md5 = compute_md5_hex(file_path);
    auto sha1 = compute_sha1_hex(file_path);
    auto sha256 = compute_sha256_hex(file_path);
    return {md5, sha1, sha256};
}

// --------------------------- Database helpers ----------------------------

bool YaraScanner::prepare_db_statements() {
    if (!db) return false;
    const char* sql_md5 = "SELECT malware_name FROM sig_md5 WHERE hash = ? LIMIT 1;";
    const char* sql_sha1 = "SELECT malware_name FROM sig_sha1 WHERE hash = ? LIMIT 1;";
    const char* sql_sha256 = "SELECT malware_name FROM sig_sha256 WHERE hash = ? LIMIT 1;";
    const char* sql_whitelist = "SELECT 1 FROM whitelist WHERE hash = ? AND hash_type = ? LIMIT 1;";

    if (sqlite3_prepare_v2(db, sql_md5, -1, &stmt_check_md5, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare MD5 statement: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    if (sqlite3_prepare_v2(db, sql_sha1, -1, &stmt_check_sha1, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare SHA1 statement: " << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt_check_md5);
        stmt_check_md5 = nullptr;
        return false;
    }
    if (sqlite3_prepare_v2(db, sql_sha256, -1, &stmt_check_sha256, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare SHA256 statement: " << sqlite3_errmsg(db) << "\n";
        sqlite3_finalize(stmt_check_md5);
        sqlite3_finalize(stmt_check_sha1);
        stmt_check_md5 = stmt_check_sha1 = nullptr;
        return false;
    }
    if (sqlite3_prepare_v2(db, sql_whitelist, -1,
                           &stmt_check_whitelist, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare whitelist statement: "
                  << sqlite3_errmsg(db) << "\n";
        return false;
    }
    return true;
}

void YaraScanner::finalize_db_statements() {
    if (stmt_check_md5) { sqlite3_finalize(stmt_check_md5); stmt_check_md5 = nullptr; }
    if (stmt_check_sha1) { sqlite3_finalize(stmt_check_sha1); stmt_check_sha1 = nullptr; }
    if (stmt_check_sha256) { sqlite3_finalize(stmt_check_sha256); stmt_check_sha256 = nullptr; }
    if (stmt_check_whitelist) { sqlite3_finalize(stmt_check_whitelist); stmt_check_whitelist = nullptr; }
}

bool YaraScanner::check_hash_whitelist(const std::string& hex_hash, const std::string& hash_type) {
    if (!db || !stmt_check_whitelist) return false;

    sqlite3_reset(stmt_check_whitelist);
    sqlite3_clear_bindings(stmt_check_whitelist);

    sqlite3_bind_text(stmt_check_whitelist, 1,
                      hex_hash.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt_check_whitelist, 2,
                      hash_type.c_str(), -1, SQLITE_TRANSIENT);

    return sqlite3_step(stmt_check_whitelist) == SQLITE_ROW;
}

bool YaraScanner::check_hash_in_db(const std::string& hex_hash, const std::string& hash_type, std::string& out_malware_name) {
    if (!db) return false;
    sqlite3_stmt* stmt = nullptr;
    if (hash_type == "MD5") stmt = stmt_check_md5;
    else if (hash_type == "SHA1") stmt = stmt_check_sha1;
    else if (hash_type == "SHA256") stmt = stmt_check_sha256;
    else return false;

    if (!stmt) return false;

    // Bind and execute
    if (sqlite3_reset(stmt) != SQLITE_OK) return false;
    if (sqlite3_clear_bindings(stmt) != SQLITE_OK) return false;

    if (sqlite3_bind_text(stmt, 1, hex_hash.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        return false;
    }

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* txt = sqlite3_column_text(stmt, 0);
        out_malware_name = txt ? reinterpret_cast<const char*>(txt) : "";
        return true;
    }
    return false;
}

// --------------------------- YARA callback --------------------------------

// YARA sends a rule match message; create Result and call the stored callback pointer.
static int rule_match_callback(YR_SCAN_CONTEXT* /*context*/, int message, void* message_data, void* user_data) {
    if (!user_data) return CALLBACK_CONTINUE;

    auto* ctx = static_cast<ScanContext*>(user_data);
    if (!ctx) return CALLBACK_CONTINUE;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(message_data);
        std::string id = (rule && rule->identifier) ? rule->identifier : "unknown";
        try {
            // Protect the vector from concurrent modifications.
            {
                std::lock_guard<std::mutex> lk(ctx->matches_mutex);
                ctx->matched_rules.push_back(id);
            }
            // Diagnostic: log each rule as it is observed to help trace misses.
            try {
                std::string fname = ctx->filename.empty() ? ctx->filepath : ctx->filename;
                // log_diag(std::string("rule_match_callback: matched rule='") + id + "' file='" + fname + "'");
            } catch (...) {
                // best-effort logging
            }
        } catch (...) {
            // Ignore allocation errors or lock failures; avoid aborting the scan.
        }
        return CALLBACK_CONTINUE;
    }

    if (message == CALLBACK_MSG_SCAN_FINISHED) {
        std::vector<std::string> matches_copy;
        {
            std::lock_guard<std::mutex> lk(ctx->matches_mutex);
            if (ctx->matched_rules.empty()) {
                try {
                    std::string fname = ctx->filename.empty() ? ctx->filepath : ctx->filename;
                } catch (...) {}
                return CALLBACK_CONTINUE;
            }
            matches_copy.swap(ctx->matched_rules); // fast clear + move out
        }

        Result r;
        r.isMalware = true;
        r.date = YaraScanner::currentDateTime();
        r.nameDesktop = YaraScanner::getComputerName();
        r.severity = "Warning";
        r.filename = ctx->filename;
        r.filepath = ctx->filepath;

        // If the scanner previously computed file digests, propagate them into
        // the Result so Python-side callers receive the MD5/SHA1/SHA256 values
        // when the detection was produced by YARA (no DB hash match).
        try {
            if (ctx->md5) r.md5 = *ctx->md5;
            if (ctx->sha1) r.sha1 = *ctx->sha1;
            if (ctx->sha256) r.sha256 = *ctx->sha256;
        } catch (...) {
            // best-effort: on any error leave hash fields empty
        }

        // Populate aggregation fields for consumers that inspect them.
        size_t count = matches_copy.size();
        r.matched_rules_count = static_cast<int>(count);
        r.matched_rules = matches_copy;

        // Build a concise description: include count and list of rule identifiers.
        r.desc = std::string("Matched by ") + std::to_string(count) + (count == 1 ? " rule: " : " rules: ");
        for (size_t i = 0; i < count; ++i) {
            if (i) r.desc += ", ";
            r.desc += matches_copy[i];
        }

        r.detection_source = "YARA";

        try {
            std::string fname = ctx->filename.empty() ? ctx->filepath : ctx->filename;
            std::string rules_list;
            for (size_t i = 0; i < matches_copy.size(); ++i) {
                if (i) rules_list += ", ";
                rules_list += matches_copy[i];
            }
        } catch (...) {}

        call_callback_if_python_ready(ctx->callback, r);

        return CALLBACK_CONTINUE;
    }

    return CALLBACK_CONTINUE;
}

// --------------------------- Construction / Destruction -------------------

YaraScanner::YaraScanner() = default;

YaraScanner::~YaraScanner() {
    shutdown();
}

// --------------------------- Init / Shutdown ------------------------------

bool YaraScanner::init(const std::string& rules_path, const std::string& db_path, ResultCallback status_callback) {
    // Notify loading start
    if (status_callback) {
        Result log_start;
        log_start.isMalware = false;
        log_start.date = currentDateTime();
        log_start.nameDesktop = getComputerName();
        log_start.severity = "NOTICE";
        log_start.desc = "Loading rules & database...";
        status_callback(log_start);
    }

    install_crash_handlers();

    // Initialize YARA library
    if (yr_initialize() != ERROR_SUCCESS) {
        if (status_callback) {
            Result err;
            err.isMalware = false;
            err.date = currentDateTime();
            err.nameDesktop = getComputerName();
            err.severity = "ERROR";
            err.desc = "YARA initialization failed";
            status_callback(err);
        }
        return false;
    }

    // Open DB
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        if (status_callback) {
            Result err;
            err.isMalware = false;
            err.date = currentDateTime();
            err.nameDesktop = getComputerName();
            err.severity = "ERROR";
            err.desc = std::string("Cannot open database: ") + sqlite3_errmsg(db);
            status_callback(err);
        }
        if (db) { sqlite3_close(db); db = nullptr; }
        // Finalize YARA since initialization succeeded earlier
        yr_finalize();
        return false;
    }

    // Prepare statements
    if (!prepare_db_statements()) {
        if (status_callback) {
            Result err;
            err.isMalware = false;
            err.date = currentDateTime();
            err.nameDesktop = getComputerName();
            err.severity = "ERROR";
            err.desc = "Failed to prepare DB statements";
            status_callback(err);
        }
        sqlite3_close(db);
        db = nullptr;
        // Finalize YARA since initialization succeeded earlier
        yr_finalize();
        return false;
    }

    // Load YARA rules
    if (status_callback) { Result r; r.isMalware=false; r.date=currentDateTime(); r.nameDesktop=getComputerName(); r.severity="NOTICE"; r.desc="Starting YARA rules load..."; status_callback(r); }

    int yr_rc = yr_rules_load(rules_path.c_str(), &rules);

    if (yr_rc == ERROR_SUCCESS) {
        if (status_callback) { Result r; r.isMalware=false; r.date=currentDateTime(); r.nameDesktop=getComputerName(); r.severity="NOTICE"; r.desc="YARA rules loaded successfully"; status_callback(r); }
    }
    if (yr_rc != ERROR_SUCCESS) {
        if (status_callback) {
            Result err;
            err.isMalware = false;
            err.date = currentDateTime();
            err.nameDesktop = getComputerName();
            err.severity = "ERROR";
            err.desc = std::string("Cannot load YARA rules: ") + rules_path;
            status_callback(err);
        }
        finalize_db_statements();
        sqlite3_close(db);
        db = nullptr;
        // Finalize YARA since initialization succeeded earlier
        yr_finalize();
        return false;
    }

    initialized = true;
    if (status_callback) {
        Result ok;
        ok.isMalware = false;
        ok.date = currentDateTime();
        ok.nameDesktop = getComputerName();
        ok.severity = "NOTICE";
        ok.desc = "Engine Ready (Rules + DB Loaded)";
        status_callback(ok);
    }
    return true;
}

void YaraScanner::shutdown() {
    log_diag("shutdown: begin");
    // Stop realtime first
    stop_realtime();

    // Free YARA rules
    if (rules) {
        yr_rules_destroy(rules);
        rules = nullptr;
    }

    // Finalize YARA library
    yr_finalize();

    // Finalize DB statements & close DB
    finalize_db_statements();
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }

    initialized = false;
    log_diag("shutdown: complete");
}

// ----------------------
// Progress accessors (exposed for UI polling)
// ----------------------
int YaraScanner::get_progress_percent() const {
    try {
        uint64_t t = total_count.load(std::memory_order_relaxed);
        uint64_t c = completed_count.load(std::memory_order_relaxed);
        if (t == 0) {
            // If total unknown but some work completed, provide a heuristic percentage (capped at 99)
            if (c == 0) return 0;
            return static_cast<int>(std::min<uint64_t>(99, c));
        }
        // compute percent safely
        uint64_t pct = (c * 100) / t;
        if (pct > 100) pct = 100;
        return static_cast<int>(pct);
    } catch (...) {
        return 0;
    }
}

uint64_t YaraScanner::get_completed_count() const {
    try {
        return completed_count.load(std::memory_order_relaxed);
    } catch (...) {
        return 0;
    }
}

uint64_t YaraScanner::get_total_count() const {
    try {
        return total_count.load(std::memory_order_relaxed);
    } catch (...) {
        return 0;
    }
}

std::pair<int, int> YaraScanner::get_progress_counts() const {
    try {
        uint64_t c = completed_count.load(std::memory_order_relaxed);
        uint64_t t = total_count.load(std::memory_order_relaxed);
        int ci = (c > INT32_MAX) ? INT32_MAX : static_cast<int>(c);
        int ti = (t > INT32_MAX) ? INT32_MAX : static_cast<int>(t);
        return {ci, ti};
    } catch (...) {
        return {-1, -1};
    }
}

void YaraScanner::reset_progress() {
    try {
        total_count.store(0, std::memory_order_relaxed);
        completed_count.store(0, std::memory_order_relaxed);
    } catch (...) {
        // ignore
    }
}


 // --------------------------- Scanning ------------------------------------

// Throttling settings
void YaraScanner::set_throttle_duty(double duty)
{
    // Accept only a sensible duty in (0.0, 1.0). A value <=0 disables throttling.
    if (duty <= 0.0 || duty >= 1.0) {
        throttle_duty_cycle = 0.0;
    } else {
        throttle_duty_cycle = duty;
    }
}

void YaraScanner::set_throttle_max_sleep_ms(int max_sleep_ms)
{
    if (max_sleep_ms < 0) max_sleep_ms = 0;
    throttle_max_sleep_ms = max_sleep_ms;
}

void YaraScanner::get_throttle_settings(double &out_duty, int &out_max_sleep_ms) const
{
    out_duty = throttle_duty_cycle;
    out_max_sleep_ms = throttle_max_sleep_ms;
}

void YaraScanner::set_full_scan(bool enabled)
{
    try {
        full_scan_override.store(enabled ? true : false);
    } catch (...) {
    }
}

bool YaraScanner::is_full_scan() const
{
    try {
        return full_scan_override.load();
    } catch (...) {
        return false;
    }
}


void YaraScanner::scan_file_internal(const std::string& file_path, ResultCallback& callback) {
    if (!initialized) return;

    std::string path_str = file_path;
    std::transform(path_str.begin(), path_str.end(), path_str.begin(), ::tolower);

    // Danh sách các từ khóa đường dẫn cần bỏ qua
    static const std::vector<std::string> excluded_keywords = {
        "c:\\programdata\\pbl4_av_data",
        "\\device\\",                     // Các thiết bị ảo
        "\\windows\\system32",
        "\\windows\\winsxs",
        "\\$recycle.bin",
        "system volume information",
        "\\appdata\\local\\temp",
        "node_modules",
        ".git",
        "all_rules.yarc",
        "full_hash.db",
        "PBL4_Client.exe"
    };

    for (const auto& keyword : excluded_keywords) {
        if (path_str.find(keyword) != std::string::npos) {
            // log_diag("Skipping excluded path: " + file_path);
            completed_count.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
    // ----------------------------------

    // Basic checks: file exists and is a regular file
    std::error_code ec;
    if (!fs::exists(file_path, ec) || !fs::is_regular_file(file_path, ec)) {
        return;
    }

    // Quick size and trust checks before acquiring global lock
    uint64_t file_size = 0;
    bool skip_by_size = false;
    try {
        file_size = static_cast<uint64_t>(fs::file_size(file_path, ec));
        skip_by_size = (file_size > UINT64_C(0) && file_size > MAX_FILE_SIZE_SKIP); // >500MB defined in header
    } catch (...) {
        // if we can't stat size, proceed conservatively
    }

    // If file too large, notify and skip (unless full-scan override is set)
    if (skip_by_size && !full_scan_override.load()) {
        if (callback) {
            Result r;
            r.isMalware = false;
            r.date = currentDateTime();
            r.nameDesktop = getComputerName();
            r.severity = "NOTICE";
            r.filename = fs::path(file_path).filename().string();
            r.filepath = file_path;
            r.desc = "Skipped: file too large (>500MB)";
            r.detection_source = "POLICY";
            // Pass owning scanner pointer so the helper can check callback enablement
            call_callback_if_python_ready(callback, r, this);
        }
        // Update progress counters for UI polling
        try {
            completed_count.fetch_add(1, std::memory_order_relaxed);
        } catch (...) {
            // ignore
        }
        return;
    }

    // If on Windows, verify code-signing trust for known publishers (quick allow-list)
    // If trusted, skip scanning (unless full-scan override is set)
    if (!full_scan_override.load() && check_trusted_publisher_and_skip(file_path)) {
        if (callback) {
            Result r;
            r.isMalware = false;
            r.date = currentDateTime();
            r.nameDesktop = getComputerName();
            r.severity = "NOTICE";
            r.filename = fs::path(file_path).filename().string();
            r.filepath = file_path;
            r.desc = "Skipped: trusted publisher signature";
            r.detection_source = "POLICY";
            // Pass owning scanner pointer so the helper can check callback enablement
            call_callback_if_python_ready(callback, r, this);
        }
        // Update progress counters for UI polling
        try {
            completed_count.fetch_add(1, std::memory_order_relaxed);
        } catch (...) {
            // ignore
        }
        return;
    }

    // Acquire lock for DB and YARA usage
    std::lock_guard<std::mutex> lock(scan_mutex);

    // 1) Compute hashes (these are used for DB lookup)
    auto [md5_opt, sha1_opt, sha256_opt] = compute_all_hashes(file_path);
    // --- WHITELIST CHECK (STOP HERE IF MATCH) ---
    if (!full_scan_override.load()) {

        if (
            (sha256_opt && check_hash_whitelist(*sha256_opt, "sha256")) ||
            (sha1_opt   && check_hash_whitelist(*sha1_opt, "sha1"))   ||
            (md5_opt    && check_hash_whitelist(*md5_opt, "md5"))
        ) {
            Result r;
            r.isMalware = false;
            r.date = currentDateTime();
            r.nameDesktop = getComputerName();
            r.filename = fs::path(file_path).filename().string();
            r.filepath = file_path;
            r.severity = "NOTICE";
            r.desc = "Skipped: hash whitelisted";
            r.detection_source = "WHITELIST";

            call_callback_if_python_ready(callback, r, this);
            completed_count.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }

    // 2) Check DB for any match. Prefer strongest first (sha256 -> sha1 -> md5)
    std::string malware_name;
    Result r_base;
    r_base.date = currentDateTime();
    r_base.nameDesktop = getComputerName();
    r_base.filename = fs::path(file_path).filename().string();
    r_base.filepath = file_path;

    if (sha256_opt) {
        std::string sha256 = *sha256_opt;
        if (check_hash_in_db(sha256, "SHA256", malware_name)) {
            r_base.isMalware = true;
            r_base.hash = sha256;
            r_base.hash_type = "SHA256";
            r_base.detection_source = "HASH";
            r_base.severity = "High";
            r_base.desc = "Matched SHA256 in DB";
            r_base.malware_name = malware_name;
            call_callback_if_python_ready(callback, r_base);
            return;
        }
    }
    if (sha1_opt) {
        std::string sha1 = *sha1_opt;
        if (check_hash_in_db(sha1, "SHA1", malware_name)) {
            r_base.isMalware = true;
            r_base.hash = sha1;
            r_base.hash_type = "SHA1";
            r_base.detection_source = "HASH";
            r_base.severity = "High";
            r_base.desc = "Matched SHA1 in DB";
            r_base.malware_name = malware_name;
            call_callback_if_python_ready(callback, r_base);
            return;
        }
    }
    if (md5_opt) {
        std::string md5 = *md5_opt;
        if (check_hash_in_db(md5, "MD5", malware_name)) {
            r_base.isMalware = true;
            r_base.hash = md5;
            r_base.hash_type = "MD5";
            r_base.detection_source = "HASH";
            r_base.severity = "High";
            r_base.desc = "Matched MD5 in DB";
            r_base.malware_name = malware_name;
            call_callback_if_python_ready(callback, r_base);
            return;
        }
    }

    // 3) No hash match -> proceed with YARA scanning following size-based policy
    if (!rules) {
        // YARA not loaded, nothing more to do here
        return;
    }

    try {
        // small files: scan full file
        if (file_size <= PARTIAL_FILE_MIN) {
            ScanContext ctx;
            ctx.callback = callback;
            ctx.owner = this;
            ctx.filepath = file_path;
            ctx.filename = r_base.filename;

            // Cache precomputed hashes on the ScanContext so the YARA callback can
            // include them in any Result it emits without re-reading the file.
            ctx.md5 = md5_opt;
            ctx.sha1 = sha1_opt;
            ctx.sha256 = sha256_opt;

            // Diagnostic: log that we're about to perform a full-file YARA scan.
            try {
                // log_diag(std::string("scan_file_internal: performing FULL YARA scan for: ") + file_path + " size=" + std::to_string(file_size));
            } catch (...) {}

            int scan_rc = yr_rules_scan_file(rules, file_path.c_str(), SCAN_FLAGS_FAST_MODE, rule_match_callback, &ctx, 0);
            // Diagnostic: log YARA return code
            try {
                if (scan_rc != ERROR_SUCCESS) {
                    // log_diag(std::string("scan_file_internal: yr_rules_scan_file returned rc=") + std::to_string(scan_rc) + " for: " + file_path);
                } else {
                    log_diag(std::string("scan_file_internal: yr_rules_scan_file completed for: ") + file_path);
                }
            } catch (...) {}

            if (scan_rc != ERROR_SUCCESS) {
                Result err;
                err.isMalware = false;
                err.date = currentDateTime();
                err.nameDesktop = getComputerName();
                err.severity = "ERROR";
                err.filename = r_base.filename;
                err.filepath = file_path;
                err.desc = "YARA full-file scan failed";
                call_callback_if_python_ready(callback, err);
            }
            return;
        }

        // medium files: sample prefix+suffix (4MB + 1MB)
        if (file_size > PARTIAL_FILE_MIN && file_size <= PARTIAL_FILE_MAX) {
            std::vector<uint8_t> prefix, suffix;
            if (!read_prefix_suffix(file_path, prefix, suffix)) {
                // read error -> notify and return
                Result err;
                err.isMalware = false;
                err.date = currentDateTime();
                err.nameDesktop = getComputerName();
                err.severity = "ERROR";
                err.filename = r_base.filename;
                err.filepath = file_path;
                err.desc = "Failed to read file segments for partial scan";
                callback(err);
                return;
            }

            // Combine prefix + suffix into single buffer for yara scanning
            std::vector<uint8_t> combined;
            combined.reserve(prefix.size() + suffix.size());
            combined.insert(combined.end(), prefix.begin(), prefix.end());
            combined.insert(combined.end(), suffix.begin(), suffix.end());

            // Diagnostic: log that we're about to perform a partial (prefix+suffix) YARA scan.
            try {
                // log_diag(std::string("scan_file_internal: performing PARTIAL YARA scan for: ") + file_path +
                //          " prefix=" + std::to_string(prefix.size()) + " suffix=" + std::to_string(suffix.size()) +
                //          " combined=" + std::to_string(combined.size()));
            } catch (...) {}

            // Create a ScanContext and call yr_rules_scan_mem
            ScanContext ctx;
            ctx.callback = callback;
            ctx.owner = this;
            ctx.filepath = file_path;
            ctx.filename = r_base.filename;

            // Propagate already-computed hashes into the context used by the
            // in-memory (prefix+suffix) YARA scan so detected results include them.
            ctx.md5 = md5_opt;
            ctx.sha1 = sha1_opt;
            ctx.sha256 = sha256_opt;

            int rc = yr_rules_scan_mem(rules, combined.data(), combined.size(), SCAN_FLAGS_FAST_MODE, rule_match_callback, &ctx, 0);
            try {
                if (rc != ERROR_SUCCESS) {
                    // log_diag(std::string("scan_file_internal: yr_rules_scan_mem returned rc=") + std::to_string(rc) + " for: " + file_path);
                } else {
                    log_diag(std::string("scan_file_internal: yr_rules_scan_mem completed for: ") + file_path);
                }
            } catch (...) {}

            if (rc != ERROR_SUCCESS) {
                Result err;
                err.isMalware = false;
                err.date = currentDateTime();
                err.nameDesktop = getComputerName();
                err.severity = "ERROR";
                err.filename = r_base.filename;
                err.filepath = file_path;
                err.desc = "YARA partial scan failed";
                call_callback_if_python_ready(callback, err);
            }
            return;
        }

        // fallback: skip (should be handled earlier)
    } catch (...) {
        Result err;
        err.isMalware = false;
        err.date = currentDateTime();
        err.nameDesktop = getComputerName();
        err.severity = "ERROR";
        err.filename = r_base.filename;
        err.filepath = file_path;
        err.desc = "Exception during scan operation";
        callback(err);
    }
}

void YaraScanner::scan_file(const std::string& file_path, ResultCallback callback) {
    if (!initialized) return;

    // Prepare progress counters for a single-file scan so UI can poll while work runs.
    try {
        total_count.store(1, std::memory_order_relaxed);
        completed_count.store(0, std::memory_order_relaxed);
    } catch (...) {
        // best-effort only
    }

    // Delegate to internal (thread-safety handled inside)
    scan_file_internal(file_path, callback);
}

void YaraScanner::scan_folder(const std::string& scan_path, ResultCallback callback) {
    if (!initialized) return;

    std::error_code ec;
    if (!fs::exists(scan_path, ec)) return;

    // Best-effort: count regular files first to provide a total for progress reporting.
    uint64_t total = 0;
    try {
        for (auto it_count = fs::recursive_directory_iterator(scan_path, fs::directory_options::skip_permission_denied, ec);
             it_count != fs::recursive_directory_iterator(); ++it_count) {
            if (ec) break;
            try {
                if (fs::is_regular_file(*it_count)) {
                    ++total;
                }
            } catch (...) {
                // ignore problematic entries
            }
        }
    } catch (...) {
        total = 0;
    }

    // Store totals (best-effort); reset completed count so polling starts from zero.
    try {
        total_count.store(total, std::memory_order_relaxed);
        completed_count.store(0, std::memory_order_relaxed);
    } catch (...) {
        // ignore
    }

    // Iterate recursively and scan
    for (auto it = fs::recursive_directory_iterator(scan_path, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it) {
        if (ec) break;
        try {
            if (fs::is_regular_file(*it)) {
                // Measure work start so we can apply a short sleep after each file to reduce duty-cycle.
                auto work_start = std::chrono::steady_clock::now();
                scan_file_internal(it->path().string(), callback);
                completed_count.fetch_add(1, std::memory_order_relaxed);
                // Apply time-slicing throttle to target ~50% duty-cycle between files.
                // max_sleep_ms is clamped to avoid excessive delays on long-running work.
                throttle_after_work(work_start, 0.5 /*50% duty*/, 500 /*max sleep ms*/, 2 /*min work ms*/);
            }
        } catch (...) {
            // ignore problematic files
        }
    }
}

// --------------------------- Realtime monitoring -------------------------

bool YaraScanner::start_realtime(const std::string& watch_path, ResultCallback callback) {
    log_diag(std::string("start_realtime: requested for path: ") + watch_path);

    // Prevent starting while stopping or already running.
    MonitorState expected = MonitorState::Stopped;
    if (!monitor_state.compare_exchange_strong(expected, MonitorState::Starting)) {
        // Already starting/running/stopping -> do not start again.
        log_diag("start_realtime: request ignored, monitor not in stopped state");
        return false;
    }

    {
        ResultCallback old_cb;
        {
            std::lock_guard<std::mutex> lk(this->callback_mutex);
            // take ownership of previous callback so destruction can be controlled
            old_cb = std::move(this->realtime_callback);
            // install new callback
            this->realtime_callback = callback;
            this->callbacks_enabled.store(true);
        }

        if (old_cb) {
            #ifndef Py_LIMITED_API
            if (Py_IsInitialized()) {
                PyGILState_STATE gstate = PyGILState_Ensure();
                old_cb = ResultCallback();
                PyGILState_Release(gstate);
            } else {
                old_cb = ResultCallback();
            }
            #else
            old_cb = ResultCallback();
            #endif
        }
    }
    monitoring.store(true);

    // Start worker thread that processes queued events (debounce + throttle)
    try {
        monitor_worker_thread = std::thread(&YaraScanner::monitor_worker_loop, this);
        log_diag("start_realtime: spawned monitor_worker_thread");
    } catch (const std::exception &e) {
        std::cerr << "start_realtime: failed to spawn monitor_worker_thread: " << e.what() << "\n";
        monitoring.store(false);
        monitor_state.store(MonitorState::Stopped);
        return false;
    } catch (...) {
        std::cerr << "start_realtime: unknown error spawning monitor_worker_thread\n";
        monitoring.store(false);
        monitor_state.store(MonitorState::Stopped);
        return false;
    }

#if defined(_WIN32)
    // On Windows use ReadDirectoryChangesW based watcher in separate thread
    try {
        monitor_thread = std::thread(&YaraScanner::windows_watcher_thread_func, this, watch_path);
        log_diag("start_realtime: spawned windows watcher thread");
    } catch (const std::exception &e) {
        std::cerr << "start_realtime: failed to spawn windows_watcher_thread_func: " << e.what() << "\n";
        // Attempt to clean up worker thread if it was started
        try {
            monitoring.store(false);
            if (monitor_worker_thread.joinable()) {
                log_diag("start_realtime: joining monitor_worker_thread due to failure");
                monitor_worker_thread.join();
            }
        } catch (...) { /* ignore cleanup errors */ }
        monitor_state.store(MonitorState::Stopped);
        return false;
    } catch (...) {
        std::cerr << "start_realtime: unknown error spawning windows watcher thread\n";
        try {
            monitoring.store(false);
            if (monitor_worker_thread.joinable()) {
                log_diag("start_realtime: joining monitor_worker_thread due to failure");
                monitor_worker_thread.join();
            }
        } catch (...) { /* ignore cleanup errors */ }
        monitor_state.store(MonitorState::Stopped);
        return false;
    }
#else
    // Fallback: use existing polling monitor loop (it will enqueue events)
    try {
        monitor_thread = std::thread(&YaraScanner::monitor_loop, this, watch_path);
        log_diag("start_realtime: spawned polling monitor thread");
    } catch (const std::exception &e) {
        std::cerr << "start_realtime: failed to spawn monitor_loop thread: " << e.what() << "\n";
        try {
            monitoring.store(false);
            if (monitor_worker_thread.joinable()) {
                log_diag("start_realtime: joining monitor_worker_thread due to failure");
                monitor_worker_thread.join();
            }
        } catch (...) { /* ignore */ }
        monitor_state.store(MonitorState::Stopped);
        return false;
    } catch (...) {
        std::cerr << "start_realtime: unknown error spawning monitor loop thread\n";
        try {
            monitoring.store(false);
            if (monitor_worker_thread.joinable()) {
                log_diag("start_realtime: joining monitor_worker_thread due to failure");
                monitor_worker_thread.join();
            }
        } catch (...) { /* ignore */ }
        monitor_state.store(MonitorState::Stopped);
        return false;
    }
#endif

    // Now fully running
    monitor_state.store(MonitorState::Running);
    log_diag("start_realtime: monitoring started");
    return true;
}

void YaraScanner::stop_realtime() {
    log_diag("stop_realtime: requested");

    // Attempt to transition to stopping state; if not running, ensure flags cleared and return.
    MonitorState expected = MonitorState::Running;
    if (!monitor_state.compare_exchange_strong(expected, MonitorState::Stopping)) {
        // If we weren't running, clear monitoring and wake worker then return.
        log_diag("stop_realtime: monitor not in Running state; clearing flags and returning");
        monitoring.store(false);
        {
            std::lock_guard<std::mutex> lk(queue_mutex);
            queue_cv.notify_all();
        }
        return;
    }

    // Signal threads to stop and wake worker
    monitoring.store(false);
    {
        std::lock_guard<std::mutex> lk(queue_mutex);
        queue_cv.notify_all();
    }

    // Disable callbacks and clear stored realtime callback early so that no new callbacks are invoked
    // while we are shutting down threads. This prevents races where a watcher
    // thread may enqueue or attempt to invoke the callback after stop was
    // requested but before threads have fully joined.
    {
        // Move the stored callback out while holding the mutex so we can destroy it
        // under the Python GIL. Also mark callbacks disabled before destruction.
        ResultCallback old_cb;
        {
            std::lock_guard<std::mutex> lk(this->callback_mutex);
            this->callbacks_enabled.store(false);
            old_cb = std::move(realtime_callback);
            realtime_callback = ResultCallback();
        }

        if (old_cb) {
            // If Python is initialized, ensure we hold the GIL while destroying Python-backed objects.
            #ifndef Py_LIMITED_API
            if (Py_IsInitialized()) {
                PyGILState_STATE gstate = PyGILState_Ensure();
                old_cb = ResultCallback(); // destruction under GIL
                PyGILState_Release(gstate);
            } else {
                // Python not initialized - destroy without GIL (best-effort)
                old_cb = ResultCallback();
            }
            #else
            old_cb = ResultCallback();
            #endif
        }
    }
    log_diag("stop_realtime: realtime_callback cleared");

#if defined(_WIN32)
    // Cancel any pending IO on watchers associated with this scanner so blocked
    // ReadDirectoryChangesW calls return promptly. Use the per-instance helper.
    try {
        this->stop_windows_watcher();
    } catch (...) {
        // swallow errors during stop
    }
#endif

    // Join watcher thread
    if (monitor_thread.joinable()) {
        try {
            log_diag("stop_realtime: joining monitor_thread");
            monitor_thread.join();
            log_diag("stop_realtime: monitor_thread joined");
        } catch (const std::exception &e) {
            std::cerr << "stop_realtime: exception joining monitor_thread: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "stop_realtime: unknown exception joining monitor_thread" << std::endl;
        }
    }

    // Join worker thread
    if (monitor_worker_thread.joinable()) {
        try {
            log_diag("stop_realtime: joining monitor_worker_thread");
            monitor_worker_thread.join();
            log_diag("stop_realtime: monitor_worker_thread joined");
        } catch (const std::exception &e) {
            std::cerr << "stop_realtime: exception joining monitor_worker_thread: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "stop_realtime: unknown exception joining monitor_worker_thread" << std::endl;
        }
    }

    // Clear any pending queued state to ensure a clean restart.
    {
        std::lock_guard<std::mutex> lk(queue_mutex);
        path_queue.clear();
        last_event_time.clear();
    }

    // Mark fully stopped
    monitor_state.store(MonitorState::Stopped);
    log_diag("stop_realtime: completed, state STOPPED");
}

void YaraScanner::monitor_loop(std::string path) {
    log_diag(std::string("monitor_loop: starting poller for path: ") + path);
    // Simple polling implementation: list files by last_write_time and scan newly created/modified files.

    std::unordered_map<std::string, std::filesystem::file_time_type> seen;
    std::error_code ec;

    // Initialize state
    for (auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) break;
        if (fs::is_regular_file(entry.path(), ec)) {
            seen[entry.path().string()] = fs::last_write_time(entry.path(), ec);
        }
    }

    while (monitoring.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        for (auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            if (!fs::is_regular_file(entry.path(), ec)) continue;
            auto p = entry.path().string();
            std::filesystem::file_time_type mtime;
            try {
                mtime = fs::last_write_time(entry.path(), ec);
            } catch (...) {
                continue;
            }
            auto it = seen.find(p);
            if (it == seen.end()) {
                // new file
                seen[p] = mtime;
                // copy callback to local to avoid illegal reference to member in some contexts
                ResultCallback cb;
                {
                    std::lock_guard<std::mutex> lk(this->callback_mutex);
                    cb = this->realtime_callback;
                }
                if (cb) {
                    log_diag(std::string("monitor_loop: detected new file -> scanning: ") + p);
                    scan_file_internal(p, cb);
                }
            } else {
                if (mtime != it->second) {
                    // modified
                    it->second = mtime;
                    std::cerr << "monitor_loop: modified file detected: " << p << "\n";
                    ResultCallback cb;
                    {
                        std::lock_guard<std::mutex> lk(this->callback_mutex);
                        cb = realtime_callback;
                    }
                    if (cb) {
                        // Wrap the original callback so we check callbacks_enabled and Python runtime
                        ResultCallback guarded_cb = [cb, this](const Result& r) {
                            call_callback_if_python_ready(cb, r, this);
                        };
                        scan_file_internal(p, guarded_cb);
                    }
                }
            }
        }
        // Remove deleted files from 'seen'
        std::vector<std::string> to_erase;
        for (auto& kv : seen) {
            if (!fs::exists(kv.first, ec)) {
                to_erase.push_back(kv.first);
            }
        }
        for (auto& k : to_erase) seen.erase(k);
    }
    log_diag("monitor_loop: exiting poller");
}
