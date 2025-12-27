#include "QuarantineManager.h"

#include <sqlite3.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>

#include <filesystem>

namespace fs = std::filesystem;

namespace pbl4 { namespace av {

const std::vector<uint8_t> QuarantineManager::DEFAULT_XOR_KEY = {
    0xAA, 0x55, 0xC3, 0x7E, 0x9A, 0x1F, 0xB6, 0x4D
};

QuarantineManager::QuarantineManager(const std::string &db_path, const std::string &quarantine_folder)
    : db_path_(db_path), quarantine_folder_(quarantine_folder), db_handle_(nullptr) {
}

QuarantineManager::~QuarantineManager() {
    shutdown();
}

void QuarantineManager::shutdown() {
    std::lock_guard<std::mutex> g(lock_);
    if (db_handle_) {
        sqlite3_close(db_handle_);
        db_handle_ = nullptr;
    }
}

bool QuarantineManager::open_db(std::string& out_error) {
    if (db_handle_) return true;
    int rc = sqlite3_open_v2(db_path_.c_str(), &db_handle_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        out_error = std::string("Failed to open DB: ") + sqlite3_errmsg(db_handle_);
        if (db_handle_) { sqlite3_close(db_handle_); db_handle_ = nullptr; }
        return false;
    }
    // Set a busy timeout so SQLite will wait for a short period when the DB is
    // locked by another connection instead of immediately failing with
    // "database is locked".
    sqlite3_busy_timeout(db_handle_, 5000);
    return true;
}

void QuarantineManager::close_db() {
    if (db_handle_) {
        sqlite3_close(db_handle_);
        db_handle_ = nullptr;
    }
}

std::string QuarantineManager::get_db_info_value(const std::string &key, const std::string &default_val) {
    if (!db_handle_) return default_val;
    sqlite3_stmt *stmt = nullptr;
    const char *sql = "SELECT value FROM db_info WHERE key = ? LIMIT 1;";
    if (sqlite3_prepare_v2(db_handle_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return default_val;
    }
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    std::string result = default_val;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text) result = reinterpret_cast<const char*>(text);
    }
    sqlite3_finalize(stmt);
    return result;
}

bool QuarantineManager::ensure_quarantine_folder_exists(std::string& out_error) {
    try {
        fs::path folder(quarantine_folder_);
        if (!fs::exists(folder)) {
            fs::create_directories(folder);
        }
        return true;
    } catch (const std::exception &e) {
        out_error = std::string("Failed to ensure quarantine folder exists: ") + e.what();
        return false;
    }
}

std::uint64_t QuarantineManager::get_free_space_bytes(std::string& out_error) {
    try {
        // Use filesystem::space which is cross-platform
        fs::path p(quarantine_folder_);
        // If folder doesn't exist yet, check the root of its path
        fs::path check_path = p;
        while (!check_path.empty() && !fs::exists(check_path)) {
            check_path = check_path.parent_path();
        }
        if (check_path.empty()) check_path = p.root_path();
        auto s = fs::space(check_path);
        return static_cast<std::uint64_t>(s.available);
    } catch (const std::exception &e) {
        out_error = std::string("Failed to get free space: ") + e.what();
        return 0;
    }
}

std::uint64_t QuarantineManager::get_total_quarantine_bytes(std::string& out_error) {
    if (!db_handle_) { out_error = "DB not open"; return 0; }
    std::string val = get_db_info_value("quarantine_total_size", "");
    if (!val.empty()) {
        try {
            return static_cast<std::uint64_t>(std::stoull(val));
        } catch (...) {
        }
    }
    // Fallback: compute folder size on disk
    try {
        std::uint64_t total = 0;
        for (auto &p : fs::directory_iterator(quarantine_folder_)) {
            if (fs::is_regular_file(p.path())) {
                total += static_cast<std::uint64_t>(fs::file_size(p.path()));
            }
        }
        return total;
    } catch (const std::exception &e) {
        out_error = std::string("Failed to compute quarantine folder size: ") + e.what();
        return 0;
    }
}

bool QuarantineManager::is_supported_hash_type(const std::string& hash_type) {
    return (hash_type == "md5" || hash_type == "sha1" || hash_type == "sha256");
}

bool QuarantineManager::compute_hash(const fs::path &file_path, std::string &out_hash, const std::string &hash_type, std::string &out_error) {
    if (!is_supported_hash_type(hash_type)) {
        out_error = "Unsupported hash type";
        return false;
    }

    const EVP_MD *md = nullptr;
    if (hash_type == "md5") md = EVP_md5();
    else if (hash_type == "sha1") md = EVP_sha1();
    else md = EVP_sha256();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        out_error = "Failed to create EVP_MD_CTX";
        return false;
    }
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        out_error = "EVP_DigestInit_ex failed";
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) {
        out_error = "Failed to open file for hashing";
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    std::vector<char> buf(8192);
    while (ifs.good()) {
        ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize r = ifs.gcount();
        if (r > 0) {
            if (EVP_DigestUpdate(mdctx, buf.data(), static_cast<size_t>(r)) != 1) {
                out_error = "EVP_DigestUpdate failed";
                EVP_MD_CTX_free(mdctx);
                return false;
            }
        }
    }
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        out_error = "EVP_DigestFinal_ex failed";
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < md_len; ++i) {
        oss << std::setw(2) << static_cast<int>(md_value[i]);
    }
    out_hash = oss.str();
    return true;
}

std::uint64_t QuarantineManager::file_size_bytes(const std::string &path) {
    try {
        return static_cast<std::uint64_t>(fs::file_size(path));
    } catch (...) {
        return 0;
    }
}

std::string QuarantineManager::make_unique_stored_filename(const fs::path& original_path) {
    // Compose: timestamp + random + original filename
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::random_device rd;
    std::mt19937_64 gen(rd());
    uint64_t r = gen();
    std::ostringstream oss;
    oss << ms << "_" << std::hex << r << "_" << original_path.filename().string();
    std::string s = oss.str();
    // Replace problematic chars
    std::replace(s.begin(), s.end(), ':', '_');
    std::replace(s.begin(), s.end(), '\\', '_');
    std::replace(s.begin(), s.end(), '/', '_');
    return s;
}

bool QuarantineManager::xor_transform_file(const fs::path& src, const fs::path& dst, std::uint64_t& out_bytes_written, std::string& out_error) {
    out_bytes_written = 0;
    try {
        std::ifstream ifs(src, std::ios::binary);
        if (!ifs) {
            out_error = "Failed to open source file for XOR transform";
            return false;
        }
        // ensure parent exists
        if (dst.has_parent_path()) fs::create_directories(dst.parent_path());
        std::ofstream ofs(dst, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            out_error = "Failed to open destination file for XOR transform";
            return false;
        }
        const std::vector<uint8_t>& key = QuarantineManager::DEFAULT_XOR_KEY;
        size_t keylen = key.size();
        std::vector<char> buf(64 * 1024);
        std::uint64_t total = 0;
        size_t kpos = 0;
        while (ifs.good()) {
            ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize r = ifs.gcount();
            if (r <= 0) break;
            for (std::streamsize i = 0; i < r; ++i) {
                uint8_t b = static_cast<uint8_t>(buf[i]);
                uint8_t xb = static_cast<uint8_t>(b ^ key[kpos]);
                buf[i] = static_cast<char>(xb);
                kpos = (kpos + 1) % keylen;
            }
            ofs.write(buf.data(), r);
            total += static_cast<std::uint64_t>(r);
        }
        ofs.flush();
        out_bytes_written = total;
        return true;
    } catch (const std::exception &e) {
        out_error = std::string("XOR transform failed: ") + e.what();
        return false;
    }
}

bool QuarantineManager::insert_whitelist_db(const std::string &hash,
                                            const std::string &hash_type,
                                            const std::string &note,
                                            std::string &out_error) {
    if (!db_handle_) { out_error = "DB not open"; return false; }
    const char *sql = "INSERT OR REPLACE INTO whitelist(hash, hash_type, note) VALUES(?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_handle_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        out_error = std::string("DB prepare failed: ") + sqlite3_errmsg(db_handle_);
        return false;
    }
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hash_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, note.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        out_error = std::string("DB insert whitelist failed: ") + sqlite3_errmsg(db_handle_);
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

bool QuarantineManager::insert_quarantine_record(const std::string &stored_filename,
                                                 const std::string &original_full_path,
                                                 const std::string &original_name,
                                                 uint64_t stored_size,
                                                 const std::string &original_hash) {
    if (!db_handle_) return false;
    // Insert according to new schema: stored_size and original_hash are stored; quarantined_at default is used.
    const char *sql =
        "INSERT INTO quarantine_files (original_path, stored_filename, stored_path, stored_size, quarantined_at, original_hash, hash_type, deleted) "
        "VALUES (?1, ?2, ?3, ?4, datetime('now'), ?5, 'sha256', 0);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_handle_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, original_full_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, stored_filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, quarantine_folder_.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(stored_size));
    sqlite3_bind_text(stmt, 5, original_hash.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = false;
    if (sqlite3_step(stmt) == SQLITE_DONE) ok = true;
    sqlite3_finalize(stmt);
    return ok;
}

bool QuarantineManager::remove_quarantine_record_by_id(int record_id, std::string& out_error) {
    if (!db_handle_) { out_error = "DB not open"; return false; }
    // Query stored path/filename to unlink the file first
    const char *sel = "SELECT stored_path, stored_filename FROM quarantine_files WHERE id = ?1;";
    sqlite3_stmt *sstmt = nullptr;
    if (sqlite3_prepare_v2(db_handle_, sel, -1, &sstmt, nullptr) != SQLITE_OK) {
        out_error = sqlite3_errmsg(db_handle_);
        return false;
    }
    sqlite3_bind_int(sstmt, 1, record_id);
    std::string stored_path, stored_filename;
    bool found = false;
    if (sqlite3_step(sstmt) == SQLITE_ROW) {
        const unsigned char *p0 = sqlite3_column_text(sstmt, 0);
        const unsigned char *p1 = sqlite3_column_text(sstmt, 1);
        if (p0) stored_path = reinterpret_cast<const char*>(p0);
        if (p1) stored_filename = reinterpret_cast<const char*>(p1);
        found = true;
    }
    sqlite3_finalize(sstmt);
    if (!found) {
        out_error = "Quarantine record not found";
        return false;
    }
    fs::path fp = fs::path(stored_path) / stored_filename;
    // Remove the file on disk if present
    try {
        if (fs::exists(fp)) {
            fs::remove(fp);
        }
    } catch (const std::exception &e) {
        // Continue to delete DB record even if unlink failed; but report
        out_error = std::string("Failed to remove quarantined file: ") + e.what();
        // we will proceed to delete DB row
    }
    const char *del = "DELETE FROM quarantine_files WHERE id = ?1;";
    sqlite3_stmt *dstmt = nullptr;
    if (sqlite3_prepare_v2(db_handle_, del, -1, &dstmt, nullptr) != SQLITE_OK) {
        out_error = sqlite3_errmsg(db_handle_);
        return false;
    }
    sqlite3_bind_int(dstmt, 1, record_id);
    bool ok = false;
    if (sqlite3_step(dstmt) == SQLITE_DONE) ok = true;
    sqlite3_finalize(dstmt);
    return ok;
}

bool QuarantineManager::prune_quarantine_to_fit(uint64_t required_bytes, uint64_t folder_limit_bytes) {
    // Deprecated: not used. Use prune_quarantine_if_needed instead.
    (void)required_bytes;
    (void)folder_limit_bytes;
    return false;
}

bool QuarantineManager::prune_quarantine_if_needed(std::uint64_t needed_bytes,
                                                   std::uint64_t& out_freed_bytes,
                                                   std::string& out_action_details,
                                                   std::string& out_error) {
    out_freed_bytes = 0;
    if (needed_bytes == 0) {
        out_action_details = "No pruning needed";
        return true;
    }
    if (!db_handle_) { out_error = "DB not open"; return false; }

    // We'll iterate selecting oldest non-deleted entries.
    const char *sel = "SELECT id, stored_filename, stored_path, stored_size FROM quarantine_files WHERE deleted = 0 ORDER BY quarantined_at ASC;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_handle_, sel, -1, &stmt, nullptr) != SQLITE_OK) {
        out_error = sqlite3_errmsg(db_handle_);
        return false;
    }

    std::vector<int> to_delete_ids;
    std::vector<uint64_t> to_delete_sizes;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        sqlite3_int64 sz = sqlite3_column_int64(stmt, 3);
        to_delete_ids.push_back(id);
        to_delete_sizes.push_back(static_cast<uint64_t>(sz));
        out_freed_bytes += static_cast<uint64_t>(sz);
        if (out_freed_bytes >= needed_bytes) break;
    }
    sqlite3_finalize(stmt);

    if (out_freed_bytes < needed_bytes) {
        out_error = "Not enough reclaimable space in quarantine to satisfy request";
        return false;
    }

    // Delete collected entries
    uint64_t actually_freed = 0;
    for (size_t i = 0; i < to_delete_ids.size(); ++i) {
        int id = to_delete_ids[i];
        uint64_t sz = to_delete_sizes[i];
        std::string ierr;
        bool ok = remove_quarantine_record_by_id(id, ierr);
        if (!ok) {
            // If remove failed, continue but note it
            out_action_details += std::string("Failed to remove record id ") + std::to_string(id) + ": " + ierr + "; ";
        } else {
            actually_freed += sz;
        }
    }
    std::ostringstream oss;
    oss << "Pruned quarantine, freed_bytes=" << actually_freed;
    out_action_details = oss.str();
    return true;
}

std::string QuarantineManager::quarantine(const std::string &file_path) {
    std::lock_guard<std::mutex> g(lock_);
    std::string err;
    if (!open_db(err)) {
        return std::string("ERROR: Cannot open DB: ") + err;
    }
    // Read config from DB (or use defaults)
    std::string folder = get_db_info_value("quarantine_folder_path", quarantine_folder_);
    if (!folder.empty()) quarantine_folder_ = folder;
    std::string folder_limit_str = get_db_info_value("quarantine_folder_limit_bytes", std::to_string(DEFAULT_QUARANTINE_FOLDER_LIMIT_BYTES));
    std::string safe_free_str = get_db_info_value("quarantine_safe_free_bytes", std::to_string(DEFAULT_SAFE_FREE_BYTES));

    uint64_t folder_limit = DEFAULT_QUARANTINE_FOLDER_LIMIT_BYTES;
    uint64_t safe_free = DEFAULT_SAFE_FREE_BYTES;
    try { folder_limit = static_cast<uint64_t>(std::stoull(folder_limit_str)); } catch(...) {}
    try { safe_free = static_cast<uint64_t>(std::stoull(safe_free_str)); } catch(...) {}

    // Ensure folder exists
    if (!ensure_quarantine_folder_exists(err)) {
        return std::string("ERROR: ") + err;
    }

    // Check free disk space on volume
    std::string gap_err;
    uint64_t free_bytes = get_free_space_bytes(gap_err);
    if (!gap_err.empty()) {
        // Non-fatal; continue but report on error when needed
    }

    // File size
    uint64_t orig_size = file_size_bytes(file_path);
    if (orig_size == 0) {
        // Could be zero or file missing
        if (!fs::exists(file_path)) {
            return std::string("ERROR: File not found: ") + file_path;
        }
    }

    // Emergency delete case
    if (free_bytes < safe_free) {
        // Delete original file and return EMERGENCY_DELETED
        try {
            fs::remove(file_path);
            std::ostringstream oss;
            oss << "EMERGENCY_DELETED: free_bytes(" << free_bytes << ") < safe_threshold(" << safe_free << "), deleted " << file_path;
            return oss.str();
        } catch (const std::exception &e) {
            return std::string("ERROR: failed to delete file in emergency: ") + e.what();
        }
    }

    // Determine current quarantine total
    uint64_t current_quarantine_total = get_total_quarantine_bytes(err);

    // stored_size will be same as original_size for XOR transform
    uint64_t stored_size = orig_size;

    // If quarantining would exceed folder limit, prune
    if (current_quarantine_total + stored_size > folder_limit) {
        uint64_t needed = (current_quarantine_total + stored_size) - folder_limit;
        uint64_t freed = 0;
        std::string action_details;
        std::string perr;
        bool pr_ok = prune_quarantine_if_needed(needed, freed, action_details, perr);
        if (!pr_ok) {
            return std::string("ERROR: Unable to make room in quarantine: ") + perr;
        }
        // After pruning, attempt to quarantine
        std::string stored_name = make_unique_stored_filename(fs::path(file_path));
        fs::path dest = fs::path(quarantine_folder_) / stored_name;
        std::uint64_t bytes_written = 0;
        std::string xerr;
        if (!xor_transform_file(fs::path(file_path), dest, bytes_written, xerr)) {
            return std::string("ERROR: Failed to move file to quarantine: ") + xerr;
        }
        // Insert DB record
        std::string hash;
        std::string herr;
        if (!compute_hash(dest, hash, "sha256", herr)) {
            // compute hash on dest may still fail; continue storing but note
            hash = "";
        }
        bool ok = insert_quarantine_record(stored_name, file_path, fs::path(file_path).filename().string(), bytes_written, hash);
        // Remove original file after successfully storing
        try { fs::remove(file_path); } catch(...) {}
        std::ostringstream oss;
        oss << "PRUNED_AND_QUARANTINED: freed=" << freed << " bytes; stored_as=" << dest.string();
        return oss.str();
    } else {
        // Enough room -> normal quarantine
        std::string stored_name = make_unique_stored_filename(fs::path(file_path));
        fs::path dest = fs::path(quarantine_folder_) / stored_name;
        std::uint64_t bytes_written = 0;
        std::string xerr;
        if (!xor_transform_file(fs::path(file_path), dest, bytes_written, xerr)) {
            return std::string("ERROR: Failed to move file to quarantine: ") + xerr;
        }
        std::string hash;
        std::string herr;
        if (!compute_hash(dest, hash, "sha256", herr)) {
            hash = "";
        }
        bool ok = insert_quarantine_record(stored_name, file_path, fs::path(file_path).filename().string(), bytes_written, hash);
        // Attempt to remove original file
        try { fs::remove(file_path); } catch(...) {}
        std::ostringstream oss;
        if (ok) {
            oss << "QUARANTINED: stored_as=" << dest.string();
            return oss.str();
        } else {
            // DB insert failed; remove stored file to avoid orphan
            try { if (fs::exists(dest)) fs::remove(dest); } catch(...) {}
            // Include sqlite error message when available to aid debugging
            std::string db_err = "unknown";
            try {
                if (db_handle_) {
                    const char *msg = sqlite3_errmsg(db_handle_);
                    if (msg) db_err = std::string(msg);
                }
            } catch (...) {
                // ignore any failure while attempting to read sqlite error
            }
            return std::string("ERROR: Failed to record quarantine in DB: ") + db_err;
        }
    }
}

std::string QuarantineManager::whitelist(const std::string &file_path) {
    std::lock_guard<std::mutex> g(lock_);
    std::string err;
    if (!open_db(err)) {
        return std::string("ERROR: Open DB failed: ") + err;
    }
    if (!fs::exists(file_path)) {
        return std::string("ERROR: File not found: ") + file_path;
    }
    std::string hash;
    std::string herr;
    if (!compute_hash(fs::path(file_path), hash, "sha256", herr)) {
        return std::string("ERROR: Hash computation failed: ") + herr;
    }
    std::string ierr;
    if (!insert_whitelist_db(hash, "sha256", file_path, ierr)) {
        return std::string("ERROR: Failed to insert whitelist: ") + ierr;
    }
    std::ostringstream oss;
    oss << "WHITELISTED: sha256=" << hash;
    return oss.str();
}

std::string QuarantineManager::restore(const std::string &stored_name_or_path) {
    std::lock_guard<std::mutex> g(lock_);
    std::string err;
    if (!open_db(err)) {
        return std::string("ERROR: Open DB failed: ") + err;
    }
    // Determine stored filename and stored path
    fs::path provided(stored_name_or_path);
    std::string search_name = provided.filename().string();
    // Query for the record by stored_filename or by composed path
    const char *sel = "SELECT id, stored_path, stored_filename, original_path, stored_size FROM quarantine_files WHERE stored_filename = ?1 OR (stored_path || '/' || stored_filename) = ?2 LIMIT 1;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_handle_, sel, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::string("ERROR: DB prepare failed: ") + sqlite3_errmsg(db_handle_);
    }
    sqlite3_bind_text(stmt, 1, search_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, stored_name_or_path.c_str(), -1, SQLITE_TRANSIENT);
    bool found = false;
    int record_id = -1;
    std::string stored_path, stored_filename, original_path;
    sqlite3_int64 stored_size = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        record_id = sqlite3_column_int(stmt, 0);
        const unsigned char *p1 = sqlite3_column_text(stmt, 1);
        const unsigned char *p2 = sqlite3_column_text(stmt, 2);
        const unsigned char *p3 = sqlite3_column_text(stmt, 3);
        if (p1) stored_path = reinterpret_cast<const char*>(p1);
        if (p2) stored_filename = reinterpret_cast<const char*>(p2);
        if (p3) original_path = reinterpret_cast<const char*>(p3);
        stored_size = sqlite3_column_int64(stmt, 4);
        found = true;
    }
    sqlite3_finalize(stmt);
    if (!found) {
        return std::string("ERROR: Quarantined file not found: ") + stored_name_or_path;
    }

    fs::path src = fs::path(stored_path) / stored_filename;
    if (!fs::exists(src)) {
        return std::string("ERROR: Quarantined file missing on disk: ") + src.string();
    }

    // Restore to original path (attempt)
    fs::path dest = fs::path(original_path);
    // Ensure dest parent exists
    try {
        if (dest.has_parent_path()) fs::create_directories(dest.parent_path());
    } catch (const std::exception &e) {
        return std::string("ERROR: Failed to create destination directories: ") + e.what();
    }

    // Decode XOR from src -> dest
    std::uint64_t written = 0;
    std::string xerr;
    // We will perform XOR transform again since XOR is symmetric
    if (!xor_transform_file(src, dest, written, xerr)) {
        return std::string("ERROR: Failed to decode and restore file: ") + xerr;
    }

    // Compute hash and insert whitelist
    std::string hash;
    std::string herr;
    if (!compute_hash(dest, hash, "sha256", herr)) {
        // Non-fatal; continue but no whitelist added
        hash = "";
    } else {
        std::string ierr;
        insert_whitelist_db(hash, "sha256", dest.string(), ierr);
        (void)ierr;
    }

    // Mark record as restored
    const char *upd = "UPDATE quarantine_files SET restored = 1, restored_at = datetime('now'), restored_path = ?1 WHERE id = ?2;";
    sqlite3_stmt *ust = nullptr;
    if (sqlite3_prepare_v2(db_handle_, upd, -1, &ust, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(ust, 1, dest.string().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(ust, 2, record_id);
        sqlite3_step(ust);
    }
    sqlite3_finalize(ust);

    // Return success message and attempt to remove the quarantined file from disk.
    std::ostringstream oss;
    oss << "RESTORED: " << dest.string();
    if (!hash.empty()) oss << " sha256=" << hash;

    try {
        // Attempt to remove the stored quarantined file; non-fatal if it fails.
        fs::remove(src);
    } catch (const std::exception &e) {
        // Append a warning to the returned message so callers are aware the stored file
        // could not be deleted even though restoration succeeded.
        oss << " WARNING: Failed to remove quarantined file: ";
        oss << e.what();
    } catch (...) {
        // Unknown error; include generic warning.
        oss << " WARNING: Failed to remove quarantined file: unknown error";
    }

    return oss.str();
}

} } // namespace av, pbl4
