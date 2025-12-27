#ifndef PBL4_CPP_QUARANTINEMANAGER_H
#define PBL4_CPP_QUARANTINEMANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <filesystem>
#include <cstdint>
#include <optional>

struct sqlite3;
struct sqlite3_stmt;

namespace pbl4 {
namespace av {

class QuarantineManager {
public:
    static constexpr const char* DEFAULT_QUARANTINE_FOLDER = "C:/ProgramData/PBL4_AV_DATA/Quarantine";
    static constexpr std::uint64_t DEFAULT_QUARANTINE_FOLDER_LIMIT_BYTES = 524288000ULL; // 500 * 1024 * 1024
    static constexpr std::uint64_t DEFAULT_SAFE_FREE_BYTES = 104857600ULL; // 100 * 1024 * 1024

    explicit QuarantineManager(const std::string& db_path,
                               const std::string& quarantine_folder = DEFAULT_QUARANTINE_FOLDER);

    ~QuarantineManager();

    // Initialize resources (open DB, ensure quarantine folder exists). Returns true on success.
    bool init(std::string& out_error);

    // Quarantine a file. Returns a human-readable result string describing the outcome.
    // The method implements the 3 cases described:
    //  - Enough free disk space -> normal quarantine.
    //  - Free disk >= safe threshold but quarantine would exceed folder limit -> prune oldest entries then quarantine.
    //  - Free disk < safe threshold -> emergency delete; do not quarantine.
    std::string quarantine(const std::string& file_path);

    // Compute a hash for the provided file and add to whitelist table.
    // (Implementation currently computes sha256 and stores it.)
    // Returns a human-readable result string (e.g. "WHITELISTED: sha256=<hash>").
    std::string whitelist(const std::string& file_path);

    // Restore a quarantined file back to original path (or requested path).
    // The argument may be the stored filename inside quarantine folder or full path to stored file.
    // On successful restore, the file will be decoded (XOR) and written back, and the hash added to whitelist.
    // Returns a human-readable result string.
    std::string restore(const std::string& stored_filename_or_path);

    // Close and release resources.
    void shutdown();

private:
    // Non-copyable
    QuarantineManager(const QuarantineManager&) = delete;
    QuarantineManager& operator=(const QuarantineManager&) = delete;

    // Internal helpers (implementations are in the .cpp file).
    bool open_db(std::string& out_error);
    void close_db();

    // Read a configuration value from db_info (returns default_val when missing)
    std::string get_db_info_value(const std::string& key, const std::string& default_val = "");

    // Ensure the quarantine folder exists on disk
    bool ensure_quarantine_folder_exists(std::string& out_error);

    // Compute hash for file. On success returns true and writes hex string to out_hash.
    bool compute_hash(const std::filesystem::path& file_path,
                      std::string& out_hash,
                      const std::string& hash_type,
                      std::string& out_error);

    // Insert a whitelist record. Returns true on success.
    // NOTE: schema changed — whitelist now stores (hash, hash_type, note). We no longer store original_path here.
    bool insert_whitelist_db(const std::string& hash,
                             const std::string& hash_type,
                             const std::string& note,
                             std::string& out_error);

    // Insert a quarantine metadata record.
    // NOTE: schema changed — `original_size` and `encrypted` are no longer stored in the table.
    // Implementation should provide stored filename, original path, original name, stored_size and original_hash.
    // The DB will set `quarantined_at` via its default.
    bool insert_quarantine_record(const std::string& stored_filename,
                                  const std::string& original_full_path,
                                  const std::string& original_name,
                                  std::uint64_t stored_size,
                                  const std::string& original_hash);

    // Remove quarantine record and corresponding file from disk (used during pruning).
    bool remove_quarantine_record_by_id(int record_id, std::string& out_error);

    // Get total bytes currently stored in quarantine (consult DB view/db_info).
    // If DB doesn't provide it, fallback to calculating the folder size.
    std::uint64_t get_total_quarantine_bytes(std::string& out_error);

    // Get available bytes free on the volume containing the quarantine folder (or C: by default).
    std::uint64_t get_free_space_bytes(std::string& out_error);

    // Convenience: get file size in bytes
    // Convenience: get file size in bytes
    std::uint64_t file_size_bytes(const std::string &path);

    // Check supported hash types (md5, sha1, sha256)
    static bool is_supported_hash_type(const std::string& hash_type);

    // Small compatibility helper: implementation contains a deprecated prune_quarantine_to_fit
    bool prune_quarantine_to_fit(std::uint64_t required_bytes, std::uint64_t folder_limit_bytes);

    // Prune quarantine to free up at least needed_bytes. This will pick oldest entries first
    // (or based on policy) and remove them until needed space is freed or no candidates remain.
    // Returns true if enough space was freed (or none was needed), false on error or insufficient freed space.
    bool prune_quarantine_if_needed(std::uint64_t needed_bytes,
                                    std::uint64_t& out_freed_bytes,
                                    std::string& out_action_details,
                                    std::string& out_error);

    // XOR-encode (or decode) a file from src -> dst using a simple repeating key.
    // Returns true on success and writes bytes_written to out_bytes.
    static bool xor_transform_file(const std::filesystem::path& src,
                                   const std::filesystem::path& dst,
                                   std::uint64_t& out_bytes_written,
                                   std::string& out_error);

    // Create a unique stored filename inside quarantine to avoid collisions.
    std::string make_unique_stored_filename(const std::filesystem::path& original_path);

    // is_supported_hash_type already declared earlier in this header

private:
    std::string db_path_;
    std::string quarantine_folder_;
    sqlite3* db_handle_ = nullptr;
    std::mutex lock_;

    // If desired, the XOR key may be rotated/managed. For the MVP we use a fixed key in C++ code.
    // The implementation file will keep the key private. Header merely declares the shape.
    static const std::vector<uint8_t> DEFAULT_XOR_KEY;
};

} // namespace av
} // namespace pbl4

#endif // PBL4_CPP_QUARANTINEMANAGER_H
