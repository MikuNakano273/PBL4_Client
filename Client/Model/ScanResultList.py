class ScanResultList:
    def __init__(self):
        self.scan_results = []

    def reset_results(self):
        self.scan_results = []

    def add_result(self, res):
        result_info = {
            "filename": getattr(res, "filename", ""),
            "desc": getattr(res, "desc", ""),
            "severity": getattr(res, "severity", ""),
            "isMalware": getattr(res, "isMalware", False),
        }
        self.scan_results.append(result_info)

    def get_all_results(self):
        return self.scan_results

    def upload_new_hashes(self, hashes):
        if not hashes:
            return False
        try:
            import datetime
            import json
            from pathlib import Path

            payload = {
                "uploaded_at": datetime.datetime.now().isoformat(),
                "items": hashes,
            }
            debug_path = Path.cwd() / "uploaded_hashes_from_model_debug.json"
            with open(debug_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False
