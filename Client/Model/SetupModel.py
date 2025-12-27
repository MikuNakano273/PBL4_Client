from pathlib import Path

import requests


class SetupModel:
    def __init__(self):
        self.base_dir = Path.cwd()
        print(self.base_dir)

        # Only ONE rule file now
        self.yarc_name = "all_rules.yarc"
        self.yarc_url = (
            "https://sourceforge.net/projects/pbl4-data/files/all_rules.yarc/download"
        )
        self.yarc_path = self.base_dir / self.yarc_name

        # Database
        self.db_name = "full_hash.db"
        self.db_url = (
            "https://sourceforge.net/projects/pbl4-data/files/full_hash.db/download"
        )
        self.db_path = self.base_dir / self.db_name

        self.config_path = self.base_dir / "App.config"

    # -----------------------------------------------------

    def internet_connected(self):
        try:
            requests.get("https://httpbin.org/ip", timeout=4)
            return True
        except Exception:
            return False

    # -----------------------------------------------------

    def get_missing_files(self):
        missing = []

        if not self.yarc_path.exists():
            missing.append(self.yarc_name)

        if not self.db_path.exists():
            missing.append(self.db_name)

        return missing

    # -----------------------------------------------------

    def ensure_setup(self, progress_callback=None, status_callback=None):
        if progress_callback is None:
            progress_callback = lambda x: None
        if status_callback is None:
            status_callback = lambda x: None

        missing = self.get_missing_files()
        if not missing:
            status_callback("All files ready")
            progress_callback(100)
            return True

        if not self.internet_connected():
            status_callback("No internet. Cannot download.")
            return False

        total = len(missing)
        done = 0

        for name in missing:
            if name == self.yarc_name:
                url = self.yarc_url
                path = self.yarc_path
            else:  # full_hash.db
                url = self.db_url
                path = self.db_path

            status_callback(f"Downloading {name}...")
            if not self._download(url, path):
                status_callback(f"Failed to download {name}")
                return False

            done += 1
            progress_callback(int(done / total * 100))

        # Create config only once
        if not self.config_path.exists():
            self.config_path.write_text("setup_complete=true\n")

        status_callback("Setup completed")
        return True

    # -----------------------------------------------------

    def _download(self, url, dest, status_callback=None):
        tmp = None
        try:
            r = requests.get(url, stream=True, timeout=20)
            r.raise_for_status()

            # Prepare temp path
            tmp = Path(str(dest)).with_suffix(".tmp")
            tmp.parent.mkdir(parents=True, exist_ok=True)

            total_size = int(r.headers.get("Content-Length") or 0)
            downloaded = 0

            with tmp.open("wb") as f:
                for chunk in r.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        # Provide coarse progress updates if caller wants them
                        if status_callback:
                            if total_size:
                                pct = int(downloaded * 100 / total_size)
                                # clamp to sensible values
                                pct = max(0, min(100, pct))
                                status_callback(f"Downloading {dest.name}: {pct}%")
                            else:
                                # Unknown total size; still report bytes
                                status_callback(
                                    f"Downloading {dest.name}: {downloaded} bytes"
                                )

            # Atomic replace so a partially-downloaded file is never left at `dest`.
            tmp.replace(dest)

            if status_callback:
                status_callback(f"Downloaded {dest.name} ({downloaded} bytes)")

            return True
        except Exception as e:
            # Emit status and ensure tmp cleanup
            print(f"[SetupModel] Download failed: {e}")
            if status_callback:
                try:
                    status_callback(f"Download failed: {e}")
                except Exception:
                    pass
            try:
                if tmp is not None and tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            return False
