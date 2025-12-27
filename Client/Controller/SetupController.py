import time

from PySide6.QtCore import QObject, Signal

from Client.Model.SetupModel import SetupModel

try:
    from Client.Model.YaraScannerModel import (
        DEFAULT_COMPILED_RULES,
        DEFAULT_RULES_DB,
        YaraScannerModel,
    )
except Exception:
    YaraScannerModel = None
    DEFAULT_COMPILED_RULES = None
    DEFAULT_RULES_DB = None


class SetupController(QObject):
    progress = Signal(int)
    status = Signal(str)
    finished = Signal(bool)

    def __init__(self):
        super().__init__()
        self.model = SetupModel()
        self._scanner = None
        self.qm_controller = None
        self.quarantine_manager = None

    def start(self):
        missing = self.model.get_missing_files()
        if not missing:
            self.status.emit("All files ready")
            self.progress.emit(20)
        else:
            # Need network
            if not self.model.internet_connected():
                self.status.emit("No internet")
                self.finished.emit(False)
                return

            # Run setup (downloads). Provide callbacks to update the loading UI.
            self.status.emit("Downloading required files...")
            self.progress.emit(5)
            success = self._run_setup()
            if not success:
                # _run_setup already emitted status
                self.finished.emit(False)
                return

        """
        Below is the disabled hash DB update logic prior to scanner init.
        """
        # At this point files are present on disk; before initializing the scanner
        # attempt to check/apply hash DB updates from remote repository. Failures
        # during update should NOT make setup fail: we only notify and continue.
        # self.status.emit("Preparing hash DB update check...")
        # # give some progress for preparation + checking
        # try:
        #     self.progress.emit(35)
        # except Exception:
        #     pass

        # try:
        #     # Attempt to import the updater; if unavailable, skip quietly.
        #     from Client.Model.UpdateModel import UpdateModel  # type: ignore

        #     try:
        #         # Prefer to use the SetupModel's db_path if available so the updater
        #         # operates on the same DB the setup prepared.
        #         db_path_arg = None
        #         try:
        #             db_path_arg = (
        #                 str(self.model.db_path)
        #                 if getattr(self.model, "db_path", None)
        #                 else None
        #             )
        #         except Exception:
        #             db_path_arg = None

        #         um = UpdateModel(db_path=db_path_arg)
        #         # Inform UI we're checking for updates
        #         self.status.emit("Checking for hash DB updates...")
        #         try:
        #             self.progress.emit(40)
        #         except Exception:
        #             pass

        #         try:
        #             # Run update synchronously here. If it fails, we catch and continue.
        #             res = um.check_and_update(dry_run=False)
        #             # UpdateModel returns an object with `.success` and `.message` when available.
        #             ok = bool(getattr(res, "success", False))
        #             msg = getattr(res, "message", str(res))
        #             if ok:
        #                 self.status.emit(f"Hash DB updated: {msg}")
        #                 try:
        #                     self.progress.emit(60)
        #                 except Exception:
        #                     pass
        #             else:
        #                 # Non-fatal: report and continue
        #                 self.status.emit(f"Hash update skipped/failed: {msg}")
        #                 try:
        #                     self.progress.emit(50)
        #                 except Exception:
        #                     pass
        #         except Exception as e:
        #             # Network or application-level failure during update; report but continue.
        #             self.status.emit(f"Hash update failed: {e}")
        #             try:
        #                 self.progress.emit(50)
        #             except Exception:
        #                 pass
        #     except Exception as e:
        #         # If constructing or running updater fails, report and continue.
        #         self.status.emit(f"Hash updater error: {e}")
        #         try:
        #             self.progress.emit(50)
        #         except Exception:
        #             pass
        # except Exception:
        #     # UpdateModel not present; skip update silently and continue.
        #     self.status.emit("No update module available; skipping hash update")
        #     try:
        #         self.progress.emit(50)
        #     except Exception:
        #         pass

        self.status.emit("Initializing scanner engine...")
        try:
            self.progress.emit(65)
        except Exception:
            pass

        try:
            ok = self._init_yara_with_retries()
            if ok:
                self.status.emit("Scanner initialized")
                try:
                    self.status.emit("Initializing quarantine manager...")
                    try:
                        self.progress.emit(75)
                    except Exception:
                        pass
                    qm_ok = self._init_quarantine_with_retries(
                        max_seconds=60, interval=0.5
                    )
                    if qm_ok:
                        self.status.emit("Quarantine manager initialized")
                    else:
                        self.status.emit("Quarantine manager init failed")
                except Exception as e:
                    self.status.emit(f"Quarantine manager not available: {e}")

                try:
                    self.progress.emit(100)
                except Exception:
                    pass
                self.finished.emit(True)
                return
            else:
                self.status.emit("Scanner initialization failed")
                self.finished.emit(False)
                return
        except Exception as e:
            self.status.emit(f"Scanner init error: {e}")
            self.finished.emit(False)
            return

    def _run_setup(self):
        try:
            success = self.model.ensure_setup(
                progress_callback=self.progress.emit,
                status_callback=self.status.emit,
            )
            return bool(success)
        except Exception as e:
            self.status.emit(f"Setup failed: {e}")
            return False

    def _init_yara_with_retries(
        self, max_seconds: int = 60, interval: float = 0.5
    ) -> bool:
        global YaraScannerModel, DEFAULT_COMPILED_RULES, DEFAULT_RULES_DB
        if YaraScannerModel is None:
            try:
                from Client.Model.YaraScannerModel import (
                    DEFAULT_COMPILED_RULES as _DEFAULT_COMP,
                )
                from Client.Model.YaraScannerModel import (
                    DEFAULT_RULES_DB as _DEFAULT_DB,
                )
                from Client.Model.YaraScannerModel import (
                    YaraScannerModel as _YaraScannerModel,
                )

                YaraScannerModel = _YaraScannerModel
                DEFAULT_COMPILED_RULES = _DEFAULT_COMP
                DEFAULT_RULES_DB = _DEFAULT_DB
            except Exception as e:
                self.status.emit(f"Cannot import scanner: {e}")
                return False

        try:
            self._scanner = YaraScannerModel()
        except Exception as e:
            self.status.emit(f"Scanner unavailable: {e}")
            return False

        deadline = time.time() + float(max_seconds)
        attempt = 0
        while True:
            attempt += 1
            try:
                self.status.emit(f"Initializing scanner (attempt {attempt})...")
                rules = DEFAULT_COMPILED_RULES
                db = DEFAULT_RULES_DB
                ok = self._scanner.init(rules, db, status_cb=self.status.emit)
                if ok:
                    return True
                else:
                    self.status.emit("Scanner init returned False; retrying...")
            except Exception as e:
                self.status.emit(f"Scanner init exception: {e}")

            if time.time() >= deadline:
                self.status.emit("Scanner init timed out")
                return False

            elapsed = max(0, min(max_seconds, max_seconds - (deadline - time.time())))
            try:
                pct = 30 + int((elapsed / max_seconds) * 60)
                pct = max(30, min(90, pct))
                self.progress.emit(pct)
            except Exception:
                pass

            time.sleep(interval)

    def _init_quarantine_with_retries(
        self, max_seconds: int = 60, interval: float = 0.5
    ) -> bool:
        try:
            from Client.Controller.QuarantineManagerController import (
                QuarantineManagerController,
            )
        except Exception as e:
            self.status.emit(f"Cannot import QuarantineManagerController: {e}")
            return False

        try:
            qm_ctrl = QuarantineManagerController()
        except Exception as e:
            self.status.emit(f"Quarantine controller unavailable: {e}")
            return False

        try:
            try:
                db_path_arg = (
                    str(self.model.db_path)
                    if getattr(self.model, "db_path", None)
                    else None
                )
            except Exception:
                db_path_arg = None

            ok = qm_ctrl.init_with_retries(
                max_seconds=max_seconds,
                interval=interval,
                db_path=db_path_arg,
                status_cb=self.status.emit,
            )
            if ok:
                self.qm_controller = qm_ctrl
                try:
                    self.quarantine_manager = qm_ctrl.model
                except Exception:
                    self.quarantine_manager = getattr(qm_ctrl, "_model", None)
                return True
            else:
                self.status.emit("Quarantine manager init failed")
                return False
        except Exception as e:
            self.status.emit(f"Quarantine manager init exception: {e}")
            return False
