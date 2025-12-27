from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("pbl4.AutostartController")
logger.addHandler(logging.NullHandler())

# Constants
PROGRAMDATA_DIR = Path("C:/ProgramData/PBL4_AV_DATA")
SETTINGS_FILE = PROGRAMDATA_DIR / "settings.json"
DEFAULT_SHORTCUT_NAME = "PBL4_Client"  # .lnk appended automatically

# Try to import win32com for creating Windows shortcuts
try:
    from win32com.client import Dispatch  # type: ignore
except Exception:
    Dispatch = None  # type: ignore


# -----------------------
# File + settings helpers
# -----------------------
def ensure_programdata_dir() -> None:
    """Create ProgramData settings directory if it does not exist."""
    try:
        PROGRAMDATA_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logger.error("Failed to create ProgramData folder %s: %s", PROGRAMDATA_DIR, exc)
        raise


def load_settings() -> Dict:
    """
    Load settings from C:/ProgramData/PBL4_AV_DATA/settings.json.

    Defaults:
      {
        "start_with_windows": False,
        "autostart_all_users": False,
        "shortcut_name": "PBL4_Client"
      }
    """
    defaults = {
        "start_with_windows": False,
        "autostart_all_users": False,
        "shortcut_name": DEFAULT_SHORTCUT_NAME,
    }
    try:
        ensure_programdata_dir()
        if SETTINGS_FILE.exists():
            with SETTINGS_FILE.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    merged = {**defaults, **data}
                    return merged
    except Exception as exc:
        logger.warning("Failed to load settings file: %s", exc)
    return defaults


def save_settings(settings: Dict) -> None:
    """Atomically save settings as JSON into the ProgramData settings file."""
    ensure_programdata_dir()
    try:
        tmp = SETTINGS_FILE.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        tmp.replace(SETTINGS_FILE)
    except Exception as exc:
        logger.error("Failed to save settings to %s: %s", SETTINGS_FILE, exc)
        raise


# -----------------------
# Paths for startup
# -----------------------
def user_startup_folder() -> Path:
    """Return the current user's Startup folder path."""
    appdata = os.getenv("APPDATA")
    if not appdata:
        appdata = str(Path.home() / "AppData" / "Roaming")
    return (
        Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    )


def all_users_startup_folder() -> Path:
    """Return the All Users Startup folder path (ProgramData)."""
    programdata = os.getenv("PROGRAMDATA") or "C:\\ProgramData"
    return (
        Path(programdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )


def _shortcut_path(all_users: bool, name: str) -> Path:
    """Return full path for the .lnk file for the requested startup scope."""
    folder = all_users_startup_folder() if all_users else user_startup_folder()
    return folder / f"{name}.lnk"


# -----------------------
# Executable helpers
# -----------------------
def current_executable_path() -> Path:
    """Return the path to the running executable that should be launched on startup."""
    try:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve()
    except Exception:
        pass

    try:
        p = Path(sys.argv[0])
        if not p.exists():
            p = Path.cwd() / p
        return p.resolve()
    except Exception:
        return Path.cwd().resolve()


# -----------------------
# Shortcut creation helpers
# -----------------------
def _create_shortcut_win32(
    target: Path,
    lnk: Path,
    arguments: Optional[str] = None,
    working_dir: Optional[Path] = None,
    icon: Optional[Path] = None,
) -> bool:
    """
    Create a .lnk shortcut using pywin32 Dispatch (WScript.Shell).
    Returns True on success, False on failure or if Dispatch not available.
    """
    if Dispatch is None:
        logger.debug("win32com Dispatch not available")
        return False

    try:
        shell = Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(str(lnk))
        shortcut.Targetpath = str(target)
        if arguments:
            shortcut.Arguments = arguments
        if working_dir:
            shortcut.WorkingDirectory = str(working_dir)
        if icon:
            shortcut.IconLocation = str(icon)
        shortcut.save()
        return lnk.exists()
    except Exception as exc:
        logger.warning("win32 shortcut creation failed: %s", exc)
        return False


def _create_shortcut_powershell(
    target: Path,
    lnk: Path,
    arguments: Optional[str] = None,
    working_dir: Optional[Path] = None,
    icon: Optional[Path] = None,
) -> bool:
    """
    Create a .lnk using a small PowerShell one-liner that uses WScript.Shell COM.
    This is a fallback when win32com is not installed.
    """

    def esc(s: str) -> str:
        return s.replace("'", "''")

    parts = ["$W=New-Object -ComObject WScript.Shell"]
    parts.append(f"$S=$W.CreateShortcut('{esc(str(lnk))}')")
    parts.append(f"$S.TargetPath='{esc(str(target))}'")
    if arguments:
        parts.append(f"$S.Arguments='{esc(arguments)}'")
    if working_dir:
        parts.append(f"$S.WorkingDirectory='{esc(str(working_dir))}'")
    if icon:
        parts.append(f"$S.IconLocation='{esc(str(icon))}'")
    parts.append("$S.Save()")
    cmd = "; ".join(parts)

    try:
        # Use -NoProfile -NonInteractive to avoid loading user profile scripts
        proc = __import__("subprocess").run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return lnk.exists()
    except Exception as exc:
        logger.warning("PowerShell shortcut creation failed: %s", exc)
        return False


def _ensure_startup_folder_exists(all_users: bool) -> None:
    """
    Ensure the target startup folder exists. For user startup this generally
    exists already; for All Users it may require elevation when created.
    """
    path = all_users_startup_folder() if all_users else user_startup_folder()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logger.debug("Could not ensure startup folder %s exists: %s", path, exc)


def create_shortcut(
    all_users: bool = False,
    name: Optional[str] = None,
    target: Optional[Path] = None,
    arguments: str = "",
) -> bool:
    """
    Create a startup shortcut. By default creates per-user shortcut (no admin required).
    If all_users=True this will attempt to create in All Users Startup (may require elevation).
    Returns True on success.
    """
    try:
        target_path = Path(target) if target is not None else current_executable_path()
        name = name or DEFAULT_SHORTCUT_NAME
        lnk = _shortcut_path(all_users, name)
        _ensure_startup_folder_exists(all_users)

        # Try win32com first (more reliable), fallback to PowerShell approach
        ok = False
        try:
            ok = _create_shortcut_win32(
                target_path,
                lnk,
                arguments=arguments,
                working_dir=target_path.parent,
                icon=target_path,
            )
        except Exception:
            ok = False

        if not ok:
            ok = _create_shortcut_powershell(
                target_path,
                lnk,
                arguments=arguments,
                working_dir=target_path.parent,
                icon=target_path,
            )

        if ok:
            # Persist settings file update
            settings = load_settings()
            settings["start_with_windows"] = True
            settings["shortcut_name"] = name
            settings["autostart_all_users"] = bool(all_users)
            save_settings(settings)
            logger.info("Created startup shortcut: %s", lnk)
            return True

        logger.warning("Failed to create startup shortcut: %s", lnk)
        return False
    except Exception as exc:
        logger.error("create_shortcut exception: %s", exc)
        return False


def remove_shortcut(
    name: Optional[str] = None, all_users: Optional[bool] = None
) -> bool:
    try:
        name = name or load_settings().get("shortcut_name", DEFAULT_SHORTCUT_NAME)
        targets = []
        if all_users is None:
            targets = [
                (False, _shortcut_path(False, name)),
                (True, _shortcut_path(True, name)),
            ]
        else:
            targets = [(all_users, _shortcut_path(all_users, name))]

        removed_any = False
        for scope, path in targets:
            try:
                if path.exists():
                    path.unlink()
                    removed_any = True
                    logger.info("Removed startup shortcut: %s", path)
            except Exception as exc:
                logger.warning("Failed to remove shortcut %s: %s", path, exc)

        if removed_any:
            settings = load_settings()
            settings["start_with_windows"] = False
            save_settings(settings)
        return removed_any
    except Exception as exc:
        logger.error("remove_shortcut exception: %s", exc)
        return False


def is_autostart_enabled(name: Optional[str] = None) -> bool:
    try:
        name = name or load_settings().get("shortcut_name", DEFAULT_SHORTCUT_NAME)
        return _shortcut_path(False, name).exists()
    except Exception:
        return False


def enable_autostart(
    name: Optional[str] = None, target: Optional[Path] = None, all_users: bool = False
) -> bool:
    ok = create_shortcut(all_users=all_users, name=name, target=target)
    if ok:
        settings = load_settings()
        settings["start_with_windows"] = True
        settings["autostart_all_users"] = bool(all_users)
        settings["shortcut_name"] = name or settings.get(
            "shortcut_name", DEFAULT_SHORTCUT_NAME
        )
        save_settings(settings)
    return ok


def disable_autostart(
    name: Optional[str] = None, all_users: Optional[bool] = None
) -> bool:
    ok = remove_shortcut(name=name, all_users=all_users)
    try:
        settings = load_settings()
        settings["start_with_windows"] = False
        if all_users is not None:
            settings["autostart_all_users"] = bool(all_users)
        else:
            settings["autostart_all_users"] = False
        save_settings(settings)
    except Exception:
        pass
    return ok
