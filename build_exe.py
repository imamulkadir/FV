"""Build the minimal FV.exe using Windows' installed .NET Framework."""

import subprocess
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
SOURCE_PATH = PROJECT_DIR / "FV.cs"
ICON_PATH = PROJECT_DIR / "fv.ico"
LOCK_ICON_PATH = PROJECT_DIR / "assets" / "lock.svg"
UNLOCK_ICON_PATH = PROJECT_DIR / "assets" / "unlock.svg"
OUTPUT_DIR = PROJECT_DIR / "dist"
OUTPUT_PATH = OUTPUT_DIR / "FV.exe"


def find_compiler() -> Path:
    candidates = (
        Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"),
        Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit("The Windows .NET Framework C# compiler was not found.")


def main():
    if not SOURCE_PATH.exists():
        raise SystemExit(f"Missing source file: {SOURCE_PATH}")
    if not ICON_PATH.exists():
        raise SystemExit(f"Missing icon file: {ICON_PATH}")
    if not LOCK_ICON_PATH.exists() or not UNLOCK_ICON_PATH.exists():
        raise SystemExit("Missing lock/unlock SVG assets.")

    OUTPUT_DIR.mkdir(exist_ok=True)
    command = [
        str(find_compiler()),
        "/nologo",
        "/target:winexe",
        "/optimize+",
        "/debug-",
        "/platform:anycpu",
        f"/win32icon:{ICON_PATH}",
        f"/out:{OUTPUT_PATH}",
        f"/resource:{LOCK_ICON_PATH},FV.lock.svg",
        f"/resource:{UNLOCK_ICON_PATH},FV.unlock.svg",
        "/reference:System.Drawing.dll",
        "/reference:System.Runtime.Serialization.dll",
        "/reference:System.Security.dll",
        "/reference:System.Windows.Forms.dll",
        "/reference:System.Xml.dll",
        str(SOURCE_PATH),
    ]
    subprocess.run(command, check=True, cwd=PROJECT_DIR)
    print(f"Built: {OUTPUT_PATH}")
    print(f"Size: {OUTPUT_PATH.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
