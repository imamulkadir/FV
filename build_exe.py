"""Build the minimal FV.exe using Windows' installed .NET Framework."""

import re
import subprocess
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
SOURCE_PATH = PROJECT_DIR / "FV.cs"
VERSION_PATH = PROJECT_DIR / "version.txt"
GENERATED_DIR = PROJECT_DIR / "obj"
VERSION_SOURCE_PATH = GENERATED_DIR / "FV.Version.cs"
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


def read_version() -> tuple[str, str]:
    if not VERSION_PATH.exists():
        raise SystemExit(f"Missing version file: {VERSION_PATH}")
    display_version = VERSION_PATH.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", display_version):
        raise SystemExit("version.txt must contain three numbers, for example: 2.5.0")
    numbers = [int(part) for part in display_version.split(".")]
    if any(number > 65534 for number in numbers):
        raise SystemExit("Each version number must be between 0 and 65534.")
    return display_version, display_version + ".0"


def write_version_source(display_version: str, assembly_version: str) -> None:
    GENERATED_DIR.mkdir(exist_ok=True)
    source = (
        "using System.Reflection;\n"
        f'[assembly: AssemblyVersion("{assembly_version}")]\n'
        f'[assembly: AssemblyFileVersion("{assembly_version}")]\n'
        f'[assembly: AssemblyInformationalVersion("{display_version}")]\n'
    )
    VERSION_SOURCE_PATH.write_text(source, encoding="utf-8")


def main():
    if not SOURCE_PATH.exists():
        raise SystemExit(f"Missing source file: {SOURCE_PATH}")
    if not ICON_PATH.exists():
        raise SystemExit(f"Missing icon file: {ICON_PATH}")
    if not LOCK_ICON_PATH.exists() or not UNLOCK_ICON_PATH.exists():
        raise SystemExit("Missing lock/unlock SVG assets.")

    display_version, assembly_version = read_version()
    write_version_source(display_version, assembly_version)
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
        str(VERSION_SOURCE_PATH),
    ]
    subprocess.run(command, check=True, cwd=PROJECT_DIR)
    print(f"Built: {OUTPUT_PATH}")
    print(f"Version: {display_version}")
    print(f"Size: {OUTPUT_PATH.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
