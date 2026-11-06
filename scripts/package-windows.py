"""Stage Windows release files without changing application behavior."""
import hashlib
import json
import os
import pefile
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
release = ROOT / "src-tauri/target/release"
out = ROOT / "release-assets"
out.mkdir(exist_ok=True)
app = release / "mirsa-windows.exe"
assert app.is_file(), app
for pattern, name in [
    ("bundle/nsis/*.exe", "Mirsa-Setup.exe"),
    ("bundle/msi/*.msi", "Mirsa-Setup.msi"),
]:
    matches = list(release.glob(pattern))
    assert len(matches) == 1, (pattern, matches)
    shutil.copy2(matches[0], out / name)

subprocess.run([
    sys.executable, str(ROOT / "src-tauri/icons/verify-branding.py"),
    "--app", str(app), "--installer", str(out / "Mirsa-Setup.exe"),
], check=True)

# Check native dependencies without launching the application or contacting Apple.
system_dir = Path(os.environ["WINDIR"]) / "System32"
system_names = {p.name.lower() for p in system_dir.iterdir()}
local_dlls = {p.name.lower(): p for p in release.glob("*.dll")}
needed_dlls = {}
imports_report = {}
pending = [app]
seen = set()
while pending:
    binary = pending.pop()
    if binary.name.lower() in seen:
        continue
    seen.add(binary.name.lower())
    pe = pefile.PE(str(binary))
    assert pe.FILE_HEADER.Machine == 0x8664, "Expected Windows x64"
    imports = {
        entry.dll.decode("ascii").lower()
        for attr in ["DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"]
        for entry in getattr(pe, attr, [])
    }
    pe.close()
    imports_report[binary.name] = sorted(imports)
    for name in imports:
        if name in local_dlls:
            if name not in needed_dlls:
                needed_dlls[name] = local_dlls[name]
                pending.append(local_dlls[name])
        elif name.startswith(("api-ms-win-", "ext-ms-win-")) or name in system_names:
            continue
        else:
            raise AssertionError(f"Unresolved native dependency: {binary.name}: {name}")
(out / "native-dependencies.json").write_text(
    json.dumps(imports_report, indent=2) + "\n", encoding="utf-8"
)

# Frontend assets are embedded by Tauri. Include required build-produced DLLs.
# WebView2 and Apple device support remain machine prerequisites, not bundled.
with zipfile.ZipFile(out / "Mirsa-Portable.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.write(app, "mirsa.exe")
    for dll in sorted(needed_dlls.values()):
        z.write(dll, dll.name)
    for name in ["README.md", "THIRD_PARTY_NOTICES.md"]:
        z.write(ROOT / name, name)
    z.writestr("START-HERE.txt", """Mirsa 0.1.1 for Windows x64
Extract ALL files into a folder before opening mirsa.exe.
Requires Windows 10/11 x64, Microsoft Edge WebView2 Runtime, and Apple USB drivers.
Frontend assets are embedded; no Node.js or Rust installation is needed.
Portable means no Mirsa installer, not self-contained system dependencies.
Settings still use the normal Windows app-data location and credential store.
This release is unsigned. Smart App Control or other Windows protections may
block either installer or the portable executable. No compatibility guarantee.
Do not disable security protections. No physical-device testing is claimed.
""")
with zipfile.ZipFile(out / "Mirsa-Portable.zip") as z:
    assert z.testzip() is None
    assert z.read("mirsa.exe") == app.read_bytes()
names = ["Mirsa-Setup.exe", "Mirsa-Setup.msi", "Mirsa-Portable.zip"]
lines = []
for name in names:
    path = out / name
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    line = f"{digest}  {name}\n"
    (out / (name + ".sha256")).write_text(line, encoding="ascii")
    lines.append(line)
    print(name, path.stat().st_size, digest)
(out / "SHA256SUMS.txt").write_text("".join(lines), encoding="ascii")
