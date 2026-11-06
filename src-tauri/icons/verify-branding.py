"""Check Mirsa NSIS inputs; optionally inspect built Windows PE icon resources.

Run from any directory with Python 3.
For PE verification first install pefile, then pass --installer PATH and/or
--uninstaller PATH. Uninstaller must be obtained from a real test installation.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
source = (ROOT / "ios-AppIcon-source.png").read_bytes()
assert hashlib.sha256(source).hexdigest() == "195bcea1b8f98caee48e782d8a711faba2888b1ba89913410aabfb6f26003d3f"
assert hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest() == "2db3eba4bcdf50819aed98e199ed4bd7e66521e3"
assert (ROOT / "icon.png").read_bytes() == source
assert (ROOT / "icon.ico").read_bytes() == (ROOT / "mirsa-installer.ico").read_bytes()
print("Exact iOS source identity and app/installer icon equality verified")
config = json.loads((ROOT.parent / "tauri.conf.json").read_text(encoding="utf-8"))
assert config["version"] == "0.1.1", "Unexpected app version"
nsis = config["bundle"]["windows"]["nsis"]
schema_path = ROOT.parent.parent / "node_modules/@tauri-apps/cli/config.schema.json"
if schema_path.exists():
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert set(nsis) <= set(schema["definitions"]["NsisConfig"]["properties"])

expected = {
    "installerIcon": "icons/mirsa-installer.ico",
    "uninstallerIcon": "icons/mirsa-installer.ico",
    "headerImage": "icons/nsis-header.bmp",
    "uninstallerHeaderImage": "icons/nsis-header.bmp",
    "sidebarImage": "icons/nsis-sidebar.bmp",
}
for key, value in expected.items():
    assert nsis[key] == value, (key, nsis.get(key))

ico = (ROOT / "mirsa-installer.ico").read_bytes()
reserved, kind, count = struct.unpack_from("<HHH", ico)
assert (reserved, kind, count) == (0, 1, 7)
payloads = []
sizes = []
for i in range(count):
    w, h, colors, reserved, planes, bpp, length, offset = struct.unpack_from(
        "<BBBBHHII", ico, 6 + i * 16
    )
    w, h = w or 256, h or 256
    assert w == h and planes == 1 and bpp == 32
    assert offset >= 6 + count * 16 and offset + length <= len(ico)
    payload = ico[offset:offset + length]
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        assert struct.unpack_from(">II", payload, 16) == (w, h)
    else:
        assert struct.unpack_from("<Iii", payload) == (40, w, h * 2)
    payloads.append(payload)
    sizes.append(w)
assert sorted(sizes) == [16, 24, 32, 48, 64, 128, 256]
print("ICO verified: seven 32-bit Mirsa sizes", sizes)

for name, dimensions in [
    ("nsis-header.bmp", (150, 57)),
    ("nsis-sidebar.bmp", (164, 314)),
]:
    data = (ROOT / name).read_bytes()
    assert data[:2] == b"BM"
    assert struct.unpack_from("<I", data, 14)[0] == 40
    assert struct.unpack_from("<ii", data, 18) == dimensions
    assert struct.unpack_from("<HHI", data, 26) == (1, 24, 0)
    assert struct.unpack_from("<I", data, 2)[0] == len(data)
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    stride = ((dimensions[0] * 3 + 3) // 4) * 4
    assert pixel_offset + stride * dimensions[1] == len(data)
    print("BMP verified:", name, dimensions, "24-bit uncompressed")

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--app", type=Path)
parser.add_argument("--installer", type=Path)
parser.add_argument("--uninstaller", type=Path)
args = parser.parse_args()
for path in (args.app, args.installer, args.uninstaller):
    if path is None:
        continue
    try:
        import pefile
    except ImportError:
        raise SystemExit("PE verification requires: python -m pip install pefile")
    pe = pefile.PE(str(path))
    icon_data = []
    groups = []
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id not in (3, 14):
            continue
        for resource in entry.directory.entries:
            for language in resource.directory.entries:
                item = language.data.struct
                raw = pe.get_data(item.OffsetToData, item.Size)
                if entry.id == 3:
                    icon_data.append(raw)
                else:
                    groups.append(raw)
    assert groups, f"No RT_GROUP_ICON in {path}"
    assert all(payload in icon_data for payload in payloads), (
        f"{path} does not embed every exact Mirsa ICO image"
    )
    print("PE resources verified:", path, "all seven Mirsa images embedded")
print("Mirsa branding checks passed")
