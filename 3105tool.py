#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
3105tool.py — 3105 Pro V1.4
- PUBG: schema 2
- Liên Quân: schema 9
- Path editor Auto/Custom
- Preview path
- Smart update statistics
- ZIP diagnostics (warning only)
- Verify after build/update/rebundle
- No automatic safety filter
"""
from __future__ import annotations


import argparse
import hashlib
import io
import json
import plistlib
import re
import secrets
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    sys.stderr.write("Cần cài: pip install cryptography\n")
    raise


MAGIC = b"3105PATCH\x00"
DEFAULT_ITERATIONS = 250_000
DEFAULT_AUTHOR = "MANZ-VIP"
DEFAULT_PASSWORD = "MANVIP"


BUNDLE_LQ = "com.garena.game.kgvn"
BUNDLE_LQ_ALT = "com.garena.game.kgvn2"
BUNDLE_PUBG_GLOBAL = "com.tencent.ig"
BUNDLE_PUBG_VNG = "vn.vng.pubgmobile"
BUNDLE_PUBG_KR = "com.pubg.krmobile"
BUNDLE_PUBG_TW = "com.rekoo.pubgm"
BUNDLE_PUBG_BGMI = "com.pubg.imobile"
ALL_BUNDLES = {
    BUNDLE_LQ,
    BUNDLE_LQ_ALT,
    BUNDLE_PUBG_GLOBAL,
    BUNDLE_PUBG_VNG,
    BUNDLE_PUBG_KR,
    BUNDLE_PUBG_TW,
    BUNDLE_PUBG_BGMI,
}


PRESETS = {
    "lq": {"bundles": [BUNDLE_LQ], "dual": False, "schema": 9},
    "lq2": {"bundles": [BUNDLE_LQ_ALT], "dual": False, "schema": 9},
    "pubg-global": {"bundles": [BUNDLE_PUBG_GLOBAL], "dual": False, "schema": 2},
    "pubg-vng": {"bundles": [BUNDLE_PUBG_VNG], "dual": False, "schema": 2},
    "pubg-kr": {"bundles": [BUNDLE_PUBG_KR], "dual": False, "schema": 2},
    "pubg-tw": {"bundles": [BUNDLE_PUBG_TW], "dual": False, "schema": 2},
    "pubg-bgmi": {"bundles": [BUNDLE_PUBG_BGMI], "dual": False, "schema": 2},
    "pubg-5sv": {"bundles": [BUNDLE_PUBG_GLOBAL, BUNDLE_PUBG_VNG, BUNDLE_PUBG_KR, BUNDLE_PUBG_TW, BUNDLE_PUBG_BGMI], "dual": True, "schema": 9},
    "pubg": {
        "bundles": [BUNDLE_PUBG_GLOBAL, BUNDLE_PUBG_VNG],
        "dual": True,
        "schema": 2,
    },
}


JUNK_BASENAMES = {".DS_Store", "Thumbs.db"}
WRAPPER_NAMES = {
    "ios", "iphone", "files", "file", "mod", "mods", "skin", "skins",
    "gl", "global", "vng", "pubg", "lq", "lienquan", "liên quân",
}
NOTABLE_LQ_BASENAMES = {
    "kernellua.pkg.bytes",
    "stablesystems_3.pkg.bytes",
    "commonactions.pkg.bytes",
    "resourcepackerinfosetall.assetbundle",
    "resourceverificationinfosetall.assetbundle",
}




def new_uuid() -> str:
    return str(uuid.uuid4()).upper()




def utc_plist_date() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)




def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()




def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()




def derive_password_key(password: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))




def aesgcm_pack(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)




def aesgcm_unpack(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("AES-GCM blob quá ngắn")
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)




def read_container(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    if not data.startswith(MAGIC):
        raise ValueError("Magic sai — không phải file .3105 hợp lệ")
    return plistlib.loads(data[len(MAGIC):])




def write_container(path: str | Path, meta: dict) -> None:
    raw = MAGIC + plistlib.dumps(meta, fmt=plistlib.FMT_BINARY, sort_keys=False)
    Path(path).write_bytes(raw)




def unlock_container(meta: dict, password: str | None):
    package_id = meta["packageID"]
    schema_version = int(meta.get("schemaVersion", 1))
    key_aad_version = int(meta.get("keyAADVersion", schema_version))


    if meta.get("isPasswordProtected"):
        if not password:
            raise ValueError("File yêu cầu mật khẩu")
        salt = meta["kdfSalt"]
        iterations = int(meta.get("kdfIterations", DEFAULT_ITERATIONS))
        pw_key = derive_password_key(password, salt, iterations)
        content_key = aesgcm_unpack(
            pw_key,
            meta["wrappedContentKey"],
            f"3105PATCH/v{key_aad_version}/key/{package_id}".encode(),
        )
    else:
        content_key = meta.get("publicContentKey")
        if not content_key:
            raise ValueError("Thiếu publicContentKey")


    fingerprint = meta.get("keyFingerprint")
    if fingerprint is not None and sha256_digest(content_key) != fingerprint:
        raise ValueError("keyFingerprint không khớp — sai mật khẩu hoặc file hỏng")


    payload_bytes = aesgcm_unpack(
        content_key,
        meta["encryptedPayload"],
        f"3105PATCH/v{schema_version}/payload/{package_id}".encode(),
    )
    return content_key, plistlib.loads(payload_bytes)




def build_container(
    payload_obj: dict,
    password: str | None,
    package_id: str | None = None,
    schema_version: int = 2,
    key_aad_version: int | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> dict:
    package_id = (package_id or new_uuid()).upper()
    key_aad_version = schema_version if key_aad_version is None else int(key_aad_version)
    payload_bytes = plistlib.dumps(payload_obj, fmt=plistlib.FMT_BINARY, sort_keys=False)
    content_key = secrets.token_bytes(32)


    meta = {
        "schemaVersion": int(schema_version),
        "keyAADVersion": int(key_aad_version),
        "packageID": package_id,
        "isPasswordProtected": password is not None,
        "keyFingerprint": sha256_digest(content_key),
        "encryptedPayload": aesgcm_pack(
            content_key,
            payload_bytes,
            f"3105PATCH/v{schema_version}/payload/{package_id}".encode(),
        ),
    }


    if password is None:
        meta["publicContentKey"] = content_key
    else:
        salt = secrets.token_bytes(16)
        pw_key = derive_password_key(password, salt, iterations)
        meta.update({
            "kdfSalt": salt,
            "kdfIterations": int(iterations),
            "wrappedContentKey": aesgcm_pack(
                pw_key,
                content_key,
                f"3105PATCH/v{key_aad_version}/key/{package_id}".encode(),
            ),
        })
    return meta




# Conservative, configurable decompression budgets shared across nested archives.
MAX_ZIP_FILES = 10000
MAX_ZIP_UNCOMPRESSED = 512 * 1024 * 1024
MAX_ZIP_RATIO = 200
MAX_ZIP_DEPTH = 2


def _clean_arcname(name: str) -> str:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("Tên mục ZIP không hợp lệ")
    if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        raise ValueError(f"Đường dẫn ZIP tuyệt đối: {name}")
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if ".." in parts or any(not part for part in parts[:-1]):
        raise ValueError(f"Đường dẫn ZIP không hợp lệ: {name}")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized == ".":
        raise ValueError("Tên mục ZIP rỗng")
    return normalized


def _zip_bytes_entries(blob: bytes, depth: int = 0, max_depth: int = MAX_ZIP_DEPTH,
                       budget=None, context: str = ""):
    if budget is None:
        budget = {"files": 0, "bytes": 0}
    out: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        seen = set()
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = _clean_arcname(info.filename)
            if name.startswith("__MACOSX/"):
                continue
            base = PurePosixPath(name).name
            if base in JUNK_BASENAMES or base.startswith("._"):
                continue
            if name in seen:
                raise ValueError(f"ZIP chứa đường dẫn trùng: {name}")
            seen.add(name)
            if (info.flag_bits & 0x1) or info.file_size < 0:
                raise ValueError(f"ZIP mã hóa/không hợp lệ: {name}")
            if info.file_size > MAX_ZIP_UNCOMPRESSED or (info.file_size > 1024 * 1024 and
                    info.file_size / max(info.compress_size, 1) > MAX_ZIP_RATIO):
                raise ValueError(f"ZIP có kích thước/tỷ lệ nén nguy hiểm: {name}")
            budget["files"] += 1
            budget["bytes"] += info.file_size
            if budget["files"] > MAX_ZIP_FILES or budget["bytes"] > MAX_ZIP_UNCOMPRESSED:
                raise ValueError("ZIP vượt giới hạn số file hoặc dung lượng giải nén")
            data = zf.read(info)
            if depth < max_depth and name.lower().endswith(".zip"):
                # Nested archives must be valid; never silently emit a corrupt ZIP as a rule.
                parent = str(PurePosixPath(name).parent)
                parent = "" if parent == "." else parent
                nested_context = "/".join(x for x in (context, parent) if x)
                nested = _zip_bytes_entries(data, depth + 1, max_depth, budget, nested_context)
                out.extend(nested)
                continue
            if name.lower().endswith(".zip"):
                raise ValueError("ZIP lồng nhau vượt độ sâu cho phép")
            # Keep bundle folder context when the nested ZIP lived under a bundle ID.
            inherited = [x for x in context.split("/") if x in ALL_BUNDLES]
            output_name = "/".join(inherited + [name]) if inherited and not any(
                x in ALL_BUNDLES for x in name.split("/")) else name
            out.append((output_name, data))
    return out


def zip_entries(zip_path: str | Path):
    path = Path(zip_path)
    if path.stat().st_size > MAX_ZIP_UNCOMPRESSED:
        raise ValueError("ZIP đầu vào vượt giới hạn kích thước")
    return _zip_bytes_entries(path.read_bytes())


def input_entries(input_path: str | Path):
    p = Path(input_path)
    if p.suffix.lower() == ".zip":
        return zip_entries(p)
    return [(p.name, p.read_bytes())]



def find_bundle_hint(parts):
    for i, part in enumerate(parts):
        if part in ALL_BUNDLES:
            return part, i
    return None, None




def strip_common_wrappers(name: str) -> str:
    parts = list(PurePosixPath(_clean_arcname(name)).parts)
    bundle_hint, idx = find_bundle_hint(parts)
    if bundle_hint is not None:
        parts = parts[idx + 1:]


    meaningful = {
        "Documents", "Resources", "ShadowTrackerExtra", "Saved",
        "Paks", "puffer_temp", "payload",
    }


    while len(parts) > 1:
        first = parts[0]
        low = first.lower()
        if first in meaningful:
            break
        if low in WRAPPER_NAMES:
            parts.pop(0)
            continue
        if parts[1] in meaningful or parts[1] in ALL_BUNDLES:
            parts.pop(0)
            continue
        if len(parts) > 2 and parts[2] in meaningful:
            parts.pop(0)
            continue
        break
    return "/".join(parts)




def auto_detect_preset(entries) -> str:
    has_pak = False
    has_resources = False
    hints = set()


    for name, _ in entries:
        low = name.lower().replace("\\", "/")
        if low.endswith(".pak"):
            has_pak = True
        if low.startswith("resources/") or "/resources/" in "/" + low:
            has_resources = True
        parts = list(PurePosixPath(name.replace("\\", "/")).parts)
        hint, _ = find_bundle_hint(parts)
        if hint:
            hints.add(hint)


    if has_pak and not has_resources:
        if hints == {BUNDLE_PUBG_GLOBAL}:
            return "pubg-global"
        if hints == {BUNDLE_PUBG_VNG}:
            return "pubg-vng"
        for bundle, preset in ((BUNDLE_PUBG_KR, "pubg-kr"), (BUNDLE_PUBG_TW, "pubg-tw"), (BUNDLE_PUBG_BGMI, "pubg-bgmi")):
            if hints == {bundle}:
                return preset
        if len(hints) >= 3 and hints.issubset(set(PRESETS["pubg-5sv"]["bundles"])):
            return "pubg-5sv"
        return "pubg"


    if hints == {BUNDLE_LQ_ALT}:
        return "lq2"
    return "lq"




def lq_target(arcname: str) -> str:
    a = strip_common_wrappers(arcname)
    if a.startswith("payload/"):
        a = a[len("payload/"):]
    if a.startswith("Documents/"):
        return a
    return "Documents/" + a




def normalize_pubg_puffer_case(path: str) -> str:
    """Canonicalize only the PUBG puffer_temp directory (never the PAK filename)."""
    parts = path.replace("\\", "/").split("/")
    for i, part in enumerate(parts):
        if part.lower() == "puffer_temp":
            parts[i] = "puffer_temp"
    return "/".join(parts)


def pubg_target(arcname: str, pubg_folder: str = "preserve") -> str:
    a = strip_common_wrappers(arcname)
    if a.startswith("payload/"):
        a = a[len("payload/"):]
    if a.lower().startswith("documents/"):
        return normalize_pubg_puffer_case(a)


    low = a.lower()
    if "shadowtrackerextra/" in low:
        idx = low.index("shadowtrackerextra/")
        return normalize_pubg_puffer_case("Documents/" + a[idx:])


    base = PurePosixPath(a).name
    if pubg_folder == "puffer_temp" or "puffer_temp/" in low:
        return f"Documents/ShadowTrackerExtra/Saved/Paks/puffer_temp/{base}"
    return f"Documents/ShadowTrackerExtra/Saved/Paks/{base}"




def _split_posix(path: str):
    return [p for p in (path or "").replace("\\", "/").strip("/").split("/") if p and p != "."]




def apply_custom_prefix(prefix: str, rel_path: str) -> str:
    p = _split_posix(prefix)
    f = _split_posix(rel_path)
    if ".." in p or ".." in f:
        raise ValueError("Đường dẫn tùy chỉnh không được chứa '..'")
    if not p:
        return "/".join(f)
    if not f:
        return "/".join(p)


    max_k = min(len(p), len(f))
    overlap = 0
    for k in range(max_k, 0, -1):
        if [x.lower() for x in p[-k:]] == [x.lower() for x in f[:k]]:
            overlap = k
            break


    joined = p + f[overlap:]
    protected = {"documents", "resources", "saved", "paks", "shadowtrackerextra"}
    cleaned: list[str] = []
    for part in joined:
        if cleaned and cleaned[-1].lower() == part.lower() and part.lower() in protected:
            continue
        cleaned.append(part)
    return "/".join(cleaned)




def _custom_target_for_arcname(arcname: str, prefix: str) -> str:
    a = strip_common_wrappers(arcname)
    if a.startswith("payload/"):
        a = a[len("payload/"):]
    return apply_custom_prefix(prefix, a)




def _resolve_target_and_bundles(
    arcname: str,
    preset_name: str,
    bundle_ids: list[str],
    dual: bool,
    pubg_folder: str,
    path_mode: str,
    custom_prefix: str | None,
):
    parts = list(PurePosixPath(arcname.replace("\\", "/")).parts)
    bundle_hint, _ = find_bundle_hint(parts)


    if path_mode == "custom" and custom_prefix:
        target = _custom_target_for_arcname(arcname, custom_prefix)
    elif preset_name.startswith("pubg"):
        target = pubg_target(arcname, pubg_folder)
    else:
        target = lq_target(arcname)


    if bundle_hint and bundle_hint in bundle_ids:
        target_bundles = [bundle_hint]
    elif dual and len(bundle_ids) > 1:
        target_bundles = list(bundle_ids)
    else:
        target_bundles = [bundle_ids[0]]


    if preset_name.startswith("pubg"):
        target = normalize_pubg_puffer_case(target)
    return target, target_bundles




def _export_artifact_reason(name: str, data: bytes) -> str | None:
    """Return a reason only for files that are clearly generated by 3105 Pro ZIP export tools."""
    low = name.lower().replace("\\", "/")
    base = PurePosixPath(name).name.lower()

    if low.startswith(("_xung_dot/", "xung_dot/", "conflicts/", "_bao_cao/", "bao_cao/")):
        return "thư mục báo cáo/xung đột do công cụ ZIP tạo"
    if "/_xung_dot/" in low or "/conflicts/" in low:
        return "bản sao xung đột do công cụ ZIP tạo"
    if base == "conflict_report.json" or base.endswith("_report.json"):
        return "file báo cáo do công cụ ZIP tạo"
    if base == "manifest.json":
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception:
            obj = None
        if isinstance(obj, dict):
            markers = {"sourcePackage", "schemaVersion", "packageID", "projectName", "files"}
            if len(markers.intersection(obj.keys())) >= 3:
                return "manifest do 3105 Pro tạo"
    return None



def _dedupe_export_entries(entries, return_skipped: bool = False):
    """Remove only recognized tool-generated report artifacts.

    Game files are never removed here. In particular, payload/ entries and files
    outside Resources/ are kept; downstream target collision handling will
    dedupe identical content or raise on conflicting SHA-256.
    """
    kept = []
    skipped = []
    for name, data in entries:
        reason = _export_artifact_reason(name, data)
        if reason:
            skipped.append({
                "path": name.replace("\\", "/"),
                "reason": reason,
                "size": len(data),
                "sha256": sha256_hex(data),
            })
            continue
        kept.append((name, data))

    if return_skipped:
        return kept, skipped
    return kept



def _filter_entries_for_preset(entries, preset_name: str):
    """Compatibility hook: V1.4 no longer filters game files by preset.

    Older code kept only Resources/ for Liên Quân when any Resources entry was
    present. That silently discarded other user files. All game entries now
    continue to path resolution; notable/system-like LQ files are warning-only.
    """
    return list(entries)



def make_rule(
    schema_version: int,
    bundle_id: str,
    target_path: str,
    filename: str,
    data: bytes,
) -> dict:
    rule = {
        "id": new_uuid(),
        "bundleID": bundle_id,
        "relativePath": target_path,
        "replacementFilename": filename,
        "replacementData": data,
    }
    if schema_version >= 9:
        rule = {
            "id": rule["id"],
            "operation": "replace",
            "containerKind": "application",
            "bundleID": bundle_id,
            "relativePath": target_path,
            "replacementFilename": filename,
            "replacementData": data,
        }
    return rule




def parse_target_overrides(raw):
    """Source-path -> target-path, or source-path -> {bundleID: target-path}."""
    if not raw:
        return {}
    obj = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(obj, dict) or len(obj) > 20000:
        raise ValueError("target_overrides phải là JSON object tối đa 20000 mục")
    result = {}
    for source, value in obj.items():
        if not isinstance(source, str) or not source or source.startswith("/") or ".." in source.replace("\\", "/").split("/"):
            raise ValueError("Source override không hợp lệ")
        if isinstance(value, dict):
            result[source] = {str(b): validate_target_path(t) for b, t in value.items()}
        else:
            result[source] = validate_target_path(value)
    return result


def validate_target_path(value):
    if not isinstance(value, str):
        raise ValueError("Đường dẫn đích phải là chuỗi")
    path = value.replace("\\", "/").strip()
    parts = path.split("/")
    if (not path or path.startswith("/") or any(x in ("", ".", "..") for x in parts)
            or ":" in path or "\x00" in path or any(ord(c) < 32 for c in path)):
        raise ValueError("Đường dẫn đích không an toàn: " + repr(value))
    if parts[0] != "Documents":
        raise ValueError("Đường dẫn đích phải bắt đầu bằng Documents/")
    return normalize_pubg_puffer_case(path)


def overridden_target(source, bundle, default, overrides):
    val = overrides.get(source.replace("\\", "/"))
    if isinstance(val, dict):
        return val.get(bundle, default)
    return val if val is not None else default


def build_rules_from_entries(
    entries,
    preset_name: str,
    bundle_ids: list[str],
    dual: bool,
    schema_version: int,
    rename_global: str | None = None,
    rename_vng: str | None = None,
    pubg_folder: str = "preserve",
    path_mode: str = "auto",
    custom_prefix: str | None = None,
    target_overrides=None,
):
    target_overrides = parse_target_overrides(target_overrides)
    entries = _filter_entries_for_preset(_dedupe_export_entries(entries), preset_name)
    if preset_name == "pubg-5sv":
        explicit = {}
        for path, blob in entries:
            hint, _ = find_bundle_hint(list(PurePosixPath(path.replace("\\", "/")).parts))
            if hint in PRESETS["pubg-5sv"]["bundles"]:
                explicit.setdefault(PurePosixPath(path).name, set()).add(sha256_hex(blob))
        if explicit:
            entries = [(path, blob) for path, blob in entries if not (
                path.lower().startswith("payload/") and
                PurePosixPath(path).name in explicit and
                sha256_hex(blob) in explicit[PurePosixPath(path).name]
            )]
    rule_map: dict[tuple[str, str], dict] = {}


    for arcname, data in entries:
        target, target_bundles = _resolve_target_and_bundles(
            arcname,
            preset_name,
            bundle_ids,
            dual,
            pubg_folder,
            path_mode,
            custom_prefix,
        )


        for bundle in target_bundles:
            final_target = overridden_target(arcname, bundle, target, target_overrides)
            filename = PurePosixPath(final_target).name


            if preset_name.startswith("pubg") and filename.lower().endswith(".pak"):
                rename = None
                if bundle == BUNDLE_PUBG_GLOBAL:
                    rename = rename_global
                elif bundle == BUNDLE_PUBG_VNG:
                    rename = rename_vng


                if rename:
                    filename = PurePosixPath(rename).name
                    parent = str(PurePosixPath(final_target).parent)
                    final_target = f"{parent}/{filename}"


            key = (bundle, final_target)
            existing = rule_map.get(key)
            if existing is not None:
                old_sha = sha256_hex(existing.get("replacementData", b""))
                new_sha = sha256_hex(data)
                if old_sha == new_sha:
                    # Cùng target + cùng nội dung: chỉ giữ một rule.
                    continue
                raise ValueError(
                    "Xung đột duplicate target: "
                    f"{bundle}:{final_target} có SHA-256 khác nhau "
                    f"({old_sha} != {new_sha})"
                )

            rule_map[key] = make_rule(
                schema_version, bundle, final_target, filename, data
            )


    return list(rule_map.values())




def diagnose_entries(
    entries,
    preset_name: str = "auto",
    bundle_ids: list[str] | None = None,
    dual: bool | None = None,
    path_mode: str = "auto",
    custom_prefix: str | None = None,
    pubg_folder: str = "preserve",
) -> dict:
    if preset_name == "auto":
        preset_name = auto_detect_preset(entries)

    preset = PRESETS.get(preset_name, PRESETS["lq"])
    if not bundle_ids:
        bundle_ids = list(preset["bundles"])
    if dual is None:
        dual = bool(preset["dual"]) or len(bundle_ids) > 1

    zero_byte = []
    notable = []
    versions = set()

    for name, data in entries:
        arc = name.replace("\\", "/")
        base = PurePosixPath(arc).name
        if len(data) == 0:
            zero_byte.append(arc)
        if base.lower() in NOTABLE_LQ_BASENAMES:
            notable.append(arc)
        m = re.search(r"(?:^|/)Resources/([^/]+)/", arc, re.I)
        if m:
            versions.add(m.group(1))

    selected, excluded_export_entries = _dedupe_export_entries(entries, return_skipped=True)
    filtered = _filter_entries_for_preset(selected, preset_name)

    target_items: dict[tuple[str, str], list[dict]] = {}
    for arcname, data in filtered:
        target, target_bundles = _resolve_target_and_bundles(
            arcname,
            preset_name,
            bundle_ids,
            dual,
            pubg_folder,
            path_mode,
            custom_prefix,
        )
        for bundle in target_bundles:
            key = (bundle, target)
            target_items.setdefault(key, []).append({
                "source": arcname.replace("\\", "/"),
                "sha256": sha256_hex(data),
                "size": len(data),
            })

    duplicate_targets = []
    conflicting_duplicate_targets = []
    dedupable_duplicate_targets = []
    for (bundle, rel), items in sorted(target_items.items()):
        if len(items) <= 1:
            continue
        unique_sha = sorted({item["sha256"] for item in items})
        item = {
            "bundleID": bundle,
            "relativePath": rel,
            "count": len(items),
            "sha256": unique_sha,
            "sources": [x["source"] for x in items],
            "result": "DEDUPE" if len(unique_sha) == 1 else "ERROR",
        }
        duplicate_targets.append(item)
        if len(unique_sha) == 1:
            dedupable_duplicate_targets.append(item)
        else:
            conflicting_duplicate_targets.append(item)

    warnings = []
    errors = []
    if zero_byte:
        warnings.append(f"Có {len(zero_byte)} file 0 byte")
    if dedupable_duplicate_targets:
        warnings.append(
            f"Có {len(dedupable_duplicate_targets)} target trùng nhưng cùng SHA-256 — sẽ dedupe"
        )
    if conflicting_duplicate_targets:
        errors.append(
            f"Có {len(conflicting_duplicate_targets)} target trùng nhưng SHA-256 khác nhau — phải dừng xử lý"
        )
    if len(versions) > 1:
        warnings.append("Nhiều phiên bản Resources: " + ", ".join(sorted(versions)))
    if notable:
        warnings.append(
            f"Có {len(notable)} file hệ thống Liên Quân cần chú ý — chỉ cảnh báo, không tự xóa"
        )
    if excluded_export_entries:
        warnings.append(
            f"Có {len(excluded_export_entries)} file báo cáo/phụ trợ do 3105 Pro tạo sẽ không đưa vào game; danh sách được hiển thị trong diagnostics"
        )

    status = "ERROR" if errors else ("WARN" if warnings else "OK")
    return {
        "status": status,
        "preset": preset_name,
        "zero_byte": zero_byte,
        "duplicate_targets": duplicate_targets,
        "dedupable_duplicate_targets": dedupable_duplicate_targets,
        "conflicting_duplicate_targets": conflicting_duplicate_targets,
        "resource_versions": sorted(versions),
        "notable_lq_files": notable,
        "excluded_export_entries": excluded_export_entries,
        "warnings": warnings,
        "errors": errors,
    }



def preview_paths(
    entries,
    preset_name: str,
    bundle_ids: list[str],
    dual: bool,
    schema_version: int,
    path_mode: str = "auto",
    custom_prefix: str | None = None,
    pubg_folder: str = "preserve",
    max_rows: int = 100,
    target_overrides=None,
    page: int = 1,
):
    target_overrides = parse_target_overrides(target_overrides)
    if preset_name == "auto":
        preset_name = auto_detect_preset(entries)


    preset = PRESETS[preset_name]
    if not bundle_ids:
        bundle_ids = list(preset["bundles"])


    rules = build_rules_from_entries(
        entries,
        preset_name,
        bundle_ids,
        dual,
        schema_version,
        pubg_folder=pubg_folder,
        path_mode=path_mode,
        custom_prefix=custom_prefix,
        target_overrides=target_overrides,
    )


    rows = []
    filtered = _filter_entries_for_preset(_dedupe_export_entries(entries), preset_name)
    for arcname, data in filtered:
        target, target_bundles = _resolve_target_and_bundles(
            arcname,
            preset_name,
            bundle_ids,
            dual,
            pubg_folder,
            path_mode,
            custom_prefix,
        )
        for bundle in target_bundles:
            actual_target = overridden_target(arcname, bundle, target, target_overrides)
            rows.append({
                "terminal": "replace --bundle " + bundle + " --target " + json.dumps(actual_target, ensure_ascii=False),
                "source": arcname.replace("\\", "/"),
                "bundleID": bundle,
                "target": actual_target,
                "size": len(data),
                "sha256": sha256_hex(data),
            })


    diagnostics = diagnose_entries(
        entries,
        preset_name,
        bundle_ids=bundle_ids,
        dual=dual,
        path_mode=path_mode,
        custom_prefix=custom_prefix,
        pubg_folder=pubg_folder,
    )


    page = max(1, int(page))
    max_rows = max(1, min(100, int(max_rows)))
    offset = (page - 1) * max_rows
    return {
        "page": page,
        "page_size": max_rows,
        "total_rows": len(rows),
        "total_pages": max(1, (len(rows) + max_rows - 1) // max_rows),
        "preset": preset_name,
        "bundles": list(bundle_ids),
        "schema": int(schema_version),
        "source_file_count": len(entries),
        "rule_count": len(rules),
        "resources_versions": diagnostics["resource_versions"],
        "rows": rows[offset:offset + max_rows],
        "truncated": len(rows) > max_rows,
        "diagnostics": diagnostics,
    }




def smart_update_stats(old_rules, new_rules) -> dict:
    old_index = {
        (r.get("bundleID"), r.get("relativePath")): sha256_digest(r.get("replacementData", b""))
        for r in old_rules
    }


    added = overwritten = same = 0
    for rule in new_rules:
        key = (rule.get("bundleID"), rule.get("relativePath"))
        digest = sha256_digest(rule.get("replacementData", b""))
        if key not in old_index:
            added += 1
        elif old_index[key] == digest:
            same += 1
        else:
            overwritten += 1


    return {
        "old_total": len(old_index),
        "incoming_total": len(new_rules),
        "added": added,
        "overwritten": overwritten,
        "same": same,
        "final_total": len(old_index) + added,
    }




def _parent_dirs(target_path: str):
    parts = target_path.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[:i])




def make_directory(schema_version: int, bundle_id: str, relative_path: str) -> dict:
    d = {
        "id": new_uuid(),
        "bundleID": bundle_id,
        "relativePath": relative_path,
    }
    if schema_version >= 9:
        d["containerKind"] = "application"
    return d




def build_payload(
    rules,
    bundle_ids,
    project_name,
    author,
    schema_version: int,
    project_id: str | None = None,
    is_private: bool = True,
    app_group_ids=None,
    system_app_group_ids=None,
    settings=None,
    created_at=None,
    updated_at=None,
):
    created_at = created_at if isinstance(created_at, datetime) else utc_plist_date()
    updated_at = updated_at if isinstance(updated_at, datetime) else utc_plist_date()
    project_id = (project_id or new_uuid()).upper()


    digests = {
        r["id"]: sha256_digest(r["replacementData"])
        for r in rules
    }


    dir_keys = set()
    for rule in rules:
        for rel in _parent_dirs(rule["relativePath"]):
            dir_keys.add((rule["bundleID"], rel))


    directories = [
        make_directory(schema_version, bundle, rel)
        for bundle, rel in sorted(dir_keys, key=lambda x: (x[0], x[1]))
    ]


    project = {
        "id": project_id,
        "name": project_name,
        "author": author,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "bundleIdentifiers": list(dict.fromkeys(bundle_ids)),
        "directories": directories,
        "rules": rules,
    }


    if schema_version >= 9:
        project = {
            "id": project["id"],
            "name": project["name"],
            "author": project["author"],
            "isPrivate": bool(is_private),
            "createdAt": project["createdAt"],
            "updatedAt": project["updatedAt"],
            "bundleIdentifiers": project["bundleIdentifiers"],
            "appGroupIdentifiers": list(app_group_ids or []),
            "systemAppGroupIdentifiers": list(system_app_group_ids or []),
            "settings": settings if isinstance(settings, list) else [],
            "directories": project["directories"],
            "rules": project["rules"],
        }


    return {
        "project": project,
        "replacementDigests": digests,
    }




def infer_preset_from_payload(meta: dict, payload: dict) -> str:
    bundles = set(payload.get("project", {}).get("bundleIdentifiers", []))
    if bundles == {BUNDLE_PUBG_GLOBAL, BUNDLE_PUBG_VNG}:
        return "pubg"
    if bundles == {BUNDLE_PUBG_GLOBAL}:
        return "pubg-global"
    if bundles == {BUNDLE_PUBG_VNG}:
        return "pubg-vng"
    for bundle, preset in ((BUNDLE_PUBG_KR, "pubg-kr"), (BUNDLE_PUBG_TW, "pubg-tw"), (BUNDLE_PUBG_BGMI, "pubg-bgmi")):
        if bundles == {bundle}:
            return preset
    if bundles == {BUNDLE_LQ_ALT}:
        return "lq2"
    if bundles == {BUNDLE_LQ}:
        return "lq"
    return "pubg" if int(meta.get("schemaVersion", 1)) <= 2 else "lq"




def verify_meta_and_payload(meta: dict, payload: dict, quiet: bool = False) -> bool:
    ok = True


    for key in ("schemaVersion", "keyAADVersion", "packageID", "keyFingerprint", "encryptedPayload"):
        if key not in meta:
            ok = False
            if not quiet:
                print(f"[verify] thiếu meta.{key}")


    fp = meta.get("keyFingerprint")
    if not isinstance(fp, (bytes, bytearray)) or len(fp) != 32:
        ok = False
        if not quiet:
            print("[verify] keyFingerprint sai kiểu/độ dài")


    project = payload.get("project", {})
    rules = project.get("rules", [])
    digests = payload.get("replacementDigests", {})


    required_project = [
        "id", "name", "author", "createdAt", "updatedAt",
        "bundleIdentifiers", "directories", "rules",
    ]
    for key in required_project:
        if key not in project:
            ok = False
            if not quiet:
                print(f"[verify] thiếu project.{key}")


    if not isinstance(project.get("createdAt"), datetime) or not isinstance(project.get("updatedAt"), datetime):
        ok = False
        if not quiet:
            print("[verify] createdAt/updatedAt phải là datetime plist")


    schema = int(meta.get("schemaVersion", 1))
    seen_keys = set()


    for rule in rules:
        required_rule = ("id", "bundleID", "relativePath", "replacementFilename", "replacementData")
        if not all(k in rule for k in required_rule):
            ok = False
            continue


        key = (rule["bundleID"], rule["relativePath"])
        if key in seen_keys:
            ok = False
            if not quiet:
                print(f"[verify] duplicate rule: {key}")
        seen_keys.add(key)


        if schema >= 9:
            if rule.get("operation") != "replace" or rule.get("containerKind") != "application":
                ok = False


        expected = digests.get(rule["id"])
        if not isinstance(expected, (bytes, bytearray)) or len(expected) != 32:
            ok = False
            if not quiet:
                print(f"[verify] digest thiếu/sai: {rule['id']}")
        elif sha256_digest(rule["replacementData"]) != bytes(expected):
            ok = False
            if not quiet:
                print(f"[verify] SHA mismatch: {rule['relativePath']}")


    for directory in project.get("directories", []):
        if not all(k in directory for k in ("id", "bundleID", "relativePath")):
            ok = False
        if schema >= 9 and directory.get("containerKind") != "application":
            ok = False


    if not quiet:
        print(f"[verify] packageID = {meta.get('packageID')}")
        print(f"[verify] schemaVersion = {schema}")
        print(f"[verify] project = {project.get('name')}")
        print(f"[verify] author = {project.get('author')}")
        print(f"[verify] bundles = {project.get('bundleIdentifiers')}")
        print(f"[verify] rules = {len(rules)}")
        print("[verify] OK" if ok else "[verify] CÓ LỖI")


    return ok




def verify_file(path: str | Path, password: str | None, quiet: bool = False) -> bool:
    meta = read_container(path)
    _, payload = unlock_container(meta, password)
    return verify_meta_and_payload(meta, payload, quiet=quiet)




def extract_to_zip(file_path: str | Path, out_zip: str | Path, password: str | None):
    meta = read_container(file_path)
    _, payload = unlock_container(meta, password)
    project = payload["project"]


    manifest = {
        "sourcePackage": Path(file_path).name,
        "schemaVersion": meta.get("schemaVersion"),
        "packageID": meta.get("packageID"),
        "projectName": project.get("name"),
        "author": project.get("author"),
        "bundleIdentifiers": project.get("bundleIdentifiers", []),
        "files": [],
    }


    seen_hash = set()
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rule in project.get("rules", []):
            data = rule.get("replacementData", b"")
            bundle = rule.get("bundleID", "unknown.bundle")
            rel = rule.get("relativePath", rule.get("replacementFilename", "file.bin"))
            filename = rule.get("replacementFilename") or PurePosixPath(rel).name
            sha = sha256_hex(data)


            manifest["files"].append({
                "bundleID": bundle,
                "relativePath": rel,
                "replacementFilename": filename,
                "size": len(data),
                "sha256": sha,
            })
            zf.writestr(f"{bundle}/{rel}", data)


            if sha not in seen_hash:
                zf.writestr(f"payload/{filename}", data)
                seen_hash.add(sha)


        zf.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )
    return manifest




def _resolve_preset(requested: str, entries):
    return auto_detect_preset(entries) if requested == "auto" else requested




def cmd_inspect(args):
    meta = read_container(args.file)
    print(f"[inspect] magic OK ({MAGIC!r})")
    for key in ("packageID", "schemaVersion", "keyAADVersion", "isPasswordProtected", "kdfIterations"):
        print(f"[inspect] {key:20} = {meta.get(key)}")


    if meta.get("isPasswordProtected") and not args.password:
        print("[inspect] Cần --password để decrypt payload")
        return


    _, payload = unlock_container(meta, args.password)
    project = payload["project"]
    print(f"[project] name = {project.get('name')}")
    print(f"[project] author = {project.get('author')}")
    print(f"[project] bundles = {project.get('bundleIdentifiers')}")
    print(f"[project] createdAt = {project.get('createdAt')}")
    print(f"[project] updatedAt = {project.get('updatedAt')}")
    print(f"[project] rules = {len(project.get('rules', []))}")
    print(f"[project] directories = {len(project.get('directories', []))}")
    verify_meta_and_payload(meta, payload)




def cmd_preview(args):
    entries = input_entries(args.input)
    preset_name = _resolve_preset(args.preset, entries)
    preset = PRESETS[preset_name]
    bundle_ids = list(args.bundle) if args.bundle else list(preset["bundles"])
    dual = bool(args.dual_bundle) if args.dual_bundle is not None else bool(preset["dual"])
    if len(bundle_ids) > 1:
        dual = True
    schema = int(args.schema if args.schema is not None else preset["schema"])


    info = preview_paths(
        entries,
        preset_name,
        bundle_ids,
        dual,
        schema,
        path_mode=args.path_mode,
        custom_prefix=args.prefix,
        pubg_folder=args.pubg_folder,
        max_rows=args.max_rows,
    )
    print(json.dumps(info, ensure_ascii=False, indent=2))




def cmd_build(args):
    entries = input_entries(args.input)
    preset_name = _resolve_preset(args.preset, entries)
    preset = PRESETS[preset_name]
    bundle_ids = list(args.bundle) if args.bundle else list(preset["bundles"])
    dual = bool(args.dual_bundle) if args.dual_bundle is not None else bool(preset["dual"])
    if len(bundle_ids) > 1:
        dual = True
    schema = int(args.schema if args.schema is not None else preset["schema"])


    rules = build_rules_from_entries(
        entries,
        preset_name,
        bundle_ids,
        dual,
        schema,
        rename_global=args.rename_global,
        rename_vng=args.rename_vng,
        pubg_folder=args.pubg_folder,
        path_mode=args.path_mode,
        custom_prefix=args.prefix,
        target_overrides=args.target_overrides,
    )
    if not rules:
        raise ValueError("Không có file hợp lệ để tạo rule")


    project_id = (args.package_id or new_uuid()).upper()
    payload = build_payload(
        rules,
        bundle_ids,
        args.name,
        args.author,
        schema,
        project_id=project_id,
        is_private=not args.no_password,
    )
    password = None if args.no_password else args.password
    meta = build_container(
        payload,
        password=password,
        package_id=project_id,
        schema_version=schema,
        key_aad_version=schema,
        iterations=args.iterations,
    )
    write_container(args.out, meta)


    if not verify_file(args.out, password, quiet=True):
        raise RuntimeError("Verify thất bại sau khi build")
    print(f"[build] Đã tạo {args.out}")




def cmd_extract(args):
    manifest = extract_to_zip(args.file, args.out, args.password)
    print(f"[extract] Project: {manifest['projectName']}")
    print(f"[extract] Files: {len(manifest['files'])}")
    print(f"[extract] Đã ghi: {args.out}")




def _dedupe_existing_rules(rules):
    ordered_keys = []
    mapping = {}
    for rule in rules:
        key = (rule.get("bundleID"), rule.get("relativePath"))
        existing = mapping.get(key)
        if existing is None:
            ordered_keys.append(key)
            mapping[key] = rule
            continue

        old_sha = sha256_hex(existing.get("replacementData", b""))
        new_sha = sha256_hex(rule.get("replacementData", b""))
        if old_sha == new_sha:
            # Package cũ có rule trùng nhưng cùng nội dung: dedupe an toàn.
            continue
        raise ValueError(
            "Package cũ có duplicate rule xung đột: "
            f"{key[0]}:{key[1]} có SHA-256 khác nhau "
            f"({old_sha} != {new_sha})"
        )

    return [mapping[key] for key in ordered_keys]




def cmd_update(args):
    old_meta = read_container(args.old)
    _, old_payload = unlock_container(old_meta, args.password)
    old_project = old_payload["project"]


    existing_rules = _dedupe_existing_rules(list(old_project.get("rules", [])))
    index = {(r.get("bundleID"), r.get("relativePath")): r for r in existing_rules}


    entries = input_entries(args.new_input)
    preset_name = args.preset if args.preset != "auto" else infer_preset_from_payload(old_meta, old_payload)
    preset = PRESETS[preset_name]
    bundle_ids = list(args.bundle) if args.bundle else list(
        old_project.get("bundleIdentifiers") or preset["bundles"]
    )
    dual = bool(args.dual_bundle) if args.dual_bundle is not None else len(bundle_ids) > 1
    schema = int(old_meta.get("schemaVersion", preset["schema"]))


    incoming = build_rules_from_entries(
        entries,
        preset_name,
        bundle_ids,
        dual,
        schema,
        rename_global=args.rename_global,
        rename_vng=args.rename_vng,
        pubg_folder=args.pubg_folder,
        path_mode=args.path_mode,
        custom_prefix=args.prefix,
    )
    stats = smart_update_stats(existing_rules, incoming)


    for new_rule in incoming:
        key = (new_rule["bundleID"], new_rule["relativePath"])
        old_rule = index.get(key)


        if old_rule is None:
            existing_rules.append(new_rule)
            index[key] = new_rule
            continue


        if sha256_digest(old_rule.get("replacementData", b"")) == sha256_digest(new_rule["replacementData"]):
            continue


        old_rule["replacementData"] = new_rule["replacementData"]
        old_rule["replacementFilename"] = new_rule["replacementFilename"]
        if schema >= 9:
            old_rule["operation"] = "replace"
            old_rule["containerKind"] = "application"
        else:
            old_rule.pop("operation", None)
            old_rule.pop("containerKind", None)


    name = args.name or old_project.get("name") or "3105 Project"
    author = args.author or old_project.get("author") or DEFAULT_AUTHOR


    payload = build_payload(
        existing_rules,
        bundle_ids,
        name,
        author,
        schema,
        project_id=old_project.get("id") or old_meta.get("packageID"),
        is_private=old_project.get("isPrivate", True),
        app_group_ids=old_project.get("appGroupIdentifiers"),
        system_app_group_ids=old_project.get("systemAppGroupIdentifiers"),
        settings=old_project.get("settings"),
        created_at=old_project.get("createdAt"),
        updated_at=utc_plist_date(),
    )


    new_password = args.new_password if args.new_password is not None else args.password
    meta = build_container(
        payload,
        new_password,
        package_id=old_meta.get("packageID"),
        schema_version=schema,
        key_aad_version=int(old_meta.get("keyAADVersion", schema)),
        iterations=int(old_meta.get("kdfIterations", DEFAULT_ITERATIONS)),
    )
    write_container(args.out, meta)


    if not verify_file(args.out, new_password, quiet=True):
        raise RuntimeError("Verify thất bại sau update")


    print(f"[update] Đã tạo {args.out}")
    print(f"[update-stats] {json.dumps(stats, ensure_ascii=False)}")




def replace_bundle_fields(payload: dict, old: str, new: str):
    project = payload.get("project", {})
    project["bundleIdentifiers"] = [
        new if value == old else value
        for value in project.get("bundleIdentifiers", [])
    ]
    for directory in project.get("directories", []):
        if directory.get("bundleID") == old:
            directory["bundleID"] = new
    for rule in project.get("rules", []):
        if rule.get("bundleID") == old:
            rule["bundleID"] = new
    return payload




def cmd_rebundle(args):
    meta = read_container(args.file)
    _, payload = unlock_container(meta, args.password)
    payload = replace_bundle_fields(payload, args.old_bundle, args.new_bundle)


    schema = int(meta.get("schemaVersion", 2))
    project = payload["project"]


    rebuilt = build_payload(
        project.get("rules", []),
        project.get("bundleIdentifiers", []),
        args.name or project.get("name") or "3105 Project",
        args.author or project.get("author") or DEFAULT_AUTHOR,
        schema,
        project_id=project.get("id"),
        is_private=project.get("isPrivate", True),
        app_group_ids=project.get("appGroupIdentifiers"),
        system_app_group_ids=project.get("systemAppGroupIdentifiers"),
        settings=project.get("settings"),
        created_at=project.get("createdAt"),
        updated_at=utc_plist_date(),
    )


    new_password = args.new_password if args.new_password is not None else args.password
    new_meta = build_container(
        rebuilt,
        new_password,
        package_id=meta.get("packageID"),
        schema_version=schema,
        key_aad_version=int(meta.get("keyAADVersion", schema)),
        iterations=int(meta.get("kdfIterations", DEFAULT_ITERATIONS)),
    )
    write_container(args.out, new_meta)


    if not verify_file(args.out, new_password, quiet=True):
        raise RuntimeError("Verify thất bại sau rebundle")
    print(f"[rebundle] {args.old_bundle} -> {args.new_bundle} | {args.out}")




def cmd_verify(args):
    ok = verify_file(args.file, args.password, quiet=False)
    raise SystemExit(0 if ok else 2)




def add_preset_opts(parser):
    parser.add_argument("--preset", default="auto", choices=["auto", *PRESETS.keys()])
    parser.add_argument("--dual-bundle", action="store_true", default=None)
    parser.add_argument("--bundle", action="append", default=None)
    parser.add_argument("--rename-global", default=None)
    parser.add_argument("--rename-vng", default=None)
    parser.add_argument(
        "--pubg-folder",
        choices=["preserve", "paks", "puffer_temp"],
        default="preserve",
    )




def add_path_opts(parser):
    parser.add_argument("--path-mode", choices=["auto", "custom"], default="auto")
    parser.add_argument("--prefix", default=None)




def main():
    parser = argparse.ArgumentParser(
        prog="3105tool",
        description="3105 builder — PUBG schema 2 / Liên Quân schema 9",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)


    p = sub.add_parser("inspect")
    p.add_argument("file")
    p.add_argument("--password", default=None)
    p.set_defaults(func=cmd_inspect)


    p = sub.add_parser("preview")
    p.add_argument("input")
    p.add_argument("--max-rows", type=int, default=100)
    p.add_argument("--schema", type=int, default=None)
    add_preset_opts(p)
    add_path_opts(p)
    p.set_defaults(func=cmd_preview)


    p = sub.add_parser("build")
    p.add_argument("input")
    p.add_argument("out")
    p.add_argument("--target-overrides", default=None)
    p.add_argument("--name", default="3105 Project")
    p.add_argument("--author", default=DEFAULT_AUTHOR)
    p.add_argument("--password", default=DEFAULT_PASSWORD)
    p.add_argument("--no-password", action="store_true")
    p.add_argument("--package-id", default=None)
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    p.add_argument("--schema", type=int, default=None)
    add_preset_opts(p)
    add_path_opts(p)
    p.set_defaults(func=cmd_build)


    p = sub.add_parser("extract")
    p.add_argument("file")
    p.add_argument("out")
    p.add_argument("--password", default=None)
    p.set_defaults(func=cmd_extract)


    p = sub.add_parser("update")
    p.add_argument("old")
    p.add_argument("new_input")
    p.add_argument("out")
    p.add_argument("--password", default=None)
    p.add_argument("--new-password", default=None)
    p.add_argument("--author", default=None)
    p.add_argument("--name", default=None)
    add_preset_opts(p)
    add_path_opts(p)
    p.set_defaults(func=cmd_update)


    p = sub.add_parser("rebundle")
    p.add_argument("file")
    p.add_argument("out")
    p.add_argument("--old-bundle", required=True)
    p.add_argument("--new-bundle", required=True)
    p.add_argument("--password", default=None)
    p.add_argument("--new-password", default=None)
    p.add_argument("--name", default=None)
    p.add_argument("--author", default=None)
    p.set_defaults(func=cmd_rebundle)


    p = sub.add_parser("verify")
    p.add_argument("file")
    p.add_argument("--password", default=None)
    p.set_defaults(func=cmd_verify)


    args = parser.parse_args()
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)




if __name__ == "__main__":
    main()