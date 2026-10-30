from flask import Flask, render_template, request, send_file, jsonify, after_this_request
from pathlib import Path
import hashlib, importlib.util, json, os, re, shutil, subprocess, sys, uuid, zipfile
from datetime import datetime
from urllib.parse import quote


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
OUTPUT_FOLDER = BASE_DIR / "outputs"
TOOL = BASE_DIR / "3105tool.py"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024
_TOOL_MODULE = None


def _tool_module():
    global _TOOL_MODULE
    if _TOOL_MODULE is None:
        spec = importlib.util.spec_from_file_location("tool3105_runtime", TOOL)
        if spec is None or spec.loader is None:
            raise RuntimeError("Không thể nạp bộ xử lý 3105")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _TOOL_MODULE = mod
    return _TOOL_MODULE


def _tmp_path(ext: str) -> Path:
    return UPLOAD_FOLDER / f"{uuid.uuid4()}{ext}"


def _save_upload(storage, allowed_exts: set[str]) -> Path:
    if storage is None or not storage.filename:
        raise ValueError("Chưa chọn file")
    ext = Path(storage.filename).suffix.lower()
    if ext not in allowed_exts:
        raise ValueError(f"Định dạng không hỗ trợ: {ext}")
    path = _tmp_path(ext)
    storage.save(path)
    return path


def _run(args: list[str]):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=str(BASE_DIR), check=True, capture_output=True,
        text=True, encoding="utf-8", env=env,
    )


def _error_text(exc: Exception) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        return ((exc.stdout or "") + "\n" + (exc.stderr or "")).strip()
    return str(exc)


def _manage_outputs(src: Path, filename: str):
    final = OUTPUT_FOLDER / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    shutil.copy(src, final)
    for f in sorted(OUTPUT_FOLDER.glob("*"), key=os.path.getmtime, reverse=True)[5:]:
        f.unlink(missing_ok=True)


def _download(path: Path, name: str, cleanup_paths=None):
    cleanup = [Path(p) for p in (cleanup_paths or [])] + [path]
    @after_this_request
    def _cleanup(response):
        for p in cleanup:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        return response
    return send_file(path, as_attachment=True, download_name=name)


def _verify(path: Path, password: str | None):
    mod = _tool_module()
    meta = mod.read_container(path)
    _, payload = mod.unlock_container(meta, password)
    ok = mod.verify_meta_and_payload(meta, payload, quiet=True)
    project = payload.get("project", {})
    return {
        "ok": bool(ok),
        "rules": len(project.get("rules", [])),
        "schema": int(meta.get("schemaVersion", 1)),
        "bundles": list(project.get("bundleIdentifiers", [])),
    }


def _parse_update_stats(stdout: str):
    for line in (stdout or "").splitlines():
        if line.startswith("[update-stats] "):
            try:
                return json.loads(line[len("[update-stats] "):])
            except Exception:
                return {}
    return {}


def _attach_diagnostic_headers(response, diagnostics: dict | None):
    diagnostics = diagnostics or {}
    warnings = diagnostics.get("warnings") or []
    errors = diagnostics.get("errors") or []
    response.headers["X-3105-Diagnostic-Status"] = str(diagnostics.get("status") or "OK")
    if warnings:
        response.headers["X-3105-Warnings"] = quote(
            json.dumps(warnings, ensure_ascii=False), safe=""
        )
    if errors:
        response.headers["X-3105-Diagnostic-Errors"] = quote(
            json.dumps(errors, ensure_ascii=False), safe=""
        )
    return response


def _diagnose_input(src: Path, preset: str = "auto", **kwargs):
    mod = _tool_module()
    entries = mod.input_entries(src)
    return mod.diagnose_entries(entries, preset, **kwargs)


def _combine_split_pubg(global_upload, vng_upload):
    combined = _tmp_path(".zip")
    cleanup = []
    def add(zout, storage, bundle):
        if storage is None or not storage.filename:
            return
        src = _save_upload(storage, {".zip", ".pak", ".bytes", ".txt", ".json"})
        cleanup.append(src)
        if src.suffix.lower() == ".zip":
            with zipfile.ZipFile(src) as zin:
                for info in zin.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename.replace("\\", "/").lstrip("/")
                    if not name or name.startswith("__MACOSX/") or Path(name).name.startswith("._"):
                        continue
                    zout.writestr(f"{bundle}/{name}", zin.read(info))
        else:
            zout.writestr(f"{bundle}/{Path(storage.filename).name}", src.read_bytes())
    with zipfile.ZipFile(combined, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        add(zout, global_upload, "com.tencent.ig")
        add(zout, vng_upload, "vn.vng.pubgmobile")
    return combined, cleanup


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/manifest.json")
def manifest():
    path = BASE_DIR / "manifest.json"
    if path.exists():
        return send_file(path, mimetype="application/json")
    return jsonify({"name":"3105 Pro","short_name":"3105 Pro","start_url":"/","display":"standalone"})


@app.route("/sw.js")
def service_worker():
    path = BASE_DIR / "sw.js"
    if path.exists():
        return send_file(path, mimetype="application/javascript")
    return "self.addEventListener('fetch',()=>{});", 200, {"Content-Type":"application/javascript"}


@app.route("/api/v2.1/analyze", methods=["POST"])
def analyze_v21():
    """Read-only content diagnostics. Never treat an extension as proof of format."""
    from analysis_engine import analyze_file
    upload = request.files.get("input_file")
    src = None
    try:
        src = _save_upload(upload, {".zip", ".ipa", ".pak", ".3105", ".bytes", ".json", ".txt"})
        return jsonify({"success": True, "analysis": analyze_file(src, upload.filename)})
    except Exception as exc:
        return jsonify({"success": False, "error": _error_text(exc)}), 400
    finally:
        if src:
            src.unlink(missing_ok=True)


@app.route("/api/v2.1/verify", methods=["POST"])
def verify_v21():
    """Decrypt and validate an uploaded 3105 container; report real verification status."""
    from analysis_engine import analyze_file
    upload = request.files.get("input_file")
    src = None
    try:
        src = _save_upload(upload, {".3105"})
        analysis = analyze_file(src, upload.filename)
        if analysis["format"] != "3105" or analysis["errors"]:
            return jsonify({"success": False, "status": "FAIL", "analysis": analysis}), 400
        verified = _verify(src, request.form.get("password") or None)
        return jsonify({"success": bool(verified["ok"]), "status": "PASS" if verified["ok"] else "FAIL", "verification": verified, "sha256": analysis["sha256"]})
    except Exception as exc:
        return jsonify({"success": False, "status": "FAIL", "error": _error_text(exc)}), 400
    finally:
        if src:
            src.unlink(missing_ok=True)


@app.route("/detect", methods=["POST"])
def detect():
    src = None
    try:
        src = _save_upload(
            request.files.get("input_file") or request.files.get("zip_file"),
            {".zip", ".pak", ".bytes", ".txt", ".json"},
        )
        mod = _tool_module()
        entries = mod.input_entries(src)
        return jsonify({
            "success": True,
            "preset": mod.auto_detect_preset(entries),
            "count": len(entries),
            "files": [name for name, _ in entries[:20]],
        })
    except Exception as exc:
        return jsonify({"success": False, "error": _error_text(exc)}), 400
    finally:
        if src:
            src.unlink(missing_ok=True)


@app.route("/preview_path", methods=["POST"])
def preview_path():
    src = None
    cleanup = []
    try:
        global_upload = request.files.get("global_input")
        vng_upload = request.files.get("vng_input")
        upload = request.files.get("input_file") or request.files.get("zip_file")


        if (global_upload and global_upload.filename) or (vng_upload and vng_upload.filename):
            src, cleanup = _combine_split_pubg(global_upload, vng_upload)
            preset = "pubg"
        elif upload and upload.filename:
            src = _save_upload(upload, {".zip", ".pak", ".bytes", ".txt", ".json"})
            preset = request.form.get("preset") or "auto"
        else:
            raise ValueError("Chưa chọn file")


        mod = _tool_module()
        entries = mod.input_entries(src)
        resolved = mod.auto_detect_preset(entries) if preset == "auto" else preset
        if resolved not in mod.PRESETS:
            raise ValueError("Loại game không hợp lệ")


        cfg = mod.PRESETS[resolved]
        custom_bundle = (request.form.get("bundle") or "").strip()
        bundle_ids = (
            [x.strip() for x in custom_bundle.split(",") if x.strip()]
            if custom_bundle else list(cfg["bundles"])
        )
        dual = bool(cfg["dual"]) or len(bundle_ids) > 1


        info = mod.preview_paths(
            entries, resolved, bundle_ids, dual, int(cfg["schema"]),
            path_mode=request.form.get("path_mode") or "auto",
            custom_prefix=(request.form.get("prefix") or "").strip() or None,
            pubg_folder=request.form.get("pubg_folder") or "preserve",
            max_rows=100,
            page=request.form.get("page", 1),
            target_overrides=request.form.get("target_overrides"),
        )
        return jsonify({"success": True, **info})
    except Exception as exc:
        return jsonify({"success": False, "error": _error_text(exc)}), 400
    finally:
        for p in ([src] if src else []) + cleanup:
            try:
                Path(p).unlink(missing_ok=True)
            except Exception:
                pass


@app.route("/build", methods=["POST"])
def build():
    src = out = None
    cleanup = []
    try:
        global_upload = request.files.get("global_input")
        vng_upload = request.files.get("vng_input")
        if (global_upload and global_upload.filename) or (vng_upload and vng_upload.filename):
            src, cleanup = _combine_split_pubg(global_upload, vng_upload)
            preset = "pubg"
        else:
            src = _save_upload(
                request.files.get("input_file") or request.files.get("zip_file"),
                {".zip", ".pak", ".bytes", ".txt", ".json"},
            )
            preset = request.form.get("preset") or "auto"


        out = _tmp_path(".3105")
        name = (request.form.get("name") or "3105 Project").strip()
        author = (request.form.get("author") or "MANZ-VIP").strip()
        password = (request.form.get("password") or "").strip()
        pubg_folder = request.form.get("pubg_folder") or "preserve"
        rename_global = (request.form.get("rename_global") or "").strip()
        rename_vng = (request.form.get("rename_vng") or "").strip()
        custom_bundle = (request.form.get("bundle") or "").strip()
        path_mode = request.form.get("path_mode") or "auto"
        prefix = (request.form.get("prefix") or "").strip()


        args = [
            "build", str(src), str(out),
            "--name", name, "--author", author,
            "--preset", preset, "--pubg-folder", pubg_folder,
        ]
        args += ["--password", password] if password else ["--no-password"]


        if request.form.get("target_overrides"):
            args += ["--target-overrides", request.form["target_overrides"]]
        if custom_bundle:
            for bundle in [x.strip() for x in custom_bundle.split(",") if x.strip()]:
                args += ["--bundle", bundle]
        if rename_global:
            args += ["--rename-global", rename_global]
        if rename_vng:
            args += ["--rename-vng", rename_vng]
        if path_mode == "custom" and prefix:
            args += ["--path-mode", "custom", "--prefix", prefix]

        mod = _tool_module()
        source_entries = mod.input_entries(src)
        resolved_preset = mod.auto_detect_preset(source_entries) if preset == "auto" else preset
        cfg = mod.PRESETS[resolved_preset]
        diag_bundles = (
            [x.strip() for x in custom_bundle.split(",") if x.strip()]
            if custom_bundle else list(cfg["bundles"])
        )
        source_diag = mod.diagnose_entries(
            source_entries,
            resolved_preset,
            bundle_ids=diag_bundles,
            dual=(bool(cfg["dual"]) or len(diag_bundles) > 1),
            path_mode=path_mode,
            custom_prefix=prefix or None,
            pubg_folder=pubg_folder,
        )
        if request.form.get("target_overrides"):
            mod.build_rules_from_entries(source_entries, resolved_preset, diag_bundles, bool(cfg["dual"]) or len(diag_bundles)>1, int(cfg["schema"]), pubg_folder=pubg_folder, path_mode=path_mode, custom_prefix=prefix or None, target_overrides=request.form["target_overrides"])
        if source_diag.get("errors"):
            raise ValueError("DIAGNOSTICS ERROR: " + "; ".join(source_diag["errors"]))

        _run(args)
        verify_info = _verify(out, password or None)
        if not verify_info["ok"]:
            raise ValueError("VERIFY LỖI sau build")


        download_name = f"{re.sub(r'[/\\\\]+', '_', name) or 'output'}.3105"
        _manage_outputs(out, download_name)
        response = _download(out, download_name, cleanup_paths=[src, *cleanup])
        response.headers["X-3105-Verify"] = "OK"
        response.headers["X-3105-Rules"] = str(verify_info["rules"])
        response.headers["X-3105-Schema"] = str(verify_info["schema"])
        response.headers["X-3105-Bundles"] = ",".join(verify_info["bundles"])
        _attach_diagnostic_headers(response, source_diag)
        return response
    except Exception as exc:
        for p in [src, out, *cleanup]:
            if p:
                Path(p).unlink(missing_ok=True)
        return _error_text(exc), 400


@app.route("/inspect", methods=["POST"])
def inspect():
    src = None
    try:
        src = _save_upload(request.files.get("file_3105"), {".3105"})
        password = (request.form.get("password") or "").strip()
        args = ["inspect", str(src)]
        if password:
            args += ["--password", password]
        result = _run(args)
        return jsonify({"success": True, "output": result.stdout})
    except Exception as exc:
        return jsonify({"success": False, "output": _error_text(exc)})
    finally:
        if src:
            src.unlink(missing_ok=True)


@app.route("/extract", methods=["POST"])
def extract():
    src = out = None
    try:
        src = _save_upload(request.files.get("file_3105"), {".3105"})
        out = _tmp_path(".zip")
        password = (request.form.get("password") or "").strip()
        args = ["extract", str(src), str(out)]
        if password:
            args += ["--password", password]
        _run(args)
        base = Path(request.files["file_3105"].filename).stem
        download_name = f"{base}_extracted.zip"
        _manage_outputs(out, download_name)
        return _download(out, download_name, cleanup_paths=[src])
    except Exception as exc:
        for p in (src, out):
            if p:
                Path(p).unlink(missing_ok=True)
        return _error_text(exc), 400


@app.route("/update", methods=["POST"])
def update():
    old = new = out = None
    try:
        old = _save_upload(request.files.get("old_3105"), {".3105"})
        new = _save_upload(
            request.files.get("new_input"),
            {".zip", ".pak", ".bytes", ".txt", ".json"},
        )
        out = _tmp_path(".3105")


        password = (request.form.get("password") or "").strip()
        new_password = request.form.get("new_password")
        preset = request.form.get("preset") or "auto"
        name = (request.form.get("name") or "").strip()
        author = (request.form.get("author") or "").strip()
        rename_global = (request.form.get("rename_global") or "").strip()
        rename_vng = (request.form.get("rename_vng") or "").strip()
        pubg_folder = request.form.get("pubg_folder") or "preserve"
        path_mode = request.form.get("path_mode") or "auto"
        prefix = (request.form.get("prefix") or "").strip()


        args = [
            "update", str(old), str(new), str(out),
            "--preset", preset, "--pubg-folder", pubg_folder,
        ]
        if password:
            args += ["--password", password]
        if new_password is not None and new_password.strip():
            args += ["--new-password", new_password.strip()]
        if name:
            args += ["--name", name]
        if author:
            args += ["--author", author]
        if rename_global:
            args += ["--rename-global", rename_global]
        if rename_vng:
            args += ["--rename-vng", rename_vng]
        if path_mode == "custom" and prefix:
            args += ["--path-mode", "custom", "--prefix", prefix]

        source_diag = _diagnose_input(
            new,
            preset,
            path_mode=path_mode,
            custom_prefix=prefix or None,
            pubg_folder=pubg_folder,
        )
        if source_diag.get("errors"):
            raise ValueError("DIAGNOSTICS ERROR: " + "; ".join(source_diag["errors"]))

        result = _run(args)
        stats = _parse_update_stats(result.stdout)
        verify_password = (
            new_password.strip()
            if (new_password and new_password.strip())
            else (password or None)
        )
        verify_info = _verify(out, verify_password)
        if not verify_info["ok"]:
            raise ValueError("VERIFY LỖI sau update")


        download_name = (name or Path(request.files["old_3105"].filename).stem) + "_updated.3105"
        _manage_outputs(out, download_name)
        response = _download(out, download_name, cleanup_paths=[old, new])
        response.headers["X-3105-Verify"] = "OK"
        response.headers["X-3105-Rules"] = str(verify_info["rules"])
        response.headers["X-3105-Schema"] = str(verify_info["schema"])
        response.headers["X-3105-Bundles"] = ",".join(verify_info["bundles"])
        response.headers["X-3105-Old-Total"] = str(stats.get("old_total", 0))
        response.headers["X-3105-Incoming"] = str(stats.get("incoming_total", 0))
        response.headers["X-3105-Added"] = str(stats.get("added", 0))
        response.headers["X-3105-Overwritten"] = str(stats.get("overwritten", 0))
        response.headers["X-3105-Same"] = str(stats.get("same", 0))
        response.headers["X-3105-Final-Total"] = str(stats.get("final_total", 0))
        _attach_diagnostic_headers(response, source_diag)
        return response
    except Exception as exc:
        for p in (old, new, out):
            if p:
                Path(p).unlink(missing_ok=True)
        return _error_text(exc), 400


@app.route("/rebundle", methods=["POST"])
def rebundle():
    src = out = None
    try:
        src = _save_upload(request.files.get("file_3105"), {".3105"})
        out = _tmp_path(".3105")
        password = (request.form.get("password") or "").strip()
        new_password = (request.form.get("new_password") or "").strip()
        old_bundle = (request.form.get("old_bundle") or "").strip()
        new_bundle = (request.form.get("new_bundle") or "").strip()
        name = (request.form.get("name") or "").strip()
        author = (request.form.get("author") or "").strip()


        if not old_bundle or not new_bundle:
            raise ValueError("Cần nhập Bundle ID cũ và mới")


        args = [
            "rebundle", str(src), str(out),
            "--old-bundle", old_bundle, "--new-bundle", new_bundle,
        ]
        if password:
            args += ["--password", password]
        if new_password:
            args += ["--new-password", new_password]
        if name:
            args += ["--name", name]
        if author:
            args += ["--author", author]


        _run(args)
        verify_info = _verify(out, new_password or password or None)
        if not verify_info["ok"]:
            raise ValueError("VERIFY LỖI sau rebundle")


        download_name = f"rebundle_{new_bundle}.3105"
        _manage_outputs(out, download_name)
        response = _download(out, download_name, cleanup_paths=[src])
        response.headers["X-3105-Verify"] = "OK"
        response.headers["X-3105-Rules"] = str(verify_info["rules"])
        response.headers["X-3105-Schema"] = str(verify_info["schema"])
        response.headers["X-3105-Bundles"] = ",".join(verify_info["bundles"])
        return response
    except Exception as exc:
        for p in (src, out):
            if p:
                Path(p).unlink(missing_ok=True)
        return _error_text(exc), 400


def _rules_for_zip(src: Path, preset_name: str, pubg_folder: str = "preserve"):
    mod = _tool_module()
    entries = mod.input_entries(src)
    if preset_name == "auto":
        preset_name = mod.auto_detect_preset(entries)
    if preset_name not in mod.PRESETS:
        raise ValueError("Loại game không hợp lệ")
    cfg = mod.PRESETS[preset_name]
    rules = mod.build_rules_from_entries(
        entries, preset_name, list(cfg["bundles"]),
        bool(cfg["dual"]), int(cfg["schema"]),
        pubg_folder=pubg_folder,
    )
    if not rules:
        raise ValueError("Không tìm thấy file game hợp lệ")
    return preset_name, cfg, rules


def _write_clean_zip(out: Path, rules, schema: int, project_name: str, extra_files=None):
    files = []
    bundles = []
    seen = set()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for r in rules:
            key = (r["bundleID"], r["relativePath"])
            if key in seen:
                continue
            seen.add(key)
            data = r["replacementData"]
            bundles.append(r["bundleID"])
            zf.writestr(f'{r["bundleID"]}/{r["relativePath"]}', data)
            files.append({
                "bundleID": r["bundleID"],
                "relativePath": r["relativePath"],
                "replacementFilename": r["replacementFilename"],
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })


        manifest = {
            "sourcePackage": out.name,
            "schemaVersion": int(schema),
            "packageID": str(uuid.uuid4()).upper(),
            "projectName": project_name,
            "author": "MANZ-VIP",
            "bundleIdentifiers": list(dict.fromkeys(bundles)),
            "files": files,
        }
        zf.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        for arc, data in (extra_files or []):
            zf.writestr(arc, data)
    return manifest


@app.route("/zip/analyze", methods=["POST"])
def zip_analyze():
    src = None
    try:
        src = _save_upload(request.files.get("zip_file"), {".zip"})
        mod = _tool_module()
        entries = mod.input_entries(src)
        preset = mod.auto_detect_preset(entries)
        diag = mod.diagnose_entries(entries, preset)
        lines = [
            "PHÂN TÍCH GÓI",
            "=" * 48,
            f"Loại game: {preset}",
            f"Tổng file: {len(entries)}",
            f"File 0 byte: {len(diag['zero_byte'])}",
            f"Đường dẫn đích trùng: {len(diag['duplicate_targets'])}",
            f"Phiên bản Resources: {', '.join(diag['resource_versions']) if diag['resource_versions'] else 'Không xác định'}",
            f"File hệ thống LQ cần chú ý: {len(diag['notable_lq_files'])}",
        ]
        if diag["warnings"]:
            lines += ["", "CẢNH BÁO:"] + [f"- {w}" for w in diag["warnings"]]
        return jsonify({"success": True, "output": "\n".join(lines)})
    except Exception as exc:
        return jsonify({"success": False, "output": _error_text(exc)}), 400
    finally:
        if src:
            src.unlink(missing_ok=True)


@app.route("/zip/diagnose", methods=["POST"])
def zip_diagnose():
    src = None
    try:
        src = _save_upload(request.files.get("zip_file"), {".zip"})
        mod = _tool_module()
        entries = mod.input_entries(src)
        diag = mod.diagnose_entries(entries, request.form.get("preset") or "auto")
        return jsonify({"success": True, "diagnostics": diag})
    except Exception as exc:
        return jsonify({"success": False, "error": _error_text(exc)}), 400
    finally:
        if src:
            src.unlink(missing_ok=True)


@app.route("/zip/clean", methods=["POST"])
def zip_clean():
    src = out = None
    try:
        src = _save_upload(request.files.get("zip_file"), {".zip"})
        preset = request.form.get("preset") or "auto"
        pubg_folder = request.form.get("pubg_folder") or "preserve"
        _, cfg, rules = _rules_for_zip(src, preset, pubg_folder)


        out = _tmp_path(".zip")
        name = re.sub(r"[^0-9A-Za-zÀ-ỹ._ -]+", "_", Path(request.files["zip_file"].filename).stem)[:80] + "_SACH"
        _write_clean_zip(out, rules, cfg["schema"], name)
        download_name = f"{name}.zip"
        _manage_outputs(out, download_name)
        return _download(out, download_name, cleanup_paths=[src])
    except Exception as exc:
        for p in (src, out):
            if p:
                Path(p).unlink(missing_ok=True)
        return _error_text(exc), 400


@app.route("/zip/merge", methods=["POST"])
def zip_merge():
    a = b = out = None
    try:
        a = _save_upload(request.files.get("zip_a"), {".zip"})
        b = _save_upload(request.files.get("zip_b"), {".zip"})
        preset = request.form.get("preset") or "lq"
        priority = request.form.get("priority") or "b"
        pubg_folder = request.form.get("pubg_folder") or "preserve"


        resolved_a, cfg_a, rules_a = _rules_for_zip(a, preset, pubg_folder)
        resolved_b, _, rules_b = _rules_for_zip(b, preset, pubg_folder)
        if resolved_a != resolved_b:
            raise ValueError(f"Hai gói nhận diện khác loại: {resolved_a} và {resolved_b}")


        map_a = {(r["bundleID"], r["relativePath"]): r for r in rules_a}
        map_b = {(r["bundleID"], r["relativePath"]): r for r in rules_b}
        active, conflicts, extra = [], [], []


        for key in sorted(set(map_a) | set(map_b)):
            ra, rb = map_a.get(key), map_b.get(key)
            if ra and rb:
                sha_a = hashlib.sha256(ra["replacementData"]).hexdigest()
                sha_b = hashlib.sha256(rb["replacementData"]).hexdigest()
                if sha_a == sha_b:
                    chosen = rb if priority == "b" else ra
                else:
                    chosen = rb if priority == "b" else ra
                    alt = ra if priority == "b" else rb
                    conflicts.append({
                        "bundleID": key[0],
                        "relativePath": key[1],
                        "sha256_A": sha_a,
                        "sha256_B": sha_b,
                        "uu_tien": "B" if priority == "b" else "A",
                    })
                    extra.append((
                        f'_xung_dot/{alt["bundleID"]}/{alt["relativePath"]}',
                        alt["replacementData"],
                    ))
                active.append(chosen)
            else:
                active.append(ra or rb)


        report = {
            "file_A": len(map_a),
            "file_B": len(map_b),
            "xung_dot": conflicts,
            "tong_file_dang_hoat_dong": len(active),
        }
        extra.append((
            "conflict_report.json",
            json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"),
        ))


        out = _tmp_path(".zip")
        _write_clean_zip(out, active, cfg_a["schema"], "GOP_2_ZIP", extra_files=extra)
        _manage_outputs(out, "GOP_2_ZIP.zip")
        return _download(out, "GOP_2_ZIP.zip", cleanup_paths=[a, b])
    except Exception as exc:
        for p in (a, b, out):
            if p:
                Path(p).unlink(missing_ok=True)
        return _error_text(exc), 400


@app.route("/history", methods=["GET"])
def history():
    files = sorted(OUTPUT_FOLDER.glob("*"), key=os.path.getmtime, reverse=True)[:5]
    return jsonify({"files": [f.name for f in files]})


@app.route("/download_out/<filename>")
def download_out(filename):
    safe = Path(filename).name
    return send_file(OUTPUT_FOLDER / safe, as_attachment=True)



@app.route("/build_pubg5_separate", methods=["POST"])
def build_pubg5_separate():
    import io
    import zipfile
    src = None
    outputs = []
    try:
        src = _save_upload(request.files.get("input_file"), {".zip", ".pak"})
        name = (request.form.get("name") or "PUBG 5 SERVER").strip()
        author = (request.form.get("author") or "MANZ-VIP").strip()
        password = (request.form.get("password") or "").strip()
        folder = request.form.get("pubg_folder") or "preserve"
        mod = _tool_module()
        source_entries = mod.input_entries(src)
        # An explicit five-server sample is recognized as five distinct targets.
        # For a single raw PAK, each build maps that PAK to its selected bundle.
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for preset in ("pubg-global", "pubg-vng", "pubg-kr", "pubg-tw", "pubg-bgmi"):
                out = _tmp_path(".3105")
                outputs.append(out)
                bundle = mod.PRESETS[preset]["bundles"][0]
                # Bundle-qualified sample ZIP: keep only entries belonging to this server;
                # omit redundant payload copies when explicit server entries exist.
                selected = [(n,b) for n,b in source_entries if mod.find_bundle_hint(list(mod.PurePosixPath(n.replace("\\", "/")).parts))[0] == bundle]
                if selected:
                    source = _tmp_path(".zip")
                    outputs.append(source)
                    with zipfile.ZipFile(source,"w") as sub:
                        for n,b in selected: sub.writestr(n,b)
                else:
                    source = src
                args = ["build", str(source), str(out), "--name", name+" "+preset.upper(), "--author", author, "--preset", preset, "--schema", "9", "--pubg-folder", folder]
                args += ["--password",password] if password else ["--no-password"]
                _run(args)
                verified = _verify(out, password or None)
                if not verified["ok"] or verified["bundles"] != [bundle]:
                    raise ValueError("Verify thất bại: "+preset)
                zout.write(out, preset+".3105")
        data.seek(0)
        response = send_file(data, mimetype="application/zip", as_attachment=True, download_name="PUBG_5_SERVERS_SEPARATE.zip")
        response.headers["X-3105-Verify"]="OK"
        response.headers["X-3105-Bundles"]=",".join(mod.PRESETS["pubg-5sv"]["bundles"])
        response.headers["X-3105-Schema"]="9"
        return response
    except Exception as exc:
        return jsonify({"success":False,"error":str(exc)}),400
    finally:
        if src: src.unlink(missing_ok=True)
        for out in outputs: out.unlink(missing_ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2006, debug=False)