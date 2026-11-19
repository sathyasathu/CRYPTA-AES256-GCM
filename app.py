import base64
import hashlib
import io
import os
import re
import zipfile
from pathlib import Path, PurePosixPath

from flask import Flask, jsonify, render_template, request, send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # total request limit: 100 MiB
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", os.urandom(32)),
)

FILE_MAGIC = b"AESFILE1"
TEXT_MAGIC = "AESTEXT1"
FOLDER_MAGIC = "CRYPTAFOLDER1"
SALT_LEN, NONCE_LEN, KEY_LEN = 16, 12, 32
PBKDF2_ITERATIONS = 600_000
TAG_LEN = 16
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_FOLDER_FILES = 500


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase.strip():
        raise ValueError("A non-empty passphrase is required.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_LEN,
        salt=salt, iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(passphrase.encode("utf-8"))


def safe_name(name: str, fallback: str = "download.bin") -> str:
    cleaned = secure_filename(Path(name or fallback).name)
    return cleaned or fallback


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)
    encrypted = AESGCM(key).encrypt(nonce, data, FILE_MAGIC)
    return FILE_MAGIC + salt + nonce + encrypted


def decrypt_bytes(payload: bytes, passphrase: str) -> bytes:
    header_len = len(FILE_MAGIC) + SALT_LEN + NONCE_LEN
    if len(payload) < header_len + TAG_LEN or not payload.startswith(FILE_MAGIC):
        raise ValueError("Invalid or unsupported encrypted file.")
    pos = len(FILE_MAGIC)
    salt = payload[pos:pos + SALT_LEN]; pos += SALT_LEN
    nonce = payload[pos:pos + NONCE_LEN]; pos += NONCE_LEN
    return AESGCM(derive_key(passphrase, salt)).decrypt(
        nonce, payload[pos:], FILE_MAGIC
    )


def encrypt_text(plain: str, passphrase: str) -> str:
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plain.encode("utf-8"), TEXT_MAGIC.encode())
    parts = [salt, nonce, ciphertext]
    return TEXT_MAGIC + "." + ".".join(
        base64.b64encode(part).decode("ascii") for part in parts
    )


def decrypt_text(payload: str, passphrase: str) -> str:
    pieces = payload.split(".")
    if len(pieces) != 4 or pieces[0] != TEXT_MAGIC:
        raise ValueError("Invalid encrypted text format.")
    salt, nonce, ciphertext = [
        base64.b64decode(part, validate=True) for part in pieces[1:]
    ]
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise ValueError("Invalid encryption parameters.")
    return AESGCM(derive_key(passphrase, salt)).decrypt(
        nonce, ciphertext, TEXT_MAGIC.encode()
    ).decode("utf-8")


def safe_archive_path(name: str) -> str:
    # Normalize ZIP paths and reject traversal, absolute paths and Windows drives.
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(p in ("", ".", "..") for p in path.parts):
        raise ValueError("Unsafe path found in folder archive.")
    if re.match(r"^[A-Za-z]:", name):
        raise ValueError("Drive-based paths are not allowed.")
    return str(path)


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; base-uri 'self'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify(status="ok", service="Crypta AES-256-GCM")


@app.post("/api/key/generate")
def generate_key():
    # Generate a high-entropy passphrase token for use with PBKDF2.
    token = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    return jsonify(passphrase=token)


@app.post("/api/text/encrypt")
def text_encrypt():
    plain = request.form.get("text", "")
    password = request.form.get("passphrase", "")
    if not plain or not password:
        return render_template("index.html", active_tab="text", error="Enter both message and passphrase.", text_value=plain), 400
    try:
        result = encrypt_text(plain, password)
        return render_template("index.html", active_tab="text", text_result=result, text_value=plain)
    except Exception:
        return render_template("index.html", active_tab="text", error="Text encryption failed."), 400


@app.post("/api/text/decrypt")
def text_decrypt():
    payload = request.form.get("payload", "").strip()
    password = request.form.get("passphrase", "")
    try:
        if not payload or not password:
            raise ValueError()
        plain = decrypt_text(payload, password)
        return render_template("index.html", active_tab="text", decrypted_text=plain, payload_value=payload)
    except Exception:
        return render_template("index.html", active_tab="text", error="Decryption failed. Check the passphrase and payload integrity.", payload_value=payload), 400


@app.post("/api/file/encrypt")
def file_encrypt():
    uploaded = request.files.get("file")
    password = request.form.get("passphrase", "")
    if not uploaded or not uploaded.filename or not password:
        return render_template("index.html", active_tab="files", error="Choose a file and enter a passphrase."), 400
    raw = uploaded.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        return render_template("index.html", active_tab="files", error="Maximum individual file size is 50 MiB."), 413
    try:
        encrypted = encrypt_bytes(raw, password)
        name = safe_name(uploaded.filename) + ".aes"
        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=name,
                         mimetype="application/octet-stream", max_age=0)
    except Exception:
        return render_template("index.html", active_tab="files", error="File encryption failed."), 400


@app.post("/api/file/decrypt")
def file_decrypt():
    uploaded = request.files.get("file")
    password = request.form.get("passphrase", "")
    if not uploaded or not uploaded.filename or not password:
        return render_template("index.html", active_tab="files", error="Choose an encrypted file and enter a passphrase."), 400
    raw = uploaded.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        return render_template("index.html", active_tab="files", error="Maximum individual file size is 50 MiB."), 413
    try:
        plain = decrypt_bytes(raw, password)
        name = safe_name(uploaded.filename)
        if name.lower().endswith(".aes"):
            name = name[:-4]
        name = safe_name(name, "decrypted_file.bin")
        return send_file(io.BytesIO(plain), as_attachment=True, download_name=name,
                         mimetype="application/octet-stream", max_age=0)
    except Exception:
        return render_template("index.html", active_tab="files", error="Decryption or authentication verification failed."), 400


@app.post("/api/folder/encrypt")
def folder_encrypt():
    uploads = request.files.getlist("files")
    password = request.form.get("passphrase", "")
    if not uploads or not password:
        return render_template("index.html", active_tab="folder", error="Select a folder and enter a passphrase."), 400
    if len(uploads) > MAX_FOLDER_FILES:
        return render_template("index.html", active_tab="folder", error=f"Folder limit is {MAX_FOLDER_FILES} files."), 413
    output = io.BytesIO()
    count = 0
    try:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in uploads:
                if not item.filename:
                    continue
                rel = safe_archive_path(item.filename)
                data = item.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise ValueError("A file exceeds the 50 MiB per-file limit.")
                encrypted = encrypt_bytes(data, password)
                zout.writestr(rel + ".aes", encrypted)
                count += 1
        if count == 0:
            raise ValueError("The selected folder contains no files.")
        output.seek(0)
        return send_file(output, as_attachment=True, download_name="crypta_encrypted_folder.zip",
                         mimetype="application/zip", max_age=0)
    except Exception as exc:
        msg = str(exc) if str(exc) else "Folder encryption failed."
        return render_template("index.html", active_tab="folder", error=msg), 400


@app.post("/api/folder/decrypt")
def folder_decrypt():
    uploaded = request.files.get("file")
    password = request.form.get("passphrase", "")
    if not uploaded or not uploaded.filename or not password:
        return render_template("index.html", active_tab="folder", error="Choose an encrypted folder ZIP and enter a passphrase."), 400
    raw = uploaded.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(raw) > app.config["MAX_CONTENT_LENGTH"]:
        return render_template("index.html", active_tab="folder", error="Folder archive exceeds 100 MiB."), 413
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as zin, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zout:
            entries = [i for i in zin.infolist() if not i.is_dir()]
            if len(entries) > MAX_FOLDER_FILES:
                raise ValueError("Folder archive contains too many files.")
            for info in entries:
                rel = safe_archive_path(info.filename)
                if not rel.endswith(".aes"):
                    raise ValueError("Archive contains a non-.aes entry.")
                encrypted = zin.read(info)
                plain = decrypt_bytes(encrypted, password)
                restored_name = rel[:-4]
                safe_archive_path(restored_name)
                zout.writestr(restored_name, plain)
        output.seek(0)
        return send_file(output, as_attachment=True, download_name="crypta_decrypted_folder.zip",
                         mimetype="application/zip", max_age=0)
    except Exception:
        return render_template("index.html", active_tab="folder", error="Folder decryption failed. Check the passphrase, archive and file integrity."), 400


@app.errorhandler(413)
def too_large(_error):
    return render_template("index.html", active_tab="files", error="The upload exceeds the configured request limit."), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
