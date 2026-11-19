import io
import zipfile
import pytest
from app import app, encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text

@pytest.fixture()
def client():
    app.config["TESTING"] = True
    return app.test_client()

def test_text_round_trip():
    payload = encrypt_text("forensic lab sample", "strong passphrase")
    assert decrypt_text(payload, "strong passphrase") == "forensic lab sample"

def test_text_wrong_passphrase_fails():
    payload = encrypt_text("secret", "right")
    with pytest.raises(Exception):
        decrypt_text(payload, "wrong")

def test_file_round_trip():
    data = b"\x00binary sample\xff"
    assert decrypt_bytes(encrypt_bytes(data, "pass"), "pass") == data

def test_tampering_fails():
    blob = bytearray(encrypt_bytes(b"evidence", "pass"))
    blob[-1] ^= 1
    with pytest.raises(Exception):
        decrypt_bytes(bytes(blob), "pass")

def test_health(client):
    assert client.get("/api/health").status_code == 200

def test_folder_round_trip(client):
    data = {"files": (io.BytesIO(b"hello folder"), "docs/sample.txt")}
    response = client.post("/api/folder/encrypt", data={**data, "passphrase":"pass"}, content_type="multipart/form-data")
    assert response.status_code == 200
    encrypted_zip = zipfile.ZipFile(io.BytesIO(response.data))
    assert "docs/sample.txt.aes" in encrypted_zip.namelist()
    dec = client.post("/api/folder/decrypt",
        data={"file": (io.BytesIO(response.data), "encrypted.zip"), "passphrase":"pass"},
        content_type="multipart/form-data")
    assert dec.status_code == 200
    restored = zipfile.ZipFile(io.BytesIO(dec.data))
    assert restored.read("docs/sample.txt") == b"hello folder"
