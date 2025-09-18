import os
import json
import uuid
import dropbox
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, AES_KEY_FILE, FRAGMENT_FOLDER, DOWNLOAD_FOLDER, RECONSTRUCTED_FILE

app = Flask(__name__)
app.secret_key = "supersecretkey"

# --- Load AES key ---
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# --- AES functions ---
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("No file uploaded!")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected!")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    filepath = os.path.join("uploads", filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(filepath)

    # --- Split + encrypt + upload ---
    with open(filepath, "rb") as f:
        data = f.read()

    # safe split into 4 parts
    length = len(data)
    fragments, base_size, remainder, start = [], length // 4, length % 4, 0
    for i in range(4):
        extra = 1 if i < remainder else 0
        end = start + base_size + extra
        fragments.append(data[start:end])
        start = end

    os.makedirs(FRAGMENT_FOLDER, exist_ok=True)
    fragments_meta = []
    for i, fragment in enumerate(fragments):
        encrypted = aes_encrypt(fragment, aes_key)
        frag_name = f"{uuid.uuid4().hex}.frag"
        local_path = os.path.join(FRAGMENT_FOLDER, frag_name)
        with open(local_path, "wb") as f:
            f.write(encrypted)

        dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
        with open(local_path, "rb") as f:
            dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)

        fragments_meta.append({"index": i, "name": frag_name})

    manifest = {"original_filename": filename, "total_fragments": len(fragments_meta), "fragments": fragments_meta}
    with open("manifest.json", "w") as mf:
        json.dump(manifest, mf, indent=2)

    with open("manifest.json", "rb") as mf:
        dbx.files_upload(mf.read(), f"{DROPBOX_FOLDER}/{filename}.manifest.json", mode=dropbox.files.WriteMode.overwrite)

    with open("last_uploaded.txt", "w") as f:
        f.write(filename)

    flash(f"✅ {filename} uploaded successfully with {len(fragments_meta)} fragments")
    return redirect(url_for("index"))

@app.route("/download")
def download_file():
    if not os.path.exists("last_uploaded.txt"):
        flash("No record of uploaded file!")
        return redirect(url_for("index"))

    with open("last_uploaded.txt", "r") as f:
        target_filename = f.read().strip()

    manifest_path = f"{DROPBOX_FOLDER}/{target_filename}.manifest.json"
    metadata, res = dbx.files_download(manifest_path)
    manifest = json.loads(res.content)

    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    reconstructed_data = b""
    for frag in sorted(manifest["fragments"], key=lambda x: x["index"]):
        dropbox_path = f"{DROPBOX_FOLDER}/{frag['name']}"
        metadata, res = dbx.files_download(dropbox_path)
        decrypted_fragment = aes_decrypt(res.content, aes_key)
        reconstructed_data += decrypted_fragment

    with open(RECONSTRUCTED_FILE, "wb") as f:
        f.write(reconstructed_data)

    return send_file(RECONSTRUCTED_FILE, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
