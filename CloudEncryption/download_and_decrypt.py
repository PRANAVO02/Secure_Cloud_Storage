import os
import json
import shutil
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, DOWNLOAD_FOLDER, RECONSTRUCTED_FILE, AES_KEY_FILE

# --- Load AES key ---
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# --- Load last uploaded file ---
if not os.path.exists("last_uploaded.txt"):
    print("No record of last uploaded file. Upload a file first.")
    exit()

with open("last_uploaded.txt", "r") as f:
    target_filename = f.read().strip()

print(f"🔍 Reconstructing fragments for: {target_filename}")

# --- Clear & prepare download folder ---
if os.path.exists(DOWNLOAD_FOLDER):
    shutil.rmtree(DOWNLOAD_FOLDER)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# --- Download manifest ---
manifest_path = f"{DROPBOX_FOLDER}/{target_filename}.manifest.json"
metadata, res = dbx.files_download(manifest_path)
manifest = json.loads(res.content)

print("Manifest loaded:", manifest)

# --- AES decrypt ---
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# --- Download fragments according to manifest ---
fragments = sorted(manifest["fragments"], key=lambda x: x["index"])
reconstructed_data = b""

for frag in fragments:
    frag_name = frag["name"]
    dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
    local_path = os.path.join(DOWNLOAD_FOLDER, frag_name)

    metadata, res = dbx.files_download(dropbox_path)
    with open(local_path, "wb") as f:
        f.write(res.content)

    decrypted_fragment = aes_decrypt(res.content, aes_key)
    reconstructed_data += decrypted_fragment
    print(f"Downloaded + Decrypted {frag_name}")

# --- Save reconstructed file ---
with open(RECONSTRUCTED_FILE, "wb") as f:
    f.write(reconstructed_data)

print(f"\n✅ File reconstructed successfully as '{RECONSTRUCTED_FILE}'")
