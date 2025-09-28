import os
import json
import shutil
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, DOWNLOAD_FOLDER, AES_KEY_FILE, RECONSTRUCTED_FOLDER

# --- Load AES key ---
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# --- Load registry (manifests.json) from Dropbox ---
try:
    metadata, res = dbx.files_download(f"{DROPBOX_FOLDER}/manifests.json")
    if res.content.strip():
        registry = json.loads(res.content)
    else:
        registry = {}
except dropbox.exceptions.ApiError:
    print("⚠️ No registry found on Dropbox yet.")
    registry = {}

# --- Check if any files exist ---
if not registry:
    print("📂 No files available for download.")
    exit()

# --- Show available files ---
print("\n📂 Available files:")
for i, fname in enumerate(registry.keys(), start=1):
    print(f"{i}. {fname}")

# --- Ask user which file to download ---
choice = input("\nEnter filename to download: ").strip()
if choice not in registry:
    print(f"❌ File '{choice}' not found in registry.")
    exit()

manifest = registry[choice]
print(f"✅ Manifest loaded for '{choice}'")

# --- Prepare download folder ---
if os.path.exists(DOWNLOAD_FOLDER):
    shutil.rmtree(DOWNLOAD_FOLDER)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# --- AES decryption function ---
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# --- Download & decrypt fragments ---
fragments = sorted(manifest["fragments"], key=lambda x: x["index"])
reconstructed_data = b""

print("\n⬇️ Downloading and decrypting fragments...")
for frag in fragments:
    frag_name = frag["name"]
    dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
    local_path = os.path.join(DOWNLOAD_FOLDER, frag_name)

    metadata, res = dbx.files_download(dropbox_path)
    with open(local_path, "wb") as f:
        f.write(res.content)

    decrypted_fragment = aes_decrypt(res.content, aes_key)
    reconstructed_data += decrypted_fragment
    print(f"   ✅ Fragment {frag_name} done")

# --- Save reconstructed file ---
os.makedirs(RECONSTRUCTED_FOLDER, exist_ok=True)
reconstructed_filename = f"reconstructed_{manifest['original_filename']}"
reconstructed_path = os.path.join(RECONSTRUCTED_FOLDER, reconstructed_filename)

with open(reconstructed_path, "wb") as f:
    f.write(reconstructed_data)

print(f"\n🎉 File reconstructed successfully: '{reconstructed_path}'")
