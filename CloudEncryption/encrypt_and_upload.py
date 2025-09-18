import os
import json
import uuid
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, AES_KEY_FILE, FRAGMENT_FOLDER

# --- Load AES key ---
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# --- Initialize Dropbox client ---
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# --- Get file to upload ---
file_path = input("Enter path of file to upload: ").strip()
filename = os.path.basename(file_path)  # e.g., "demo.txt"

# --- Create fragment folder if not exists ---
os.makedirs(FRAGMENT_FOLDER, exist_ok=True)

# --- AES encryption ---
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

# --- Read file ---
with open(file_path, "rb") as f:
    data = f.read()

# --- Safe fragment splitting ---
def split_file(data, num_fragments=4):
    length = len(data)
    fragments = []
    base_size = length // num_fragments
    remainder = length % num_fragments
    start = 0
    for i in range(num_fragments):
        extra = 1 if i < remainder else 0
        end = start + base_size + extra
        fragments.append(data[start:end])
        start = end
    return fragments

fragments = split_file(data, num_fragments=4)

# --- Encrypt & upload fragments ---
fragments_meta = []
for i, fragment in enumerate(fragments):
    encrypted = aes_encrypt(fragment, aes_key)

    # Random name for fragment
    frag_name = f"{uuid.uuid4().hex}.frag"

    # Save locally
    local_path = os.path.join(FRAGMENT_FOLDER, frag_name)
    with open(local_path, "wb") as f:
        f.write(encrypted)

    # Upload to Dropbox
    dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
    with open(local_path, "rb") as f:
        dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)

    fragments_meta.append({"index": i, "name": frag_name})
    print(f"Uploaded fragment {i} → {frag_name}")

# --- Save manifest locally ---
manifest = {
    "original_filename": filename,
    "total_fragments": len(fragments_meta),
    "fragments": fragments_meta,
}
with open("manifest.json", "w") as mf:
    json.dump(manifest, mf, indent=2)

# --- Upload manifest (overwrite mode) ---
with open("manifest.json", "rb") as mf:
    dbx.files_upload(
        mf.read(),
        f"{DROPBOX_FOLDER}/{filename}.manifest.json",
        mode=dropbox.files.WriteMode.overwrite
    )

# --- Save last uploaded filename ---
with open("last_uploaded.txt", "w") as f:
    f.write(filename)

print(f"\n✅ File '{filename}' uploaded in {len(fragments_meta)} fragments + manifest.")
