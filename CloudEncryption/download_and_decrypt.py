import os
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from config import ACCESS_TOKEN, DROPBOX_FOLDER, DOWNLOAD_FOLDER, RECONSTRUCTED_FILE, AES_KEY_FILE

# Load AES key
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()

# Initialize Dropbox client
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# Create local folder if it doesn't exist
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# List fragments in Dropbox folder
try:
    fragments = [entry.name for entry in dbx.files_list_folder(DROPBOX_FOLDER).entries]
except dropbox.exceptions.ApiError as e:
    print("Error listing Dropbox folder:", e)
    exit()

if not fragments:
    print("No fragments found in Dropbox folder.")
    exit()

print("Fragments found in Dropbox:", fragments)

# Download fragments
for frag_name in fragments:
    dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
    local_path = os.path.join(DOWNLOAD_FOLDER, frag_name)
    metadata, res = dbx.files_download(dropbox_path)
    with open(local_path, "wb") as f:
        f.write(res.content)
    print(f"Downloaded {frag_name}")

# AES decrypt function
def aes_decrypt(ciphertext, key):
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short, cannot extract IV.")
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    if len(ct) % 16 != 0:
        raise ValueError("Ciphertext length is not multiple of block size!")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted

# Merge and decrypt fragments
reconstructed_data = b""

# Only include fragment files (avoid hidden/system files)
fragments_sorted = sorted(
    [f for f in os.listdir(DOWNLOAD_FOLDER) if f.endswith("_frag_0") or "_frag_" in f]
)

for frag_file in fragments_sorted:
    frag_path = os.path.join(DOWNLOAD_FOLDER, frag_file)
    with open(frag_path, "rb") as f:
        encrypted_fragment = f.read()
    try:
        decrypted_fragment = aes_decrypt(encrypted_fragment, aes_key)
    except ValueError as e:
        print(f"Skipping {frag_file} due to decryption error: {e}")
        continue
    reconstructed_data += decrypted_fragment

# Save reconstructed file
with open(RECONSTRUCTED_FILE, "wb") as f:
    f.write(reconstructed_data)

print(f"\nFile reconstructed successfully as '{RECONSTRUCTED_FILE}'")
