import os
import uuid
import dropbox
from utils.crypto_aes import aes_encrypt
from utils.file_handler import split_file
from utils.metadata import load_registry, save_registry
from config import *

# Initialize Dropbox client
dbx = dropbox.Dropbox(ACCESS_TOKEN)

def encrypt_and_upload(file_path):
    filename = os.path.basename(file_path)
    os.makedirs(FRAGMENT_FOLDER, exist_ok=True)

    # Read file
    with open(file_path, "rb") as f:
        data = f.read()

    # Split into fragments
    fragments = split_file(data, FRAGMENT_SIZE)
    fragments_meta = []

    # Encrypt and upload fragments
    for idx, fragment in enumerate(fragments):
        encrypted = aes_encrypt(fragment, open(AES_KEY_FILE, "rb").read())
        frag_name = f"{uuid.uuid4().hex}.frag"
        local_path = os.path.join(FRAGMENT_FOLDER, frag_name)

        # Save locally
        with open(local_path, "wb") as f:
            f.write(encrypted)

        # Upload to Dropbox
        dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
        with open(local_path, "rb") as f:
            dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite)

        fragments_meta.append({"index": idx, "name": frag_name})
        print(f"Uploaded fragment {idx+1}/{len(fragments)}: {frag_name}")

    # Update registry
    registry = load_registry()
    registry[filename] = {
        "original_filename": filename,
        "total_fragments": len(fragments_meta),
        "fragments": fragments_meta
    }
    save_registry(registry)

    # Upload registry to Dropbox
    with open("manifests.json", "rb") as f:
        dbx.files_upload(f.read(), f"{DROPBOX_FOLDER}/manifests.json", mode=dropbox.files.WriteMode.overwrite)

    print(f"\n✅ File '{filename}' encrypted, fragmented, and uploaded successfully!")
    return registry[filename]

# Terminal run
if __name__ == "__main__":
    file_path = input("Enter file path to upload: ").strip()
    encrypt_and_upload(file_path)
