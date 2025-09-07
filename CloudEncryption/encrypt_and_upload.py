import os
import dropbox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from config import ACCESS_TOKEN, DROPBOX_FOLDER, FRAGMENT_FOLDER, AES_KEY_FILE, AES_KEY_SIZE

# Create local fragment folder if not exists
os.makedirs(FRAGMENT_FOLDER, exist_ok=True)

# Load AES key (or generate if not exists)
if not os.path.exists(AES_KEY_FILE):
    from cryptography.hazmat.primitives import keywrap
    import os
    aes_key = os.urandom(AES_KEY_SIZE)
    os.makedirs(os.path.dirname(AES_KEY_FILE), exist_ok=True)
    with open(AES_KEY_FILE, "wb") as f:
        f.write(aes_key)
else:
    with open(AES_KEY_FILE, "rb") as f:
        aes_key = f.read()

# AES encrypt function (CBC mode, random IV)
def aes_encrypt(data, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct  # prepend IV

# Split file into fragments
def split_file(file_path, num_fragments=4):
    with open(file_path, "rb") as f:
        content = f.read()
    fragment_size = len(content) // num_fragments
    fragments = []
    for i in range(num_fragments):
        start = i * fragment_size
        end = None if i == num_fragments - 1 else (i + 1) * fragment_size
        fragments.append(content[start:end])
    return fragments

# Upload fragments to Dropbox
dbx = dropbox.Dropbox(ACCESS_TOKEN)

file_path = input("Enter path of file to upload: ")
fragments = split_file(file_path)

for idx, frag in enumerate(fragments):
    encrypted_frag = aes_encrypt(frag, aes_key)
    frag_name = os.path.basename(file_path) + f"_frag_{idx}"
    local_frag_path = os.path.join(FRAGMENT_FOLDER, frag_name)
    with open(local_frag_path, "wb") as f:
        f.write(encrypted_frag)
    dropbox_path = f"{DROPBOX_FOLDER}/{frag_name}"
    dbx.files_upload(encrypted_frag, dropbox_path, mode=dropbox.files.WriteMode.overwrite)
    print(f"Uploaded {frag_name}")

print("All fragments uploaded successfully!")
