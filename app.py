from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import subprocess
import os
import sys
import random
from flask import send_file
import io
import shutil
import base64
import hashlib
from Crypto.Cipher import AES 

UPLOADS_DIR = '/home/pranav/hackathon/Web_XFS/uploads_7864505'
SAVE_DIR = '/home/pranav/hackathon/Web_XFS/tem_67654398/files'

app = Flask(__name__)
app.secret_key = "supersecret"
BLOCK_SIZE = 4096

P_HEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
         "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
         "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
         "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF")
G_DEC = 2
P_INT = int(P_HEX, 16)

B_DEC = 140737488355333

def sha256_bytes(data_bytes: bytes) -> bytes:
    return hashlib.sha256(data_bytes).digest()

def get_image_path():
    return session.get("image_path", None)

def is_xfs_image(file_path):
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        return magic == b"XFSB"
    except:
        return False

def get_all_files():
    file_uploaded_name = session.get("unique_name")
    image_path = os.path.join(UPLOADS_DIR, file_uploaded_name) if file_uploaded_name else ""
    root_inode = session.get("root_inode", 128)
    if not file_uploaded_name:
        return []

    process = subprocess.Popen(
        [sys.executable, 'xfs_scripts/AA_all_files_details.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "IMAGE_PATH": image_path}
    )
    output, error = process.communicate(input=f"{root_inode}\n")
    if error:
        print("Error:", error)

    all_entries = []
    for line in output.splitlines():
        if line.startswith("Name: "):
            parts = line.split(", ")
            file_info = {}
            for part in parts:
                key, val = part.split(": ")
                file_info[key.strip().lower()] = val.strip()
            all_entries.append(file_info)
    return all_entries

def create_zip_of_saved_files():
    """Create zip from SAVE_DIR, return raw bytes (not saved)."""
    zip_filename = "files_archive.zip"
    zip_path = os.path.join("/tmp", zip_filename)
    shutil.make_archive(zip_path.replace(".zip", ""), 'zip', SAVE_DIR)
    with open(zip_path, "rb") as f:
        data = f.read()
    os.remove(zip_path)
    
    # cleaning up the files under SAVE_DIR path.
    for root, dirs, files in os.walk(SAVE_DIR):
        for file in files:
            try:
                os.remove(os.path.join(root, file))
            except Exception:
                pass
    return data

def save_key_for_upload(unique_name: str, key_bytes: bytes):
    """Save derived key bytes (32 bytes) to a file per-upload for later use."""
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    key_path = os.path.join(UPLOADS_DIR, f"{unique_name}.key")
    with open(key_path, "wb") as kf:
        kf.write(key_bytes)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

def load_key_for_upload(unique_name: str):
    key_path = os.path.join(UPLOADS_DIR, f"{unique_name}.key")
    if not os.path.exists(key_path):
        return None
    with open(key_path, "rb") as kf:
        return kf.read()

def save_file_from_fsblock(fsblock, block_count, filename):
    fsblock = int(fsblock)
    block_count = int(block_count)
    full_bytes = b""
    image_path = get_image_path()
    for i in range(block_count):
        process = subprocess.Popen(
            ['sudo', 'dd', f'if={image_path}', 'bs=4096', 'count=1', f'skip={fsblock + i}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        data, error = process.communicate()
        if process.returncode != 0:
            raise Exception(f"Error reading block {fsblock + i}: {error.decode()}")
        full_bytes += data

    os.makedirs(SAVE_DIR, exist_ok=True)
    full_path = os.path.join(SAVE_DIR, filename)
    temp_file = "/tmp/temp_file.bin"
    with open(temp_file, "wb") as f:
        f.write(full_bytes)
    subprocess.run(['sudo', 'cp', temp_file, full_path])
    subprocess.run(['sudo', 'rm', temp_file])
    return full_path

@app.route("/")
def start():
    return render_template("start.html")

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if "image" not in request.files:
            flash("No file selected!"); return redirect(request.url)

        file = request.files["image"]
        if file.filename == "":
            flash("No file selected!"); return redirect(request.url)

        unique_number = str(random.randint(167654, 678987))
        file_name = file.filename
        New_name = unique_number + file_name
        session['unique_name'] = New_name

        upload_path = os.path.join(UPLOADS_DIR, New_name)

        ga_dec_str = request.form.get("ga", None)
        iv_b64 = request.form.get("iv", None)

        if ga_dec_str and iv_b64:
            try:
                ga_int = int(ga_dec_str)
                iv = base64.b64decode(iv_b64)
                ciphertext = file.read()
                if len(ciphertext) < 16:
                    raise ValueError("Ciphertext too short")

                shared_int = pow(ga_int, B_DEC, P_INT)
                shared_hex = format(shared_int, 'x')
                if len(shared_hex) % 2:
                    shared_hex = '0' + shared_hex
                shared_bytes = bytes.fromhex(shared_hex)
                key = sha256_bytes(shared_bytes)

                tag = ciphertext[-16:]
                enc = ciphertext[:-16]
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(enc, tag)

                with open(upload_path, "wb") as f:
                    f.write(plaintext)

                save_key_for_upload(New_name, key)
            except Exception as e:
                flash(f"Decryption failed: {e}")
                return redirect(request.url)
        else:
            try:
                file.save(upload_path)
            except Exception as e:
                flash(f"File upload failed: {e}")
                return redirect(request.url)

       
        session["image_path"] = upload_path
        session["root_inode"] = int(request.form.get("inode", 128))

        flash("Image uploaded successfully!")
        return redirect(url_for("index"))

    gb_mod_p_dec = str(pow(G_DEC, B_DEC, P_INT))
    return render_template("upload.html", gb_mod_p=gb_mod_p_dec, p_hex=P_HEX, g_dec=str(G_DEC))

@app.route("/download_encrypted_zip", methods=["POST"])
def download_encrypted_zip():
    """
    Receives JSON: {"files": ["name|fsblock|count", ...]}
    Prepares ZIP (same as send_zip) then encrypts with the key associated with current upload (session unique_name).
    Returns JSON: {"iv": "...", "ciphertext": "..."} with base64 values.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    files = data.get("files", [])
    
    os.makedirs(SAVE_DIR, exist_ok=True)
    
    for entry in files:
        try:
            filename, fsblock, block_count = entry.split("|")
            save_file_from_fsblock(fsblock, block_count, filename)
        except Exception as e:
            return jsonify({"error": f"Failed to save {entry}: {e}"}), 500

    zip_bytes = create_zip_of_saved_files()

    unique_name = session.get("unique_name")
    key = load_key_for_upload(unique_name) 
    if not key:
        return jsonify({
            "iv": "",
            "ciphertext": base64.b64encode(zip_bytes).decode(),
            "encrypted": False
        })


    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(zip_bytes)

    blob = ciphertext + tag
    return jsonify({
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(blob).decode(),
        "encrypted": True
    })

@app.route("/main", methods=["GET", "POST"])
def index():
    files = get_all_files()
    if request.method == "POST":
        selected_files = request.form.getlist("files")
        if not selected_files:
            flash("No files selected!"); return redirect(url_for("index"))
        # for file_str in selected_files:
        #     filename, fsblock, block_count = file_str.split("|")
        #     save_file_from_fsblock(fsblock, block_count, filename)
        # return send_file(
        #     io.BytesIO(create_zip_of_saved_files()),
        #     as_attachment=True,
        #     download_name="files_archive.zip",
        #     mimetype="application/zip"
        # )
    return render_template("index.html", files=files)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
