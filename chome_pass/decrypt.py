import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# Define file names in the current directory
LOCAL_STATE_FILE = "Local State"
LOGIN_DATA_FILE = "Login Data"

def get_secret_key():
    try:
        # Read the Local State file from the current directory
        with open(LOCAL_STATE_FILE, "r", encoding='utf-8') as f:
            local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            # Remove the 'DPAPI' prefix
            encrypted_key = encrypted_key[5:]
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        print(f"[ERR] Secret key extraction failed: {e}")
        return None

def decrypt_password(ciphertext, secret_key):
    try:
        # Extract the initialization vector (IV) and encrypted password
        iv = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        return decrypted_password
    except Exception as e:
        print(f"[ERR] Decryption failed: {e}")
        return ""

def get_db_connection(db_path):
    try:
        # Copy the database to avoid locking issues
        temp_db_path = "TempVault.db"
        shutil.copy2(db_path, temp_db_path)
        return sqlite3.connect(temp_db_path)
    except Exception as e:
        print(f"[ERR] Database connection failed: {e}")
        return None

def main():
    try:
        # Check if the required files exist in the current directory
        if not os.path.exists(LOCAL_STATE_FILE):
            print(f"[ERR] '{LOCAL_STATE_FILE}' not found in the current directory.")
            return
        if not os.path.exists(LOGIN_DATA_FILE):
            print(f"[ERR] '{LOGIN_DATA_FILE}' not found in the current directory.")
            return

        # Get the secret key
        secret_key = get_secret_key()
        if not secret_key:
            print("[ERR] Unable to retrieve secret key.")
            return

        # Open a CSV file to write the extracted passwords
        with open('output.csv', mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            writer.writerow(["index", "url", "username", "password"])

            # Connect to the Login Data database
            conn = get_db_connection(LOGIN_DATA_FILE)
            if conn:
                cursor = conn.cursor()
                try:
                    # Query the logins table
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, (url, username, ciphertext) in enumerate(cursor.fetchall()):
                        if url and username and ciphertext:
                            password = decrypt_password(ciphertext, secret_key)
                            if password:
                                writer.writerow([index, url, username, password])
                                print(f"Index: {index}\nURL: {url}\nUsername: {username}\nPassword: {password}\n" + "*" * 50)
                except sqlite3.OperationalError as e:
                    print(f"[ERR] SQL query failed: {e}")
                finally:
                    cursor.close()
                    conn.close()
                    # Clean up the temporary database file
                    if os.path.exists("TempVault.db"):
                        os.remove("TempVault.db")
    except Exception as e:
        print(f"[ERR] {e}")

if __name__ == '__main__':
    main()
