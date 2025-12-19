#!/usr/bin/env python3
import argparse
import struct
import sys
import uuid
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_BYTES = b"PGRSUS01"
MAGIC_LEN = 8
SALT_LEN = 32
NONCE_LEN = 12
RESERVED_LEN = 12
HEADER_LEN = MAGIC_LEN + SALT_LEN + NONCE_LEN + RESERVED_LEN
CHUNK_SIZE = 1 * 1024 * 1024
PBKDF2_ITERATIONS = 100000
ENV_KEY_NAME = "POSTGRESUS_MASTER_KEY"   # имя переменной в .env


def load_env_value(name: str, env_path: str = ".env") -> str:
    """
    Простейший парсер .env:
    Ищет строку вида KEY=VALUE, игнорирует комментарии и пустые строки.
    """
    if not os.path.exists(env_path):
        raise SystemExit(f".env file not found at {env_path}")

    value = None
    with open(env_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k == name:
                # убираем кавычки, если есть
                if (v.startswith('"') and v.endswith('"')) or (
                    v.startswith("'") and v.endswith("'")
                ):
                    v = v[1:-1]
                value = v
                break

    if value is None:
        raise SystemExit(f"Variable {name} not found in {env_path}")
    return value


def derive_backup_key(master_key_str: str, backup_id: uuid.UUID, salt: bytes) -> bytes:
    if not master_key_str:
        raise ValueError("master key cannot be empty")
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes, got {len(salt)}")

    # Go: []byte(masterKey + backupID.String())
    key_material = (master_key_str + str(backup_id)).encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(key_material)


def decrypt_backup(in_path: str, master_key: str):
    # backup id = имя файла без расширения
    backup_id_str = Path(in_path).stem
    try:
        backup_id = uuid.UUID(backup_id_str)
    except ValueError as e:
        raise SystemExit(
            f"File name (without extension) must be valid UUID, got '{backup_id_str}': {e}"
        )

    out_path = backup_id_str + ".dump"

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        # ---- header ----
        header = fin.read(HEADER_LEN)
        if len(header) != HEADER_LEN:
            raise SystemExit(
                f"Invalid file: expected header of {HEADER_LEN} bytes, got {len(header)}"
            )

        magic = header[0:MAGIC_LEN]
        if magic != MAGIC_BYTES:
            raise SystemExit(
                f"Invalid magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}"
            )

        salt = header[MAGIC_LEN:MAGIC_LEN + SALT_LEN]
        base_nonce = header[MAGIC_LEN + SALT_LEN:MAGIC_LEN + SALT_LEN + NONCE_LEN]
        # reserved = header[MAGIC_LEN + SALT_LEN + NONCE_LEN:]  # не трогаем

        # ---- key ----
        derived_key = derive_backup_key(master_key, backup_id, salt)
        aesgcm = AESGCM(derived_key)

        chunk_index = 0
        while True:
            length_buf = fin.read(4)
            if not length_buf:
                break
            if len(length_buf) < 4:
                raise SystemExit("Unexpected EOF while reading chunk length")

            (chunk_len,) = struct.unpack(">I", length_buf)

            if chunk_len == 0 or chunk_len > CHUNK_SIZE + 16:
                raise SystemExit(f"Invalid chunk length: {chunk_len}")

            encrypted = fin.read(chunk_len)
            if len(encrypted) != chunk_len:
                raise SystemExit(
                    f"Unexpected EOF while reading encrypted chunk: "
                    f"expected {chunk_len}, got {len(encrypted)}"
                )

            # nonce как в Go: первые 4 байта фикс, дальше счётчик
            chunk_nonce = bytearray(NONCE_LEN)
            chunk_nonce[0:4] = base_nonce[0:4]
            struct.pack_into(">Q", chunk_nonce, 4, chunk_index)

            try:
                plaintext = aesgcm.decrypt(bytes(chunk_nonce), encrypted, None)
            except Exception as e:
                raise SystemExit(
                    f"Failed to decrypt chunk {chunk_index}: {e}\n"
                    f"File may be corrupted OR master key / file name (UUID) is wrong."
                )

            fout.write(plaintext)
            chunk_index += 1

    print(f"OK: decrypted {in_path} -> {out_path}, chunks: {chunk_index}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt Postgresus AES-256-GCM backup (file name = backup UUID, key from .env)"
    )
    parser.add_argument(
        "backup_file",
        help="Encrypted backup file (in current directory). "
             "Backup ID is taken from the file name (without extension).",
    )
    parser.add_argument(
        "--env",
        dest="env_path",
        default=".env",
        help="Path to .env file (default: .env)",
    )
    parser.add_argument(
        "--env-key",
        dest="env_key",
        default=ENV_KEY_NAME,
        help=f"Env variable name with master key (default: {ENV_KEY_NAME})",
    )

    args = parser.parse_args()

    master_key = load_env_value(args.env_key, args.env_path)
    decrypt_backup(args.backup_file, master_key)


if __name__ == "__main__":
    main()
