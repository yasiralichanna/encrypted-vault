import os
import sys
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import getpass

class SecureVault:
    def __init__(self):
        self.key = None
        self.salt = None
        self.password = None

    def generate_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Generate a key from password using PBKDF2"""
        if salt is None:
            self.salt = os.urandom(16)
        else:
            self.salt = salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.password = password
        return self.key

    def load_key_from_file(self, keyfile_path: str) -> None:
        """Load a pre-generated key"""
        if not os.path.exists(keyfile_path):
            raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
        
        with open(keyfile_path, 'rb') as f:
            self.key = f.read()
        self.salt = None

    def encrypt_file(self, input_file: str, output_file: str = None) -> str:
        """Base encryption function"""
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        if not self.key:
            raise ValueError("Encryption key not loaded")

        if output_file is None:
            output_file = input_file + '.enc'

        fernet = Fernet(self.key)
        
        with open(input_file, 'rb') as f:
            file_data = f.read()
        
        encrypted = fernet.encrypt(file_data)

        with open(output_file, 'wb') as f:
            if self.salt is not None:
                f.write(self.salt + encrypted)
            else:
                f.write(encrypted)

        return output_file

    def decrypt_file(self, input_file: str, output_file: str = None) -> str:
        """Base decryption function"""
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")

        if output_file is None:
            if input_file.endswith('.enc'):
                output_file = input_file[:-4]
            else:
                output_file = input_file + '.dec'

        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        if self.salt is not None:
            if len(encrypted_data) < 16:
                raise ValueError("Invalid encrypted file format")
            
            salt = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            if not self.password:
                self.password = getpass.getpass("Enter decryption password: ")
            
            self.generate_key_from_password(self.password, salt)
        else:
            ciphertext = encrypted_data

        fernet = Fernet(self.key)

        try:
            decrypted = fernet.decrypt(ciphertext)
        except:
            raise ValueError("Decryption failed (wrong password/key or corrupted file)")

        with open(output_file, 'wb') as f:
            f.write(decrypted)

        return output_file

    def secure_delete(self, file_path: str, passes: int = 3) -> None:
        """Securely delete a file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
            os.remove(file_path)
        except Exception as e:
            raise IOError(f"Secure deletion failed: {str(e)}")

    def secure_encrypt(self, input_file: str, output_file: str = None) -> str:
        """Encrypt and securely delete original"""
        encrypted_file = self.encrypt_file(input_file, output_file)
        self.secure_delete(input_file)
        return encrypted_file

    def secure_decrypt(self, input_file: str, output_file: str = None) -> str:
        """Decrypt and securely delete encrypted file"""
        decrypted_file = self.decrypt_file(input_file, output_file)
        self.secure_delete(input_file)
        return decrypted_file

    def generate_keyfile(self, keyfile_path: str = 'vault.key') -> str:
        """Generate a new random keyfile"""
        if os.path.exists(keyfile_path):
            raise FileExistsError(f"Keyfile already exists: {keyfile_path}")

        key = Fernet.generate_key()
        with open(keyfile_path, 'wb') as f:
            f.write(key)
        return keyfile_path

def main():
    parser = argparse.ArgumentParser(
        description="Secure File Vault - Encrypt/decrypt with automatic secure deletion",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt file (original will be securely deleted)')
    encrypt_parser.add_argument('input', help='File to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file (default: <input>.enc)')
    encrypt_parser.add_argument('-p', '--password', help='Password (optional)')
    encrypt_parser.add_argument('-k', '--keyfile', help='Use keyfile instead of password')

    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt file (encrypted file will be securely deleted)')
    decrypt_parser.add_argument('input', help='File to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output file (default: <input> without .enc)')
    decrypt_parser.add_argument('-p', '--password', help='Password (optional)')
    decrypt_parser.add_argument('-k', '--keyfile', help='Use keyfile instead of password')

    # Shred command
    shred_parser = subparsers.add_parser('shred', help='Securely delete a file')
    shred_parser.add_argument('file', help='File to shred')
    shred_parser.add_argument('-p', '--passes', type=int, default=3, help='Overwrite passes (default: 3)')

    # Keygen command
    keygen_parser = subparsers.add_parser('keygen', help='Generate a new keyfile')
    keygen_parser.add_argument('-o', '--output', default='vault.key', help='Output path (default: vault.key)')

    args = parser.parse_args()
    vault = SecureVault()

    try:
        if args.command == 'encrypt':
            if args.keyfile:
                vault.load_key_from_file(args.keyfile)
            else:
                password = args.password if args.password else getpass.getpass("Enter encryption password: ")
                vault.generate_key_from_password(password)

            encrypted_file = vault.secure_encrypt(args.input, args.output)
            print(f" File encrypted and original securely deleted: {encrypted_file}")

        elif args.command == 'decrypt':
            if args.keyfile:
                vault.load_key_from_file(args.keyfile)
            elif args.password:
                vault.generate_key_from_password(args.password)

            decrypted_file = vault.secure_decrypt(args.input, args.output)
            print(f" File decrypted and encrypted version securely deleted: {decrypted_file}")

        elif args.command == 'shred':
            confirm = input(f" PERMANENTLY delete '{args.file}'? (y/n): ")
            if confirm.lower() == 'y':
                vault.secure_delete(args.file, args.passes)
                print(f"🗑️ File securely deleted: {args.file}")
            else:
                print(" Cancelled")

        elif args.command == 'keygen':
            keyfile = vault.generate_keyfile(args.output)
            print(f"🔑 New keyfile: {keyfile}\n Keep it secure!")

    except Exception as e:
        print(f"\n Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()