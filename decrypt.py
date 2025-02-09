#!/usr/bin/env python3

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA512
import sys
import json
import getpass
import os
import argparse

def decrypt_file(filename, password, base_path, output_dir, ignore_existing=False):
    with open(filename, 'rb') as file:
        version = int.from_bytes(file.read(4), byteorder='big')
        # Script only work for version 2 of encryption algorythm
        if version != 2:
            print_animation("Not 2 version of encryption")
            return 1

        salt = file.read(16)
        iv = file.read(12)
        iterations=int.from_bytes(file.read(4), byteorder='big')
            
        cipher = ChaCha20.new(
            key=PBKDF2(password, salt=salt, dkLen=32, count=iterations, hmac_hash_module=SHA512),
            nonce=iv
        )

        check = file.read(12)
        decrypted_check = cipher.decrypt(file.read(12))
        if (check != decrypted_check):
            print_animation("Invalid password for file", filename)
            return 1

        cipher.decrypt(file.read(1)) # skip newline character
        name_bytes = bytearray()
        while (True):
            c = cipher.decrypt(file.read(1))
            if (c == b'\n'): # read until newline
                break
            name_bytes.extend(c)

        try:
            original_name = name_bytes.decode("utf-8")
        except:
            print_animation("Could not decode the original filename, did you use the correct password?")
            return 1

        # Convert json to normal string
        original_name = json.loads(original_name)
        original_name = original_name.get("originalName")

        # Set relative path for sync functionality
        relative_path = os.path.relpath(filename, start=base_path)
        
        # Create path to sync directory
        output_dir = os.path.join(output_dir, os.path.dirname(relative_path))
        new_file = os.path.join(output_dir,original_name)

        # If ignore-existing flag is True check if file exist in output directory
        if ignore_existing:
            if os.path.exists(new_file):
                #print(f"File {new_file} exist.")
                return 0

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        print_animation(f"Decrypting: {relative_path}")
        decrypted = cipher.decrypt(file.read())
        with open(new_file, 'wb') as output_file:
            output_file.write(decrypted)

    print_animation(f"Decrypted to {new_file}")
    return 0

# Simple animation to show that script is working
def working_animation(frame):
    frames = ['\\', '|', '/', '-']
    sys.stdout.write(f'\r [{frames[frame]}] Comparing files...')
    sys.stdout.flush()

def print_animation(string):
    clear_animation=len(string)-23
    if clear_animation < 0:
        clear_animation = 0
    sys.stdout.write('\r' + string + ' '*clear_animation + '\n')


# Tworzymy parser argumentów
parser = argparse.ArgumentParser()

# Dodajemy obowiązkowe argumenty
parser.add_argument("-i", "--input", required=True, type=str, help="type input directory or file")
parser.add_argument("-o", "--output", required=False, type=str, help="type output directory")
parser.add_argument("--ignore-existing", action="store_true", help="skip updating files that exist on output")

# Parsujemy argumenty
args = parser.parse_args()


if args.output is None:
    sync_directory='./'
else:
    sync_directory=args.output

if not os.path.isdir(sync_directory):
    print(f"Error: The folder {sync_directory} does not exist.")
    sys.exit(1)

if os.path.isfile(args.input):
    decrypt_file(args.input, getpass.getpass("Password: ").encode().strip(), args.input, sync_directory, args.ignore_existing)
elif os.path.isdir(args.input):
    directory = args.input
    pw = getpass.getpass("Password: ").encode().strip()
    frame_num = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            # Check if file has the `.valv` extension and skip thumbnail files
            if file.endswith(".valv") and not file.endswith("-t.valv"):
                full_path = os.path.join(root, file)
                decrypt_file(full_path, pw, directory, sync_directory, args.ignore_existing)
                if args.ignore_existing:
                    working_animation(frame_num)
                    frame_num = (frame_num + 1) % 4

print()
