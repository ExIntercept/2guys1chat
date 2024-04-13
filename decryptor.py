"""extracting data back from the image"""

import cv2

def extract_hidden_data_from_image(image_path, size_file_path, extracted_binary_file_path):
    # Load the image
    image = cv2.imread(image_path)

    # Read the size of the hidden data from the size.txt file
    with open(size_file_path, 'r') as size_file:
        data_length = int(size_file.read())

    # Initialize variables
    binary_data = ''
    binary_index = 0

    # Get the shape of the image
    rows, cols, _ = image.shape

    # Iterate through each pixel in the image
    for i in range(rows):
        for j in range(cols):
            # Extract RGB values of the pixel
            r, g, b = image[i, j]

            # Convert RGB values to binary strings
            r_binary = format(r, '08b')
            g_binary = format(g, '08b')
            b_binary = format(b, '08b')

            # Extract the least significant bit of each color channel
            binary_data += r_binary[-1]
            binary_index += 1
            if binary_index < data_length:
                binary_data += g_binary[-1]
                binary_index += 1
            if binary_index < data_length:
                binary_data += b_binary[-1]
                binary_index += 1

            # Break loop if enough data has been extracted
            if binary_index >= data_length:
                break
        if binary_index >= data_length:
            break

    # Convert the binary data to bytes
    extracted_data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

    # Write the extracted data to a binary file
    with open(extracted_binary_file_path, 'wb') as extracted_file:
        extracted_file.write(extracted_data)

# Example usage
image_path = 'output.png'  # Path to the image with hidden data
size_file_path = 'content/size.txt'  # Path to the file storing the size of the hidden data
extracted_binary_file_path = 'content/extracted_data.bin'  # Path for the extracted binary data file

# Extract hidden data from the image
extract_hidden_data_from_image(image_path, size_file_path, extracted_binary_file_path)

"""binary to text"""

def binary_to_encrypted_text(input_file, output_file):
    try:
        # Open the input file in binary read mode
        with open(input_file, 'rb') as f:
            # Read the binary data from the input file
            binary_data = f.read()

        # Open the output file in write mode
        with open(output_file, 'wb') as f:
            # Write the binary data to the output file
            f.write(binary_data)

        print("Binary data converted to encrypted text and saved to file successfully!")

    except FileNotFoundError:
        print("File not found. Please provide valid file paths.")
    except Exception as e:
        print("An error occurred:", str(e))


# Provide the paths of the input and output files
input_file_path = "content/extracted_data.bin"
output_file_path = "content/encrypted_text_output.txt"

# Call the function to convert binary data to encrypted text and save it to a text file
binary_to_encrypted_text(input_file_path, output_file_path)

"""decrypter"""

import os
import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pub_key_decryptor():
    with open("key/private.pem", "rb") as f:
      private_key = rsa.PrivateKey.load_pkcs1(f.read())

    encrypted_message = open("key/pki_encrypted.txt","rb").read()
    global clear_message
    clear_message = rsa.decrypt(encrypted_message, private_key)
    with open("key/pki_decrypted.txt", "wb") as f:
      f.write(clear_message)


def decrypt_file(input_file, output_file):
    # Read the salt, IV, and ciphertext from the encrypted file
    with open(input_file, 'rb') as f:
        # Read the salt (16 bytes)
        salt = f.read(16)
        # Read the IV (16 bytes)
        iv = f.read(16)
        # Read the ciphertext
        ciphertext = f.read()

    # Read the encryption key from the key.txt file
    '''
    with open("key/pki_decrypted.txt", 'rb') as key_file    w 4y1:
        key = key_file.read()
        print(key)
    '''

    with open("key/key.txt", 'rb') as file1:
        key = file1.read()
        print(key)


    # Derive the key using the password and salt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted plaintext to the output file
    with open(output_file, 'w') as f:
        f.write(unpadded_data.decode('utf-8'))

    print("Decryption completed successfully!")

# Provide the paths of the encrypted file and output decrypted file
encrypted_file_path = "content/encrypted_text_output.txt"
decrypted_file_path = "output.txt"

# Call the decrypt function
pub_key_decryptor()
decrypt_file(encrypted_file_path, decrypted_file_path)