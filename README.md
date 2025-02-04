A simple steganography tool for hiding messages inside images.

Features

✅ Hide text messages inside images
✅ AES encryption for added security
✅ Generates a secret key for decryption
✅ Simple command-line usage

How It Works
	1.	Message Input – Write your message in input.txt.
	2.	Encryption & Embedding – Run encryptor.py, which:
	•	Encrypts the message.
	•	Hides it inside an image (output.png).
	•	Generates a decryption key.
	3.	Decryption – Run decryptor.py, which:
	•	Extracts the hidden message from output.png.
	•	Outputs the decrypted text to output.txt.

Usage

Encrypt a Message

python encryptor.py

	•	Outputs: output.png and a secret key.

Decrypt a Message

python decryptor.py

	•	Requires output.png and the key.
	•	Outputs: output.txt.
