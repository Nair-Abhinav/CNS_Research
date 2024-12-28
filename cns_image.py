import hashlib
import hmac
import os
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image


def derive_key(key: str, salt: bytes = None) -> (int, bytes):
    if salt is None:
        salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000)
    return int.from_bytes(derived_key, byteorder='big'), salt


def xor_encrypt(data: bytes, key: int) -> bytes:
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    return bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(data))


def add_authentication(data: bytes, auth_key: bytes) -> bytes:
    hmac_digest = hmac.new(auth_key, data, hashlib.sha256).digest()
    return data + hmac_digest


def verify_authentication(data: bytes, auth_key: bytes) -> bytes:
    received_data, received_hmac = data[:-32], data[-32:]
    expected_hmac = hmac.new(auth_key, received_data, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("Authentication failed.")
    return received_data


def encrypt_image(image_path: str, key: str) -> (bytes, bytes, bytes):
    # Load image as bytes
    with open(image_path, "rb") as img_file:
        img_data = img_file.read()

    # Derive key
    derived_key, salt = derive_key(key)

    # Encrypt image data
    encrypted_data = xor_encrypt(img_data, derived_key)

    # Add HMAC for authentication
    auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    final_encrypted_data = add_authentication(encrypted_data, auth_key)

    return final_encrypted_data, salt, img_data


def decrypt_image(encrypted_data: bytes, key: str, salt: bytes) -> bytes:
    # Derive key
    derived_key, _ = derive_key(key, salt)

    # Verify authentication
    auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    verified_data = verify_authentication(encrypted_data, auth_key)

    # Decrypt image data
    decrypted_data = xor_encrypt(verified_data, derived_key)

    return decrypted_data


def display_images(original_path: str, encrypted: bytes, decrypted_path: str):
    # Load original and decrypted images
    original_img = np.array(Image.open(original_path))
    decrypted_img = np.array(Image.open(decrypted_path))

    # Process encrypted image for visualization
    encrypted_data_without_hmac = encrypted[:-32]  # Remove HMAC
    encrypted_img = np.frombuffer(encrypted_data_without_hmac, dtype=np.uint8)
    encrypted_img = encrypted_img[: original_img.size]  # Match the size of the original image
    encrypted_img = encrypted_img.reshape(original_img.shape)

    # Display images
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    axes[0].imshow(original_img)
    axes[0].set_title("Original Image")
    axes[0].axis("off")

    axes[1].imshow(encrypted_img, cmap="gray")
    axes[1].set_title("Encrypted Image")
    axes[1].axis("off")

    axes[2].imshow(decrypted_img)
    axes[2].set_title("Decrypted Image")
    axes[2].axis("off")

    plt.tight_layout()
    plt.show()


# Input details
original_image_path = "free-nature-images.jpg"  # Path to the original image
key = "SecureEncryptionKey"

# Encrypt the image
encrypted_image, salt, original_data = encrypt_image(original_image_path, key)

# Decrypt the image
decrypted_image = decrypt_image(encrypted_image, key, salt)

# Save decrypted image for visualization
decrypted_image_path = "decrypted_image.jpg"
with open(decrypted_image_path, "wb") as f:
    f.write(decrypted_image)

# Display the images
display_images(original_image_path, encrypted_image, decrypted_image_path)
