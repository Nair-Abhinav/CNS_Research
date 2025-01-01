import hashlib
import hmac
import random
import networkx as nx
import os
import numpy as np
from PIL import Image

def generate_graph(seed: int) -> nx.Graph:
    random.seed(seed)
    graph = nx.Graph()
    ascii_range = range(256)  # Full byte range for image pixels
    graph.add_nodes_from(ascii_range)
    for i in ascii_range:
        for j in ascii_range:
            if random.random() < 0.05:  # Random edge creation
                graph.add_edge(i, j)
    return graph

def randomize_graph(graph: nx.Graph, seed: int) -> nx.Graph:
    random.seed(seed)
    nodes = list(graph.nodes())
    random.shuffle(nodes)
    randomized_graph = nx.Graph()
    randomized_graph.add_nodes_from(nodes)
    randomized_graph.add_edges_from((nodes[i], nodes[j]) for i, j in graph.edges())
    return randomized_graph

def derive_key(key: str, salt: bytes = None) -> (int, bytes):
    if salt is None:
        salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000)
    return int.from_bytes(derived_key, byteorder='big'), salt

def compute_param(pixel: int, derived_key: int, salt: int) -> int:
    return (pixel ^ derived_key ^ salt) % 256

def xor_encrypt(data: bytes, key: int) -> bytes:
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    return bytes(d ^ key_bytes[i % len(key_bytes)] for i, d in enumerate(data))

def add_authentication(data: bytes, auth_key: bytes) -> bytes:
    hmac_digest = hmac.new(auth_key, data, hashlib.sha256).digest()
    return data + hmac_digest


def encrypt_image(image_path: str, key: str) -> (str, bytes, np.ndarray):
    # Open the image and convert to grayscale
    original_image = Image.open(image_path).convert('L')
    image_array = np.array(original_image)
    
    # Derive key and generate graph
    derived_key, salt = derive_key(key)
    graph = generate_graph(derived_key)
    randomized_graph = randomize_graph(graph, derived_key)
    coloring = nx.coloring.greedy_color(randomized_graph, strategy="random_sequential")
    
    # Prepare encrypted image data
    encrypted_pairs = []
    for i in range(image_array.shape[0]):
        row_pairs = []
        for j in range(image_array.shape[1]):
            pixel = image_array[i, j]
            color = coloring[pixel]
            salt_value = random.randint(0, 255)  # Random salt for each pixel
            param = compute_param(pixel, derived_key, salt_value)
            row_pairs.append((color, param, salt_value))
        encrypted_pairs.append(row_pairs)
    
    # Flatten and serialize pairs
    flat_pairs = [f"{color}-{param}-{salt}" for row in encrypted_pairs for color, param, salt in row]
    cipher_str = '|'.join(flat_pairs)
    
    # XOR encrypt the serialized string
    encrypted_cipher = xor_encrypt(cipher_str.encode('utf-8'), derived_key)
    
    # Add HMAC for authentication
    auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    final_cipher = add_authentication(encrypted_cipher, auth_key)
    
    return final_cipher.hex(), salt, image_array

def decrypt_image(cipher_text: str, key: str, salt: bytes, original_shape: tuple) -> np.ndarray:
    # Derive key
    derived_key, _ = derive_key(key, salt)
    
    # Prepare authentication
    auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    
    # Verify and extract the ciphertext
    encrypted_data = bytes.fromhex(cipher_text)
    decrypted_data = verify_authentication(encrypted_data, auth_key)
    
    # XOR Decrypt the serialized string
    decrypted_str = xor_decrypt(decrypted_data, derived_key)
    
    # Reconstruct cipher text pairs
    cipher_pairs = [
        tuple(map(int, pair.split('-'))) for pair in decrypted_str.split('|')
    ]
    
    # Regenerate graph and coloring
    graph = generate_graph(derived_key)
    randomized_graph = randomize_graph(graph, derived_key)
    coloring = nx.coloring.greedy_color(randomized_graph, strategy="random_sequential")
    
    # Decrypt image
    decrypted_array = np.zeros(original_shape, dtype=np.uint8)
    for i in range(original_shape[0]):
        for j in range(original_shape[1]):
            color, param, salt_value = cipher_pairs[i * original_shape[1] + j]
            # Find the original pixel value
            for pixel, char_color in coloring.items():
                if char_color == color and compute_param(pixel, derived_key, salt_value) == param:
                    decrypted_array[i, j] = pixel
                    break
    
    return decrypted_array

def xor_decrypt(data: bytes, key: int) -> str:
    decrypted_bytes = xor_encrypt(data, key)
    return decrypted_bytes.decode('utf-8', errors='ignore')

def verify_authentication(data: bytes, auth_key: bytes) -> bytes:
    """Verify the HMAC and return the data if valid."""
    received_data, received_hmac = data[:-32], data[-32:]
    expected_hmac = hmac.new(auth_key, received_data, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("Authentication failed.")
    return received_data

def main():
    # Image path
    image_path = 'gray_scale.jpeg'
    key = "Cryptography"
    
    # Encrypt
    encrypted_data, salt, original_image = encrypt_image(image_path, key)
    
    # Save original image
    original_img = Image.fromarray(original_image)
    original_img.save('original_image.jpeg')
    
    # Save encrypted visualization (just for demonstration)
    encrypted_img = Image.fromarray(np.random.randint(0, 256, original_image.shape, dtype=np.uint8))
    encrypted_img.save('encrypted_image.jpeg')
    
    # Decrypt
    try:
        decrypted_array = decrypt_image(encrypted_data, key, salt, original_image.shape)
        
        # Save decrypted image
        decrypted_img = Image.fromarray(decrypted_array)
        decrypted_img.save('decrypted_image.jpeg')
        
        print("Encryption and decryption completed successfully.")
    except ValueError as e:
        print(f"Decryption error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

