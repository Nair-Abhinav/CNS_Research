import hashlib
import hmac
import random
import networkx as nx
import os

def generate_graph(seed: int) -> nx.Graph:
    random.seed(seed)
    graph = nx.Graph()
    ascii_range = range(128)  # Standard ASCII range
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

def compute_param(char: int, derived_key: int, salt: int) -> int:
    return (char ^ derived_key ^ salt) % 256

def xor_encrypt(data: str, key: int) -> str:
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    return ''.join(chr(ord(c) ^ key_bytes[i % len(key_bytes)]) for i, c in enumerate(data))

def add_authentication(data: bytes, auth_key: bytes) -> bytes:
    hmac_digest = hmac.new(auth_key, data, hashlib.sha256).digest()
    return data + hmac_digest

def encrypt(plain_text: str, key: str) -> (str, bytes):
    derived_key, salt = derive_key(key)
    graph = generate_graph(derived_key)
    randomized_graph = randomize_graph(graph, derived_key)
    coloring = nx.coloring.greedy_color(randomized_graph, strategy="random_sequential")
    
    cipher_pairs = []
    for char in plain_text:
        ascii_val = ord(char)
        color = coloring[ascii_val]
        salt_value = random.randint(0, 255)  # Random salt for each character
        param = compute_param(ascii_val, derived_key, salt_value)
        cipher_pairs.append((color, param, salt_value))
    
    # Serialize pairs into a string
    cipher_str = '|'.join(f"{color}-{param}-{salt}" for color, param, salt in cipher_pairs)
    return cipher_str, salt

def xor_decrypt(data: str, key: int) -> str:
    return xor_encrypt(data, key)  # XOR is symmetric

def decode_character(color: int, param: int, coloring: dict, derived_key: int, salt: int) -> str:
    for char, char_color in coloring.items():
        if char_color == color and compute_param(char, derived_key, salt) == param:
            return chr(char)
    raise ValueError("Decryption failed. Invalid cipher text or key.")

def verify_authentication(data: bytes, auth_key: bytes) -> bytes:
    """Verify the HMAC and return the data if valid."""
    received_data, received_hmac = data[:-32], data[-32:]
    expected_hmac = hmac.new(auth_key, received_data, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("Authentication failed.")
    return received_data

def decrypt(cipher_text: str, key: str, salt: bytes) -> str:
    """Decrypt the cipher text using the given key."""
    derived_key, _ = derive_key(key, salt)

    # auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    
    # # Verify and extract the ciphertext
    # encrypted_data = bytes.fromhex(cipher_text)
    # decrypted_data = verify_authentication(encrypted_data, auth_key)
    
    # # XOR Decrypt the serialized string
    # decrypted_str = xor_decrypt(decrypted_data.decode(), derived_key)
    
    # Reconstruct cipher text pairs
    cipher_pairs = [
        tuple(map(int, pair.split('-'))) for pair in cipher_text.split('|')
    ]
    
    graph = generate_graph(derived_key)
    randomized_graph = randomize_graph(graph, derived_key)
    coloring = nx.coloring.greedy_color(randomized_graph, strategy="random_sequential")
    
    plain_text = []
    for color, param, salt_value in cipher_pairs:
        plain_text.append(decode_character(color, param, coloring, derived_key, salt_value))
    
    return ''.join(plain_text)

key = "Cryptography"
plain_text = "Hello, Secure World!"

# key = input('Enter Secret Key: ')
# plain_text = input('Enter Plain Text: ')

# Encrypt
cipher_text, salt = encrypt(plain_text, key)
print("Cipher Text:", cipher_text)

# Decrypt
try:
    decrypted_text = decrypt(cipher_text, key, salt)
    print("Decrypted Text:", decrypted_text)
except ValueError as e:
    print(e)
