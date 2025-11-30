import hashlib
import base64
from PIL import Image
from cryptography.fernet import Fernet
from io import BytesIO

# --- Encryption Module ---
def generate_key(password):
    """Generates a valid AES key from a user password."""
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_message(message, password):
    """Encrypts text using AES."""
    key = generate_key(password)
    f = Fernet(key)
    encrypted_bytes = f.encrypt(message.encode())
    return encrypted_bytes.decode()

def decrypt_message(encrypted_message, password):
    """Decrypts text using AES."""
    try:
        key = generate_key(password)
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_message.encode())
        return decrypted_bytes.decode()
    except Exception:
        return None # Failed to decrypt (wrong password)

# --- Steganography Module ---
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def hide_data(image_file, secret_text):
    """Hides text inside an image file object."""
    image = Image.open(image_file)
    image = image.convert("RGB")
    pixels = image.load()
    width, height = image.size
    
    # Add a delimiter to know when the message ends
    secret_text += "#####"
    binary_secret = text_to_binary(secret_text)
    data_len = len(binary_secret)
    
    if data_len > width * height * 3:
        raise ValueError("Message too large for this image.")

    data_index = 0
    for y in range(height):
        for x in range(width):
            if data_index < data_len:
                r, g, b = pixels[x, y]
                
                # Modify Red
                if data_index < data_len:
                    r = (r & ~1) | int(binary_secret[data_index])
                    data_index += 1
                # Modify Green
                if data_index < data_len:
                    g = (g & ~1) | int(binary_secret[data_index])
                    data_index += 1
                # Modify Blue
                if data_index < data_len:
                    b = (b & ~1) | int(binary_secret[data_index])
                    data_index += 1
                
                pixels[x, y] = (r, g, b)
            else:
                break
        if data_index >= data_len:
            break
    
    # Save to a BytesIO object instead of disk (better for web apps)
    img_byte_arr = BytesIO()
    image.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    return img_byte_arr

def reveal_data(image_file):
    """Extracts text from an image file object."""
    image = Image.open(image_file)
    image = image.convert("RGB")
    pixels = image.load()
    width, height = image.size
    
    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
    
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    decoded_string = ""
    
    for byte in all_bytes:
        decoded_string += chr(int(byte, 2))
        if decoded_string.endswith("#####"):
            return decoded_string[:-5]
            
    return None # No message found
