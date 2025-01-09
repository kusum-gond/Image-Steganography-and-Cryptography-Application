import streamlit as st
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
from skimage.metrics import structural_similarity as ssim
import matplotlib.pyplot as plt
import io
import hashlib
import base64
import stepic

def generate_key(passkey: str):
    hash_key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hash_key)

def encrypt_text(text: str, passkey: str):
    key = generate_key(passkey)
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text.decode()

def decrypt_text(encrypted_text: str, passkey: str):
    key = generate_key(passkey)
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
    return decrypted_text.decode()

def encode_text_in_image(image, text):
    return stepic.encode(image, text.encode())

def decode_text_from_image(image):
    return stepic.decode(image)

def calculate_mse(original, stego):
    return np.mean((np.array(original) - np.array(stego)) ** 2)

def calculate_psnr(original, stego):
    mse_value = calculate_mse(original, stego)
    if mse_value == 0:
        return float('inf')
    max_pixel = 255.0
    return 20 * np.log10(max_pixel / np.sqrt(mse_value))

def calculate_ssim(original, stego):
    original_array = np.array(original.convert('L'))
    stego_array = np.array(stego.convert('L'))
    return ssim(original_array, stego_array)

def calculate_ncc(original, stego):
    original_array = np.array(original).flatten()
    stego_array = np.array(stego).flatten()
    return np.corrcoef(original_array, stego_array)[0, 1]

def calculate_ber(original, stego):
    original_bits = np.unpackbits(np.array(original, dtype=np.uint8))
    stego_bits = np.unpackbits(np.array(stego, dtype=np.uint8))
    return np.mean(original_bits != stego_bits)

def plot_histograms(original, stego):
    original_hist = np.array(original).flatten()
    stego_hist = np.array(stego).flatten()
    fig, ax = plt.subplots(1, 2, figsize=(10, 5))
    ax[0].hist(original_hist, bins=256, color='blue', alpha=0.5, label="Original Image")
    ax[1].hist(stego_hist, bins=256, color='red', alpha=0.5, label="Stego Image")
    ax[0].set_title('Original Image Histogram')
    ax[1].set_title('Stego Image Histogram')
    st.pyplot(fig)

st.title("Steganography & Cryptography App")

uploaded_image = st.file_uploader("Choose an image...", type=["png", "jpg", "jpeg"])

if uploaded_image:
    image = Image.open(uploaded_image)
    st.image(image, caption='Uploaded Image.', use_column_width=True)
    option = st.selectbox("Choose Operation", ["Encrypt Text in Image", "Decrypt Text from Image"])

    if option == "Encrypt Text in Image":
        text_to_hide = st.text_area("Enter text to hide:")
        passkey = st.text_input("Enter Passkey (For Encryption):", type="password")

        if st.button("Encrypt and Hide Text"):
            if text_to_hide and passkey:
                try:
                    encrypted_text = encrypt_text(text_to_hide, passkey)
                    st.write(f"Encrypted Text: {encrypted_text}")
                    encoded_image = encode_text_in_image(image, encrypted_text)
                    img_bytes = io.BytesIO()
                    encoded_image.save(img_bytes, format='PNG')
                    st.download_button("Download Image", data=img_bytes.getvalue(), file_name="encoded_image.png")
                    psnr_value = calculate_psnr(image, encoded_image)
                    mse_value = calculate_mse(image, encoded_image)
                    ssim_value = calculate_ssim(image, encoded_image)
                    ncc_value = calculate_ncc(image, encoded_image)
                    ber_value = calculate_ber(image, encoded_image)
                    st.write(f"**Image Quality Analysis**")
                    st.write(f"PSNR: {psnr_value:.2f} dB")
                    st.write(f"MSE: {mse_value:.2f}")
                    st.write(f"SSIM: {ssim_value:.4f}")
                    st.write(f"NCC: {ncc_value:.4f}")
                    st.write(f"BER: {ber_value:.4f}")
                    st.write("**Histogram Analysis**")
                    plot_histograms(image, encoded_image)
                except Exception as e:
                    st.error(f"An error occurred: {e}")

    elif option == "Decrypt Text from Image":
        passkey = st.text_input("Enter Passkey (For Decryption):", type="password")

        if st.button("Decode and Decrypt Text"):
            try:
                hidden_text = decode_text_from_image(image)
                decrypted_text = decrypt_text(hidden_text, passkey)
                st.write(f"Decrypted Text: {decrypted_text}")
            except Exception as e:
                st.error(f"Incorrect Pass Key {e}")
