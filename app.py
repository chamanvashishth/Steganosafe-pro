import streamlit as st
import stego_logic as logic

# --- Page Config ---
st.set_page_config(
    page_title="SteganoSafe Pro",
    page_icon="🔒",
    layout="centered"
)

# --- Custom CSS for "Flashy" Look ---
st.markdown("""
<style>
    .stButton>button {
        width: 100%;
        background-color: #00ADB5;
        color: white;
    }
    .stAlert {
        background-color: #222831;
        color: #EEEEEE;
    }
</style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🔒 SteganoSafe Pro")
st.markdown("### Military-Grade Image Steganography")
st.markdown("Hide secret messages inside images using **LSB Manipulation** and **AES Encryption**.")
st.divider()

# --- Tabs for Navigation ---
tab1, tab2, tab3 = st.tabs(["🛡️ Hide Data", "🔓 Reveal Data", "ℹ️ About Project"])

# === TAB 1: HIDE DATA ===
with tab1:
    st.header("Encrypt & Hide")
    uploaded_file = st.file_uploader("Upload an Image (PNG)", type=['png', 'jpg', 'jpeg'])
    
    col1, col2 = st.columns(2)
    with col1:
        secret_message = st.text_area("Secret Message", height=100)
    with col2:
        password = st.text_input("Encryption Password", type="password", key="enc_pass")

    if st.button("Generate Secret Image"):
        if uploaded_file and secret_message and password:
            try:
                with st.spinner("Encrypting and Encoding..."):
                    # 1. Encrypt the text
                    encrypted_text = logic.encrypt_message(secret_message, password)
                    
                    # 2. Hide encrypted text in image
                    result_img_bytes = logic.hide_data(uploaded_file, encrypted_text)
                    
                    st.success("Success! Your image is ready.")
                    
                    # 3. Provide Download
                    st.download_button(
                        label="📥 Download Secret Image",
                        data=result_img_bytes,
                        file_name="secret_image.png",
                        mime="image/png"
                    )
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Please upload an image, enter a message, and set a password.")

# === TAB 2: REVEAL DATA ===
with tab2:
    st.header("Decrypt & Reveal")
    decode_file = st.file_uploader("Upload Secret Image", type=['png'], key="decode_uploader")
    decode_pass = st.text_input("Decryption Password", type="password", key="dec_pass")
    
    if st.button("Reveal Message"):
        if decode_file and decode_pass:
            try:
                with st.spinner("Scanning pixels..."):
                    # 1. Extract hidden data
                    hidden_data = logic.reveal_data(decode_file)
                    
                    if hidden_data:
                        # 2. Decrypt data
                        decrypted_text = logic.decrypt_message(hidden_data, decode_pass)
                        
                        if decrypted_text:
                            st.balloons()
                            st.success("Message Decoded Successfully!")
                            st.code(decrypted_text, language="text")
                        else:
                            st.error("Wrong Password! The message is unreadable.")
                    else:
                        st.error("No hidden message found in this image.")
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Please upload an image and enter the password.")

# === TAB 3: ABOUT ===
with tab3:
    st.markdown("""
    ### Technical Details
    This project uses a dual-layer security approach:
    
    1.  **Cryptography (AES-128):** The text is first encrypted using the **Fernet** symmetric encryption standard.
    2.  **Steganography (LSB):** The encrypted binary string is distributed across the **Least Significant Bits** of the image's RGB channels.
    
    ### Tech Stack
    * **Python 3.10+**
    * **Streamlit** (Frontend UI)
    * **Pillow** (Image Processing)
    * **Cryptography** (AES Encryption)
    """)
