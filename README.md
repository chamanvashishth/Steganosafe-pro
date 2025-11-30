# 🔒 SteganoSafe Pro

A secure image steganography tool that hides encrypted messages inside images using **AES Encryption + LSB Steganography**.

---

## ✨ Features
✔ Encrypt your secret message using AES (Fernet)  
✔ Hide encrypted text inside images (PNG/JPG)  
✔ Decode and decrypt secret text from images  
✔ Simple and clean Streamlit interface  

---

## 🧠 How It Works
1. **AES Encryption** turns your message into unreadable data  
2. **LSB Steganography** hides that data inside the image pixels  
3. Anyone without the password sees only a normal image  

---

## 🛠️ Tech Stack
- Python 3
- Streamlit (UI)
- Pillow (Image processing)
- Cryptography (AES encryption)

---

## ▶️ Run the App
```bash
pip install -r requirements.txt
streamlit run app.py
