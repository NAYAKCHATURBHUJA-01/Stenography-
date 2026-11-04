# Advanced Image Steganography with Hybrid Encryption

A comprehensive Python application for hiding secret messages within images using advanced steganography techniques combined with multiple encryption algorithms and hashing methods.

## Features

### 🔐 Encryption Methods
- **None**: Plain text embedding (no encryption)
- **AES**: Advanced Encryption Standard with password-based key derivation
- **RSA**: RSA asymmetric encryption with 2048-bit keys
- **Hybrid**: Combines AES and RSA for maximum security (RSA encrypts AES key, AES encrypts message)

### 🔍 Hashing Algorithms
- **SHA-256**: Secure Hash Algorithm 256-bit
- **SHA-512**: Secure Hash Algorithm 512-bit
- **MD5**: Message Digest Algorithm 5
- **SHA-1**: Secure Hash Algorithm 1

### 🖼️ Image Support
- PNG, JPEG, JPG, BMP, GIF, TIFF formats
- LSB (Least Significant Bit) steganography technique
- Automatic image processing and conversion

### 🛠️ Additional Tools
- Hash calculator for text strings
- RSA key pair generator
- Message integrity verification
- User-friendly GUI with tabbed interface

## Installation

1. **Clone or download the project files**
2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Requirements
- Python 3.7 or higher
- See `requirements.txt` for specific package versions

## Usage

### 1. Encoding a Message

1. **Launch the application**:
   ```bash
   python advanced_steganography.py
   ```

2. **Select the Encode tab**

3. **Choose an image**:
   - Click "Select Image" button
   - Choose any supported image format

4. **Enter your secret message**:
   - Type or paste your message in the text area

5. **Configure encryption settings**:
   - Choose encryption method (None, AES, RSA, or Hybrid)
   - Select hash algorithm for integrity verification
   - Enter password if using AES or Hybrid encryption

6. **Generate RSA keys** (if using RSA or Hybrid):
   - Go to Tools tab
   - Click "Generate RSA Key Pair"

7. **Encode the message**:
   - Click "Encode Message"
   - Choose where to save the encoded image

### 2. Decoding a Message

1. **Select the Decode tab**

2. **Choose the encoded image**:
   - Click "Select Encoded Image"
   - Select the image containing hidden data

3. **Enter decryption password** (if applicable):
   - Required for AES or Hybrid encrypted messages

4. **Decode the message**:
   - Click "Decode Message"
   - View the decrypted message with metadata

### 3. Using the Tools Tab

#### Hash Calculator
- Enter text to calculate its hash
- Choose from multiple hash algorithms
- Instant hash calculation and display

#### RSA Key Generator
- Generate 2048-bit RSA key pairs
- Keys are stored in memory for the session
- Required for RSA and Hybrid encryption methods

## Security Features

### Message Integrity
- Each encoded message includes a hash for integrity verification
- Automatic hash validation during decoding
- Tamper detection capabilities

### Encryption Strength
- **AES**: 256-bit key, CBC mode with PKCS7 padding
- **RSA**: 2048-bit keys with OAEP padding
- **Hybrid**: Combines strengths of both algorithms

### Steganography Technique
- LSB (Least Significant Bit) method
- Minimal image quality degradation
- Support for various image formats

## Technical Details

### LSB Steganography Algorithm
1. Converts message to binary representation
2. Embeds message length in first 32 bits
3. Replaces LSBs of image pixels with message bits
4. Preserves image structure and appearance

### Hybrid Encryption Process
1. Generate random AES key (256-bit)
2. Encrypt message with AES (CBC mode)
3. Encrypt AES key with RSA (OAEP padding)
4. Combine: RSA-encrypted key + IV + AES-encrypted message

### Hash Verification
- Calculates hash of encrypted message
- Stores hash with message metadata
- Verifies integrity during decoding

## Error Handling

The application includes comprehensive error handling for:
- Invalid image formats
- Missing encryption keys
- Incorrect passwords
- Corrupted encoded data
- Insufficient image capacity

## Security Considerations

- RSA keys are generated per session (not persisted)
- Passwords are not stored (used only for key derivation)
- Encoded images contain no visible traces of hidden data
- Multiple layers of security for sensitive messages

## Troubleshooting

### Common Issues

1. **"Message too large for the image"**
   - Use a larger image or shorter message
   - Consider compression for long messages

2. **"RSA keys not generated"**
   - Go to Tools tab and generate keys first
   - Keys are session-based only

3. **"Message integrity check failed"**
   - Image may be corrupted or tampered with
   - Try decoding with the original encoded image

4. **"Password required" error**
   - Enter the correct password used during encoding
   - Password is case-sensitive

## File Structure

```
SUPPLY/
├── advanced_steganography.py    # Main application
├── requirements.txt             # Python dependencies
└── README.md                   # This documentation
```

## Dependencies

- **Pillow**: Image processing and manipulation
- **cryptography**: Encryption and cryptographic operations
- **pycryptodome**: Additional cryptographic functions
- **numpy**: Numerical operations for image processing
- **matplotlib**: Image display utilities
- **scikit-image**: Advanced image processing

## License

This project is for educational purposes. Use responsibly and in accordance with applicable laws and regulations.

## Contributing

Feel free to contribute improvements, bug fixes, or new features to enhance the steganography application.

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring compliance with local laws and regulations regarding steganography and encryption technologies.
