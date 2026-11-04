"""
DCT Steganography Module (Frequency Domain Steganography)
=========================================================
Research Implementation: Phase 3 - Robustness Against Compression & Lossy Channels.

Technical Architecture:
1. Color Space Transformation: RGB -> YCrCb (extracting Luminance channel Y).
2. Block Decomposition: Partitions Luminance channel into 8x8 pixel spatial blocks.
3. Frequency Transformation: Computes 2D Discrete Cosine Transform (cv2.dct) per 8x8 block.
4. Mid-Frequency Modulation: Embeds payload bits into differential mid-frequency pairs.
   - Avoids DC (0, 0) and low-frequency coefficients to prevent perceptible distortion.
   - Avoids high-frequency coefficients to survive high-frequency JPEG quantization discard.
5. Key-Dependent Spatial Permutation: PRNG block sequence derived from SHA-256(Password).
6. Inverse Transformation: Reconstructs spatial domain via Inverse 2D DCT (cv2.idct).
"""

import cv2
import numpy as np
from PIL import Image
import hashlib
import io

# Mid-frequency coefficient coordinate pairs in an 8x8 DCT matrix
# These pairs share balanced quantization table values in JPEG baseline matrices.
MID_COEFF_PAIRS = [
    ((3, 4), (4, 3)),
    ((2, 5), (5, 2)),
    ((1, 5), (5, 1)),
    ((2, 4), (4, 2))
]

# Robustness margin (delta) ensuring coefficients retain differential sign post-quantization
DEFAULT_DELTA = 35.0

# Unique 10-byte sentinel delimiter preventing false-positive collisions with image noise
DCT_SENTINEL = b'##DCT_END##'

def get_dct_prng_seed(password):
    """Derive deterministic 32-bit seed from password SHA-256"""
    pwd_str = str(password) if password else "steganography_pro_dct_default_seed"
    digest = hashlib.sha256(pwd_str.encode('utf-8')).hexdigest()
    return int(digest[:8], 16)

def embed_differential(block_dct, pair, bit, delta=DEFAULT_DELTA):
    """
    Embed a single bit into a pair of mid-frequency DCT coefficients.
    bit = 0 -> enforce (C1 - C2) >= delta
    bit = 1 -> enforce (C2 - C1) >= delta
    """
    (u1, v1), (u2, v2) = pair
    c1 = block_dct[u1, v1]
    c2 = block_dct[u2, v2]
    
    if bit == 0:
        if c1 - c2 < delta:
            avg = (c1 + c2) / 2.0
            c1 = avg + delta / 2.0
            c2 = avg - delta / 2.0
    else:
        if c2 - c1 < delta:
            avg = (c1 + c2) / 2.0
            c1 = avg - delta / 2.0
            c2 = avg + delta / 2.0
            
    block_dct[u1, v1] = c1
    block_dct[u2, v2] = c2

def extract_differential(block_dct, pair):
    """Extract embedded bit by comparing mid-frequency coefficient amplitudes"""
    (u1, v1), (u2, v2) = pair
    return 0 if block_dct[u1, v1] >= block_dct[u2, v2] else 1

def encode_dct(img, message, password=None, delta=DEFAULT_DELTA):
    """
    Embeds message into 8x8 DCT mid-frequency coefficients of carrier image.
    
    Parameters:
        img (PIL.Image): Carrier image (RGB mode)
        message (str): Encrypted payload string
        password (str): Stego-key used to seed PRNG block trajectory
        delta (float): Robustness differential margin
        
    Returns:
        PIL.Image: Stego-image in RGB mode with embedded payload
    """
    # Standardize image to RGB
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    width, height = img.size
    
    # Calculate usable 8x8 blocks (crop dimensions to multiples of 8)
    blocks_w = width // 8
    blocks_h = height // 8
    total_blocks = blocks_w * blocks_h
    
    if total_blocks == 0:
        raise ValueError(f"Image too small ({width}x{height}) for 8x8 DCT decomposition.")
        
    pairs_per_block = len(MID_COEFF_PAIRS)
    max_bits = total_blocks * pairs_per_block
    max_bytes = max_bits // 8
    
    # Format payload with sentinel delimiter ##DCT_END##
    payload_bytes = message.encode('utf-8') + DCT_SENTINEL
    if len(payload_bytes) > max_bytes:
        raise ValueError(
            f"Message size ({len(payload_bytes)} bytes) exceeds DCT carrier capacity ({max_bytes} bytes). "
            f"Consider using a larger image or Spatial PRNG mode."
        )
        
    # Unpack payload bytes to bit array
    bits = np.unpackbits(np.frombuffer(payload_bytes, dtype=np.uint8))
    total_bits = len(bits)
    blocks_needed = (total_bits + pairs_per_block - 1) // pairs_per_block
    
    # Convert image to YCrCb (Luminance Y is robust to compression)
    img_rgb = np.array(img, dtype=np.uint8)
    img_ycrcb = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2YCrCb).astype(np.float32)
    y_channel = img_ycrcb[:, :, 0]
    
    # Generate key-dependent randomized block sequence using PRNG
    seed = get_dct_prng_seed(password)
    rng = np.random.RandomState(seed)
    block_indices = rng.permutation(total_blocks)[:blocks_needed]
    
    bit_idx = 0
    for b_idx in block_indices:
        if bit_idx >= total_bits:
            break
            
        bx = (b_idx % blocks_w) * 8
        by = (b_idx // blocks_w) * 8
        
        # 1. Extract 8x8 spatial block
        block = y_channel[by:by+8, bx:bx+8]
        
        # 2. Forward 2D Discrete Cosine Transform
        dct_block = cv2.dct(block)
        
        # 3. Embed bits in mid-frequency coefficient pairs
        for pair in MID_COEFF_PAIRS:
            if bit_idx < total_bits:
                embed_differential(dct_block, pair, int(bits[bit_idx]), delta)
                bit_idx += 1
            else:
                break
                
        # 4. Inverse 2D Discrete Cosine Transform
        y_channel[by:by+8, bx:bx+8] = cv2.idct(dct_block)
        
    # Reassemble and convert back to RGB
    img_ycrcb[:, :, 0] = np.clip(y_channel, 0, 255)
    stego_rgb = cv2.cvtColor(img_ycrcb.astype(np.uint8), cv2.COLOR_YCrCb2RGB)
    
    return Image.fromarray(stego_rgb)

def decode_dct(img, password=None):
    """
    Extracts embedded payload from 8x8 DCT coefficients along PRNG path.
    
    Parameters:
        img (PIL.Image): Stego-image
        password (str): Stego-key used during encoding
        
    Returns:
        str: Recovered payload string
    """
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    width, height = img.size
    blocks_w = width // 8
    blocks_h = height // 8
    total_blocks = blocks_w * blocks_h
    
    if total_blocks == 0:
        raise ValueError("Image too small for 8x8 DCT decomposition.")
        
    pairs_per_block = len(MID_COEFF_PAIRS)
    
    # Convert image to YCrCb
    img_rgb = np.array(img, dtype=np.uint8)
    img_ycrcb = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2YCrCb).astype(np.float32)
    y_channel = img_ycrcb[:, :, 0]
    
    # Recreate deterministic block sequence from password seed
    seed = get_dct_prng_seed(password)
    rng = np.random.RandomState(seed)
    block_indices = rng.permutation(total_blocks)
    
    extracted_bits = []
    tail_bytes = bytearray()
    found_sentinel = False
    
    for b_idx in block_indices:
        bx = (b_idx % blocks_w) * 8
        by = (b_idx // blocks_w) * 8
        
        block = y_channel[by:by+8, bx:bx+8]
        dct_block = cv2.dct(block)
        
        for pair in MID_COEFF_PAIRS:
            bit = extract_differential(dct_block, pair)
            extracted_bits.append(bit)
            
            # Every 8 bits, check if delimiter ##DCT_END## has been reached
            if len(extracted_bits) % 8 == 0:
                current_byte = 0
                for b in extracted_bits[-8:]:
                    current_byte = (current_byte << 1) | b
                tail_bytes.append(current_byte)
                
                if len(tail_bytes) >= len(DCT_SENTINEL) and tail_bytes[-len(DCT_SENTINEL):] == DCT_SENTINEL:
                    found_sentinel = True
                    break
        if found_sentinel:
            break
            
    if not found_sentinel:
        raise ValueError("No DCT hidden message found (or incorrect password provided).")
        
    payload_bytes = bytes(tail_bytes[:-len(DCT_SENTINEL)])
    try:
        return payload_bytes.decode('utf-8')
    except Exception:
        try:
            return payload_bytes.decode('latin1')
        except Exception:
            raise ValueError("DCT payload corrupted or unreadable.")
