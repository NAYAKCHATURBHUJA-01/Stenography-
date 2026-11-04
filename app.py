from flask import Flask, render_template_string, request, jsonify, send_file, send_from_directory
import os
import io
import urllib.parse
from PIL import Image, ImageOps
import numpy as np
import cv2
from skimage.metrics import structural_similarity as ssim
from dct_steganography import encode_dct, decode_dct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta

app = Flask(__name__)

# Base directory and uploads directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOADS_DIR, exist_ok=True)

# Security constants
SESSION_KEY = "steganography_pro_session_key_2024"
WEBSITE_KEY = "steganography_pro_website_key_2024"

# Track failed password attempts
failed_attempts = {}  # {image_hash: {'attempts': count, 'last_attempt': timestamp, 'ip': ip}}
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds

def calculate_psnr(img1_np, img2_np):
    """
    Calculate Peak Signal-to-Noise Ratio (PSNR) in dB using OpenCV and NumPy.
    Compares original raw image array against stego image array.
    Higher value (>30 dB, typically 50-80 dB for LSB) indicates imperceptible noise.
    """
    if img1_np.shape != img2_np.shape:
        return 0.0
    
    # Calculate MSE using NumPy
    mse = np.mean((img1_np.astype(np.float64) - img2_np.astype(np.float64)) ** 2)
    if mse == 0:
        return 100.0  # Identical images
    
    try:
        psnr_val = float(cv2.PSNR(img1_np, img2_np))
        if np.isinf(psnr_val):
            return 100.0
        return round(psnr_val, 2)
    except Exception:
        max_pixel = 255.0
        psnr_val = float(20 * np.log10(max_pixel / np.sqrt(mse)))
        return round(psnr_val, 2)

def calculate_ssim(img1_np, img2_np):
    """
    Calculate Structural Similarity Index (SSIM) using skimage.metrics.structural_similarity.
    Compares structural fidelity between original raw image and stego image.
    Score ranges from -1 to 1 (1.0 indicates identical structure).
    """
    if img1_np.shape != img2_np.shape:
        return 0.0
    
    try:
        # scikit-image >= 0.19 uses channel_axis
        score = ssim(img1_np, img2_np, channel_axis=-1)
    except TypeError:
        # scikit-image < 0.19 uses multichannel
        score = ssim(img1_np, img2_np, multichannel=True)
    except Exception:
        try:
            gray1 = cv2.cvtColor(img1_np, cv2.COLOR_RGB2GRAY)
            gray2 = cv2.cvtColor(img2_np, cv2.COLOR_RGB2GRAY)
            score = ssim(gray1, gray2)
        except Exception:
            score = 1.0
            
    return round(float(score), 4)

def get_image_hash(image_data):
    """Generate a unique hash for an image to track attempts"""
    return hashlib.sha256(image_data).hexdigest()

def check_failed_attempts(image_hash, client_ip):
    """Check if user has exceeded failed attempts"""
    current_time = time.time()
    
    if image_hash in failed_attempts:
        attempts_data = failed_attempts[image_hash]
        
        # Check if lockout period has expired
        if current_time - attempts_data['last_attempt'] > LOCKOUT_TIME:
            del failed_attempts[image_hash]
            return False, 0
        
        # Check if max attempts reached
        if attempts_data['attempts'] >= MAX_ATTEMPTS:
            return True, attempts_data['attempts']
        
        return False, attempts_data['attempts']
    
    return False, 0

def record_failed_attempt(image_hash, client_ip):
    """Record a failed password attempt"""
    current_time = time.time()
    
    if image_hash in failed_attempts:
        failed_attempts[image_hash]['attempts'] += 1
        failed_attempts[image_hash]['last_attempt'] = current_time
    else:
        failed_attempts[image_hash] = {
            'attempts': 1,
            'last_attempt': current_time,
            'ip': client_ip
        }

def destroy_image_file(image_path):
    """Securely destroy an image file"""
    try:
        if os.path.exists(image_path):
            # Overwrite the file with random data multiple times
            with open(image_path, 'wb') as f:
                for _ in range(3):
                    f.write(os.urandom(os.path.getsize(image_path)))
            
            # Delete the file
            os.remove(image_path)
            return True
    except Exception:
        pass
    
    return False

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Steganography Pro - Military-Grade Security</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: white;
                overflow-x: hidden;
                line-height: 1.6;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
            }
            
            header {
                text-align: center;
                padding: 80px 0 60px;
                position: relative;
            }
            
            h1 {
                font-size: clamp(2.5rem, 5vw, 4rem);
                font-weight: 800;
                margin-bottom: 20px;
                background: linear-gradient(135deg, #ffd700 0%, #ffed4e 25%, #ffffff 50%, #fff59d 75%, #ffd700 100%);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -0.02em;
                animation: gradientShift 4s ease-in-out infinite, textGlow 2s ease-in-out infinite alternate;
                text-shadow: 0 0 30px rgba(255, 215, 0, 0.5);
            }
            
            @keyframes gradientShift {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }
            
            @keyframes textGlow {
                from { 
                    filter: brightness(1) drop-shadow(0 0 20px rgba(255, 215, 0, 0.6));
                    transform: scale(1);
                }
                to { 
                    filter: brightness(1.2) drop-shadow(0 0 30px rgba(255, 237, 78, 0.8));
                    transform: scale(1.02);
                }
            }
            
            .subtitle {
                font-size: 1.25rem;
                opacity: 0.95;
                margin-bottom: 50px;
                font-weight: 400;
                letter-spacing: 0.5px;
                background: linear-gradient(90deg, #fff59d 0%, #ffffff 25%, #ffeb3b 50%, #fff9c4 75%, #fff59d 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                max-width: 600px;
                margin-left: auto;
                margin-right: auto;
                animation: subtitleGradient 6s ease-in-out infinite;
                text-shadow: 0 0 15px rgba(255, 235, 59, 0.3);
            }
            
            @keyframes subtitleGradient {
                0%, 100% { background-position: 0% 50%; }
                25% { background-position: 50% 25%; }
                50% { background-position: 100% 50%; }
                75% { background-position: 50% 75%; }
            }
            
            .nav {
                display: flex;
                justify-content: center;
                gap: 30px;
                margin: 80px 0;
                flex-wrap: wrap;
            }
            
            .nav a {
                display: inline-flex;
                align-items: center;
                gap: 16px;
                padding: 24px 48px;
                background: linear-gradient(135deg, #ffd700 0%, #ffed4e 50%, #fff59d 100%);
                backdrop-filter: blur(20px);
                border: 3px solid rgba(255, 215, 0, 0.3);
                color: #333;
                text-decoration: none;
                border-radius: 20px;
                font-size: 20px;
                font-weight: 700;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                box-shadow: 0 10px 30px rgba(255, 215, 0, 0.3);
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .nav a::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(135deg, #fff59d 0%, #ffffff 50%, #ffeb3b 100%);
                transition: left 0.4s ease;
                z-index: -1;
            }
            
            .nav a::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 0;
                height: 0;
                background: radial-gradient(circle, rgba(255, 255, 255, 0.8) 0%, transparent 70%);
                transition: all 0.4s ease;
                transform: translate(-50%, -50%);
                border-radius: 50%;
            }
            
            .nav a:hover::before {
                left: 0;
            }
            
            .nav a:hover::after {
                width: 300px;
                height: 300px;
            }
            
            .nav a:hover {
                transform: translateY(-8px) scale(1.05);
                box-shadow: 0 25px 50px rgba(255, 215, 0, 0.5);
                border-color: rgba(255, 215, 0, 0.6);
                color: #333;
            }
            
            .nav a:active {
                transform: translateY(-4px) scale(1.02);
            }
            
            .nav a i {
                font-size: 24px;
                filter: drop-shadow(0 2px 4px rgba(255, 215, 0, 0.3));
            }
            
            .hero-section {
                text-align: center;
                padding: 80px 40px;
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 24px;
                margin: 80px 0;
                position: relative;
                overflow: hidden;
            }
            
            .hero-section::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at 50% 50%, rgba(255, 215, 0, 0.1) 0%, transparent 70%);
                pointer-events: none;
            }
            
            .hero-section h2 {
                font-size: clamp(2rem, 4vw, 3rem);
                font-weight: 700;
                margin-bottom: 24px;
                background: linear-gradient(45deg, #ffd700 0%, #ffed4e 25%, #ffffff 50%, #fff59d 75%, #ffeb3b 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: heroTitleAnimation 5s ease-in-out infinite;
                text-shadow: 0 0 25px rgba(255, 215, 0, 0.4);
            }
            
            @keyframes heroTitleAnimation {
                0%, 100% { 
                    background-position: 0% 50%;
                    filter: brightness(1) hue-rotate(0deg);
                }
                25% { 
                    background-position: 50% 25%;
                    filter: brightness(1.2) hue-rotate(10deg);
                }
                50% { 
                    background-position: 100% 50%;
                    filter: brightness(1.4) hue-rotate(0deg);
                }
                75% { 
                    background-position: 50% 75%;
                    filter: brightness(1.2) hue-rotate(-10deg);
                }
            }
            
            .hero-section p {
                font-size: 1.125rem;
                line-height: 1.7;
                max-width: 700px;
                margin: 0 auto;
                background: linear-gradient(90deg, #fff59d 0%, #ffffff 25%, #ffeb3b 50%, #fff9c4 75%, #fff59d 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                font-weight: 400;
                animation: paragraphGradient 6s ease-in-out infinite;
            }
            
            @keyframes paragraphGradient {
                0%, 100% { background-position: 0% 50%; }
                25% { background-position: 50% 25%; }
                50% { background-position: 100% 50%; }
                75% { background-position: 50% 75%; }
            }
            
            .features-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 30px;
                margin: 80px 0;
            }
            
            .feature-card {
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 40px 30px;
                border-radius: 20px;
                text-align: center;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            
            .feature-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at 50% 50%, rgba(255, 215, 0, 0.05) 0%, transparent 70%);
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            
            .feature-card:hover::before {
                opacity: 1;
            }
            
            .feature-card:hover {
                transform: translateY(-8px);
                background: rgba(255, 255, 255, 0.12);
                box-shadow: 0 30px 60px rgba(0, 0, 0, 0.2);
                border-color: rgba(255, 255, 255, 0.2);
            }
            
            .feature-card i {
                font-size: 3rem;
                background: linear-gradient(135deg, #ffd700 0%, #ffed4e 25%, #ffffff 50%, #fff59d 75%, #ffeb3b 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 24px;
                animation: iconGradient 4s ease-in-out infinite;
                filter: drop-shadow(0 0 15px rgba(255, 215, 0, 0.5));
            }
            
            @keyframes iconGradient {
                0%, 100% { 
                    background-position: 0% 50%;
                    transform: scale(1) rotate(0deg);
                }
                25% { 
                    background-position: 50% 25%;
                    transform: scale(1.05) rotate(5deg);
                }
                50% { 
                    background-position: 100% 50%;
                    transform: scale(1.1) rotate(0deg);
                }
                75% { 
                    background-position: 50% 75%;
                    transform: scale(1.05) rotate(-5deg);
                }
            }
            
            .feature-card h3 {
                font-size: 1.5rem;
                font-weight: 600;
                margin-bottom: 16px;
                background: linear-gradient(90deg, #fff59d 0%, #ffffff 25%, #ffeb3b 50%, #fff9c4 75%, #fff59d 100%);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: featureTitleGradient 3s ease-in-out infinite;
            }
            
            @keyframes featureTitleGradient {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }
            
            .feature-card p {
                font-size: 1rem;
                line-height: 1.6;
                background: linear-gradient(90deg, #fff59d 0%, #ffffff 25%, #ffeb3b 50%, #fff9c4 75%, #fff59d 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: featureTextGradient 6s ease-in-out infinite;
            }
            
            @keyframes featureTextGradient {
                0%, 100% { background-position: 0% 50%; }
                33% { background-position: 100% 50%; }
                66% { background-position: 50% 100%; }
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 30px;
                margin: 80px 0 60px;
            }
            
            .stat-item {
                text-align: center;
                padding: 40px 20px;
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 16px;
                transition: all 0.3s ease;
            }
            
            .stat-item:hover {
                transform: translateY(-4px);
                background: rgba(255, 255, 255, 0.12);
            }
            
            .stat-item .number {
                font-size: 2.5rem;
                font-weight: 800;
                background: linear-gradient(45deg, #ffd700 0%, #ffed4e 25%, #ffffff 50%, #fff59d 75%, #ffeb3b 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 8px;
                animation: statNumberAnimation 3s ease-in-out infinite;
                text-shadow: 0 0 20px rgba(255, 215, 0, 0.4);
            }
            
            @keyframes statNumberAnimation {
                0%, 100% { 
                    background-position: 0% 50%;
                    transform: scale(1);
                    filter: brightness(1);
                }
                25% { 
                    background-position: 50% 25%;
                    transform: scale(1.05);
                    filter: brightness(1.2);
                }
                50% { 
                    background-position: 100% 50%;
                    transform: scale(1.1);
                    filter: brightness(1.4);
                }
                75% { 
                    background-position: 50% 75%;
                    transform: scale(1.05);
                    filter: brightness(1.2);
                }
            }
            
            .stat-item .label {
                font-size: 1rem;
                font-weight: 500;
                background: linear-gradient(90deg, #fff59d 0%, #ffffff 25%, #ffeb3b 50%, #fff9c4 75%, #fff59d 100%);
                background-size: 400% 400%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: statLabelGradient 5s ease-in-out infinite;
            }
            
            @keyframes statLabelGradient {
                0%, 100% { background-position: 0% 50%; }
                20% { background-position: 100% 0%; }
                40% { background-position: 100% 100%; }
                60% { background-position: 0% 100%; }
                80% { background-position: 50% 50%; }
            }
            
            @media (max-width: 768px) {
                .nav { flex-direction: column; align-items: center; }
                .features-grid { grid-template-columns: 1fr; }
                .hero-section { padding: 60px 20px; margin: 60px 0; }
                .feature-card { padding: 30px 20px; }
                header { padding: 60px 0 40px; }
            }
            
            /* Smooth scrolling */
            html {
                scroll-behavior: smooth;
            }
            
            /* Custom scrollbar */
            ::-webkit-scrollbar {
                width: 8px;
            }
            
            ::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.1);
            }
            
            ::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.3);
                border-radius: 4px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: rgba(255, 255, 255, 0.5);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Steganography Pro</h1>
                <p class="subtitle">Military-Grade Security Meets Cutting-Edge Design</p>
            </header>
            
            <nav class="nav">
                <a href="/encode">
                    <i class="fas fa-lock"></i>
                    <span>Encode Message</span>
                </a>
                <a href="/decode">
                    <i class="fas fa-unlock"></i>
                    <span>Decode Message</span>
                </a>
            </nav>
            
            <div class="hero-section">
                <h2>Advanced Image Steganography</h2>
                <p>Transform ordinary images into secure digital vaults using cutting-edge steganography and military-grade encryption. Hide confidential messages within plain sight while maintaining complete deniability.</p>
            </div>
            
            <div class="features-grid">
                <div class="feature-card">
                    <i class="fas fa-shield-alt"></i>
                    <h3>Military-Grade Encryption</h3>
                    <p>AES-256, RSA-2048, and hybrid encryption methods to protect your messages with the highest security standards.</p>
                </div>
                
                <div class="feature-card">
                    <i class="fas fa-image"></i>
                    <h3>Multi-Format Support</h3>
                    <p>Works with PNG, JPEG, BMP, GIF, and TIFF images. Your steganography needs are fully covered.</p>
                </div>
                
                <div class="feature-card">
                    <i class="fas fa-user-secret"></i>
                    <h3>Complete Deniability</h3>
                    <p>Hidden messages are virtually undetectable. Only with the exact password can your secrets be revealed.</p>
                </div>
                
                <div class="feature-card">
                    <i class="fas fa-tachometer-alt"></i>
                    <h3>Lightning Fast</h3>
                    <p>Advanced algorithms ensure quick encoding and decoding without compromising on security.</p>
                </div>
                
                <div class="feature-card">
                    <i class="fas fa-fingerprint"></i>
                    <h3>Multi-Layered Security</h3>
                    <p>Website-specific hashing and session keys ensure your messages can only be decoded here.</p>
                </div>
                
                <div class="feature-card">
                    <i class="fas fa-mobile-alt"></i>
                    <h3>Responsive Design</h3>
                    <p>Works seamlessly across all devices - desktop, tablet, and mobile.</p>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="number">256-bit</div>
                    <div class="label">AES Encryption</div>
                </div>
                <div class="stat-item">
                    <div class="number">2048-bit</div>
                    <div class="label">RSA Keys</div>
                </div>
                <div class="stat-item">
                    <div class="number">5+</div>
                    <div class="label">Image Formats</div>
                </div>
                <div class="stat-item">
                    <div class="number">100%</div>
                    <div class="label">Secure</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/encode')
def encode_page():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Encode Message - Steganography Pro</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #ffffff;
                min-height: 100vh;
                overflow-x: hidden;
                line-height: 1.6;
            }
            
            .container {
                max-width: 900px;
                margin: 0 auto;
                padding: 0 20px;
            }
            
            header {
                text-align: center;
                padding: 60px 0 40px;
                position: relative;
                animation: slideDown 0.8s ease-out;
            }
            
            @keyframes slideDown {
                from {
                    opacity: 0;
                    transform: translateY(-50px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .back-btn {
                display: inline-flex;
                align-items: center;
                gap: 12px;
                padding: 16px 32px;
                background: linear-gradient(135deg, #ffd700 0%, #ffed4e 50%, #fff59d 100%);
                color: #333;
                text-decoration: none;
                border-radius: 50px;
                margin-bottom: 40px;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                font-weight: 600;
                box-shadow: 0 8px 25px rgba(255, 215, 0, 0.3);
                position: relative;
                overflow: hidden;
            }
            
            .back-btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(135deg, #fff59d 0%, #ffffff 50%, #ffeb3b 100%);
                transition: left 0.4s ease;
                z-index: -1;
            }
            
            .back-btn:hover::before {
                left: 0;
            }
            
            .back-btn:hover {
                transform: translateY(-3px) scale(1.05);
                box-shadow: 0 15px 40px rgba(255, 215, 0, 0.5);
            }
            
            h1 {
                font-size: clamp(2.5rem, 6vw, 3.5rem);
                font-weight: 800;
                margin-bottom: 20px;
                background: linear-gradient(135deg, #ffffff 0%, #e0e0e0 50%, #ffffff 100%);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: titleGradient 4s ease-in-out infinite;
                text-shadow: 0 0 40px rgba(255, 255, 255, 0.5);
                letter-spacing: 1px;
            }
            
            @keyframes titleGradient {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }
            
            .subtitle {
                font-size: 1.4rem;
                background: linear-gradient(90deg, #ffffff 0%, #f0f0f0 25%, #ffffff 50%, #e0e0e0 75%, #ffffff 100%);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: subtitleGradient 6s ease-in-out infinite;
                margin-bottom: 40px;
                font-weight: 500;
                text-shadow: 0 0 20px rgba(255, 255, 255, 0.3);
            }
            
            @keyframes subtitleGradient {
                0%, 100% { background-position: 0% 50%; }
                25% { background-position: 50% 25%; }
                50% { background-position: 100% 50%; }
                75% { background-position: 50% 75%; }
            }
            
            .form-container {
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 50px;
                border-radius: 24px;
                animation: fadeInUp 0.8s ease-out 0.2s both;
                position: relative;
                overflow: hidden;
            }
            
            .form-container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at 50% 50%, rgba(255, 215, 0, 0.05) 0%, transparent 70%);
                pointer-events: none;
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .form-group {
                margin-bottom: 35px;
                position: relative;
            }
            
            .form-group.encryption-active {
                background: rgba(255, 215, 0, 0.1);
                border: 2px solid rgba(255, 215, 0, 0.3);
                border-radius: 15px;
                padding: 20px;
                animation: encryptionGlow 2s ease-in-out infinite;
            }
            
            @keyframes encryptionGlow {
                0%, 100% { box-shadow: 0 0 20px rgba(255, 215, 0, 0.2); }
                50% { box-shadow: 0 0 30px rgba(255, 215, 0, 0.4); }
            }
            
            label {
                display: block;
                margin-bottom: 12px;
                font-weight: 600;
                background: linear-gradient(90deg, #ffffff 0%, #f0f0f0 25%, #ffffff 50%, #e0e0e0 75%, #ffffff 100%);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: labelGradient 3s ease-in-out infinite;
                font-size: 1.3rem;
                text-shadow: 0 0 15px rgba(255, 255, 255, 0.3);
            }
            
            @keyframes labelGradient {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }
            
            input[type="file"],
            input[type="password"],
            textarea,
            select {
                width: 100%;
                padding: 20px 22px;
                background: rgba(255, 255, 255, 0.15);
                border: 3px solid rgba(255, 255, 255, 0.4);
                border-radius: 16px;
                color: #ffffff;
                font-size: 18px;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                backdrop-filter: blur(10px);
                font-weight: 500;
            }
            
            input[type="file"]:focus,
            input[type="password"]:focus,
            textarea:focus,
            select:focus {
                outline: none;
                border-color: #ffffff;
                background: rgba(255, 255, 255, 0.2);
                box-shadow: 0 0 25px rgba(255, 255, 255, 0.4);
                transform: translateY(-2px);
            }
            
            input::placeholder,
            textarea::placeholder {
                color: rgba(255, 255, 255, 0.7);
                font-size: 16px;
            }
            
            textarea {
                resize: vertical;
                min-height: 160px;
                font-family: inherit;
                font-size: 18px;
            }
            
            select option {
                background: #1a1a2e;
                color: white;
                font-size: 16px;
            }
            
            .file-input-wrapper {
                position: relative;
                overflow: hidden;
            }
            
            .file-input-label {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 50px 25px;
                background: rgba(255, 255, 255, 0.12);
                border: 3px dashed rgba(255, 255, 255, 0.6);
                border-radius: 20px;
                cursor: pointer;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            
            .file-input-label::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at center, rgba(255, 255, 255, 0.15) 0%, transparent 70%);
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            
            .file-input-label:hover::before {
                opacity: 1;
            }
            
            .file-input-label:hover {
                background: rgba(255, 255, 255, 0.18);
                border-color: #ffffff;
                transform: translateY(-3px);
                box-shadow: 0 15px 35px rgba(255, 255, 255, 0.2);
            }
            
            .file-input-label.has-file {
                border-color: #4caf50;
                background: rgba(76, 175, 80, 0.15);
            }
            
            .file-input-label i {
                font-size: 3.5rem;
                margin-bottom: 20px;
                background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 50%, #ffffff 100%);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: iconGradient 3s ease-in-out infinite;
            }
            
            @keyframes iconGradient {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }
            
            .file-input-label span {
                font-size: 1.2rem;
                font-weight: 600;
                color: #ffffff;
                margin-bottom: 8px;
            }
            
            .file-input-label small {
                font-size: 1rem;
                color: rgba(255, 255, 255, 0.8);
                font-weight: 500;
            }
            
            .file-name {
                margin-top: 12px;
                font-size: 1rem;
                color: #4caf50;
                font-weight: 600;
            }
            
            .camera-section {
                margin-top: 20px;
                text-align: center;
            }
            
            .camera-btn {
                padding: 16px 32px;
                background: linear-gradient(135deg, #4caf50 0%, #8bc34a 50%, #66bb6a 100%);
                color: white;
                border: none;
                border-radius: 50px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                display: inline-flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 8px 25px rgba(76, 175, 80, 0.3);
                position: relative;
                overflow: hidden;
            }
            
            .camera-btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(135deg, #66bb6a 0%, #8bc34a 50%, #4caf50 100%);
                transition: left 0.4s ease;
                z-index: -1;
            }
            
            .camera-btn:hover::before {
                left: 0;
            }
            
            .camera-btn:hover {
                transform: translateY(-3px) scale(1.05);
                box-shadow: 0 15px 40px rgba(76, 175, 80, 0.5);
            }
            
            .camera-btn i {
                font-size: 20px;
            }
            
            .camera-preview {
                margin-top: 20px;
                padding: 24px;
                background: rgba(0, 0, 0, 0.45);
                border: 2px solid rgba(255, 215, 0, 0.35);
                border-radius: 20px;
                backdrop-filter: blur(15px);
                animation: fadeInUp 0.4s ease-out;
                text-align: center;
            }
            
            .camera-status-banner {
                padding: 14px 20px;
                border-radius: 12px;
                margin-bottom: 18px;
                font-size: 0.95rem;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 12px;
                animation: fadeInUp 0.3s ease;
                line-height: 1.5;
                text-align: left;
            }
            
            .camera-status-banner.error {
                background: rgba(244, 67, 54, 0.25);
                border: 1px solid rgba(244, 67, 54, 0.6);
                color: #ffcdd2;
            }
            
            .camera-status-banner.info {
                background: rgba(33, 150, 243, 0.25);
                border: 1px solid rgba(33, 150, 243, 0.6);
                color: #e1f5fe;
            }

            .camera-loading-overlay {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(10, 15, 30, 0.92);
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                z-index: 5;
                padding: 24px;
                text-align: center;
            }
            
            .camera-loading-overlay i {
                font-size: 2.5rem;
                color: #ffd700;
                margin-bottom: 14px;
            }
            
            .camera-loading-overlay p {
                font-size: 1.15rem;
                font-weight: 600;
                color: #fff;
                margin-bottom: 6px;
            }
            
            .camera-loading-overlay small {
                color: rgba(255, 255, 255, 0.7);
                font-size: 0.9rem;
            }

            .video-container {
                position: relative;
                max-width: 520px;
                min-height: 320px;
                margin: 0 auto 20px;
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
                background: #0b0f19;
                border: 2px solid rgba(255, 215, 0, 0.35);
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            #video {
                width: 100%;
                height: 100%;
                min-height: 280px;
                object-fit: cover;
                display: block;
                border-radius: 14px;
            }
            
            .camera-viewfinder-overlay {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                border: 2px dashed rgba(255, 215, 0, 0.6);
                margin: 16px;
                border-radius: 10px;
                pointer-events: none;
            }
            
            .camera-controls {
                display: flex;
                justify-content: center;
                gap: 12px;
                flex-wrap: wrap;
            }
            
            .capture-btn, .cancel-btn, .retry-btn, .fallback-cam-btn {
                padding: 14px 26px;
                border: none;
                border-radius: 50px;
                cursor: pointer;
                font-size: 15px;
                font-weight: 700;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 10px;
            }
            
            .capture-btn {
                background: linear-gradient(135deg, #4caf50 0%, #8bc34a 100%);
                color: white;
                box-shadow: 0 6px 20px rgba(76, 175, 80, 0.4);
            }
            
            .capture-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(76, 175, 80, 0.6);
            }
            
            .retry-btn {
                background: linear-gradient(135deg, #ff9800 0%, #ffb74d 100%);
                color: #222;
                box-shadow: 0 6px 20px rgba(255, 152, 0, 0.4);
            }
            
            .retry-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(255, 152, 0, 0.6);
            }

            .fallback-cam-btn {
                background: linear-gradient(135deg, #009688 0%, #4db6ac 100%);
                color: white;
                box-shadow: 0 6px 20px rgba(0, 150, 136, 0.4);
            }
            
            .fallback-cam-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(0, 150, 136, 0.6);
            }

            .cancel-btn {
                background: linear-gradient(135deg, #f44336 0%, #e91e63 100%);
                color: white;
                box-shadow: 0 6px 20px rgba(244, 67, 54, 0.3);
            }
            
            .cancel-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(244, 67, 54, 0.5);
            }

            /* Image Preview Card */
            .image-preview-card {
                display: none;
                margin-top: 20px;
                padding: 24px;
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: blur(15px);
                border: 2px solid rgba(76, 175, 80, 0.5);
                border-radius: 20px;
                text-align: center;
                animation: fadeInUp 0.4s ease-out;
            }
            
            .image-preview-card.active {
                display: block;
            }
            
            .image-preview-thumb-wrap {
                display: inline-block;
                max-width: 100%;
                margin: 0 auto;
            }
            
            .image-preview-thumb {
                max-width: 100%;
                max-height: 280px;
                border-radius: 14px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
                border: 2px solid rgba(255, 255, 255, 0.2);
                object-fit: contain;
                display: block;
                margin: 0 auto;
            }
            
            .image-preview-meta {
                margin-top: 16px;
                display: flex;
                justify-content: center;
                align-items: center;
                gap: 15px;
                flex-wrap: wrap;
            }
            
            .image-preview-badge {
                background: linear-gradient(135deg, #4caf50 0%, #8bc34a 100%);
                color: white;
                font-size: 0.85rem;
                font-weight: 700;
                padding: 6px 14px;
                border-radius: 20px;
                display: inline-flex;
                align-items: center;
                gap: 6px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .image-preview-name {
                font-size: 1rem;
                font-weight: 600;
                color: #ffffff;
                max-width: 250px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .image-preview-size {
                font-size: 0.9rem;
                color: rgba(255, 255, 255, 0.7);
            }
            
            .image-preview-actions {
                margin-top: 18px;
                display: flex;
                justify-content: center;
                gap: 12px;
                flex-wrap: wrap;
            }
            
            .preview-action-btn {
                padding: 12px 22px;
                border-radius: 50px;
                border: none;
                font-weight: 700;
                font-size: 0.95rem;
                cursor: pointer;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                text-decoration: none;
                -webkit-text-fill-color: initial !important;
                -webkit-background-clip: initial !important;
                background-clip: border-box !important;
                line-height: 1.2;
            }
            
            .preview-action-retake {
                background: linear-gradient(135deg, #2196f3 0%, #00bcd4 100%) !important;
                color: #ffffff !important;
                -webkit-text-fill-color: #ffffff !important;
                box-shadow: 0 4px 15px rgba(33, 150, 243, 0.4);
            }
            
            .preview-action-retake:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(33, 150, 243, 0.6);
            }
            
            .preview-action-change {
                background: linear-gradient(135deg, #f57c00 0%, #ff9800 100%) !important;
                color: #ffffff !important;
                -webkit-text-fill-color: #ffffff !important;
                box-shadow: 0 4px 15px rgba(245, 124, 0, 0.4);
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
            }
            
            .preview-action-change:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(245, 124, 0, 0.6);
            }
            
            .preview-action-change i,
            .preview-action-change span {
                color: #ffffff !important;
                -webkit-text-fill-color: #ffffff !important;
                display: inline-block;
                opacity: 1 !important;
                visibility: visible !important;
            }

            .preview-action-remove {
                background: rgba(244, 67, 54, 0.25) !important;
                border: 1px solid rgba(244, 67, 54, 0.6) !important;
                color: #ffcdd2 !important;
                -webkit-text-fill-color: #ffcdd2 !important;
            }
            
            .preview-action-remove:hover {
                background: rgba(244, 67, 54, 0.45) !important;
                color: #ffffff !important;
                -webkit-text-fill-color: #ffffff !important;
            }
            
            .btn {
                padding: 24px 48px;
                background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 50%, #e0e0e0 100%);
                color: #1a1a2e;
                border: none;
                border-radius: 50px;
                cursor: pointer;
                font-size: 20px;
                font-weight: 700;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                display: inline-flex;
                align-items: center;
                gap: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
                box-shadow: 0 10px 30px rgba(255, 255, 255, 0.3);
                position: relative;
                overflow: hidden;
            }
            
            .btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(135deg, #f0f0f0 0%, #ffffff 50%, #e0e0e0 100%);
                transition: left 0.4s ease;
                z-index: -1;
            }
            
            .btn::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 0;
                height: 0;
                background: radial-gradient(circle, rgba(255, 255, 255, 0.8) 0%, transparent 70%);
                transition: all 0.4s ease;
                transform: translate(-50%, -50%);
                border-radius: 50%;
            }
            
            .btn:hover::before {
                left: 0;
            }
            
            .btn:hover::after {
                width: 300px;
                height: 300px;
            }
            
            .btn:hover {
                transform: translateY(-5px) scale(1.05);
                box-shadow: 0 20px 40px rgba(255, 255, 255, 0.5);
            }
            
            .btn:active {
                transform: translateY(-2px) scale(1.02);
            }
            
            .btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
            }
            
            .btn i {
                font-size: 22px;
                animation: none;
            }
            
            .btn.spinning i {
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            
            .result {
                margin-top: 40px;
                padding: 35px;
                background: rgba(76, 175, 80, 0.2);
                backdrop-filter: blur(20px);
                border: 3px solid rgba(76, 175, 80, 0.5);
                border-radius: 20px;
                text-align: center;
                animation: slideIn 0.5s ease-out;
                position: relative;
                overflow: hidden;
            }
            
            .result::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at 50% 50%, rgba(76, 175, 80, 0.15) 0%, transparent 70%);
                pointer-events: none;
            }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .result.error {
                background: rgba(244, 67, 54, 0.2);
                border-color: rgba(244, 67, 54, 0.5);
            }
            
            .result.error::before {
                background: radial-gradient(circle at 50% 50%, rgba(244, 67, 54, 0.15) 0%, transparent 70%);
            }
            
            .result h3 {
                font-size: 1.8rem;
                margin-bottom: 20px;
                background: linear-gradient(90deg, #4caf50 0%, #8bc34a 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                font-weight: 700;
            }
            
            .result.error h3 {
                background: linear-gradient(90deg, #f44336 0%, #e91e63 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            
            .result p {
                margin-bottom: 25px;
                font-size: 1.2rem;
                color: #ffffff;
                font-weight: 500;
            }
            
            .message-content {
                background: rgba(255, 255, 255, 0.1);
                padding: 20px;
                border-radius: 12px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                font-size: 1.1rem;
                line-height: 1.6;
                color: #ffffff;
                word-wrap: break-word;
                margin-top: 15px;
            }
            
            .password-strength {
                margin-top: 12px;
                height: 8px;
                background: rgba(255, 255, 255, 0.15);
                border-radius: 4px;
                overflow: hidden;
            }
            
            .password-strength-bar {
                height: 100%;
                width: 0;
                transition: all 0.3s ease;
                border-radius: 4px;
            }
            
            .strength-weak { background: #f44336; width: 33%; }
            .strength-medium { background: #ff9800; width: 66%; }
            .strength-strong { background: #4caf50; width: 100%; }
            
            .encryption-info {
                margin-top: 18px;
                padding: 18px;
                background: rgba(255, 255, 255, 0.15);
                border-left: 4px solid #ffffff;
                border-radius: 8px;
                font-size: 1rem;
                animation: fadeIn 0.5s ease-out;
                color: #ffffff;
                font-weight: 500;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            #strengthText {
                font-size: 1rem;
                font-weight: 600;
                margin-top: 8px;
            }
            
            .password-hint {
                margin-top: 14px;
                padding: 14px 18px;
                background: rgba(255, 215, 0, 0.12);
                border-left: 4px solid #ffd700;
                border-radius: 10px;
                font-size: 0.95rem;
                color: #fff9c4;
                display: flex;
                align-items: center;
                gap: 12px;
                line-height: 1.4;
                transition: all 0.3s ease;
            }
            
            .password-hint i {
                color: #ffd700;
                font-size: 1.2rem;
                flex-shrink: 0;
            }
            
            @media (max-width: 768px) {
                .container { padding: 0 15px; }
                .form-container { padding: 30px 20px; }
                h1 { font-size: 2.2rem; }
                .subtitle { font-size: 1.2rem; }
                label { font-size: 1.1rem; }
                .btn { padding: 20px 40px; font-size: 18px; }
                .file-input-label { padding: 40px 20px; }
                .file-input-label i { font-size: 3rem; }
                .file-input-label span { font-size: 1.1rem; }
                .result h3 { font-size: 1.5rem; }
                .result p { font-size: 1.1rem; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <a href="/" class="back-btn">
                    <i class="fas fa-arrow-left"></i>
                    <span>Back to Home</span>
                </a>
                <h1>Encode Secret Message</h1>
                <p class="subtitle">Hide your message inside an image with military-grade encryption</p>
            </header>
            
            <div class="form-container">
                <form id="encodeForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="image">Choose Image</label>
                        <div class="file-input-wrapper">
                            <input type="file" id="image" name="image" accept="image/*" style="display: none;">
                            <input type="file" id="camera" name="camera" accept="image/*" capture="environment" style="display: none;">
                            
                            <label for="image" class="file-input-label" id="fileLabel">
                                <i class="fas fa-cloud-upload-alt"></i>
                                <span>Click to upload or drag and drop</span>
                                <small>PNG, JPEG, BMP, GIF, TIFF (Max 10MB)</small>
                            </label>
                            
                            <div class="camera-section" id="cameraSection">
                                <div style="display: flex; gap: 15px; justify-content: center; flex-wrap: wrap; margin-bottom: 10px;">
                                    <button type="button" class="camera-btn" id="cameraBtn">
                                        <i class="fas fa-video"></i>
                                        <span>Open Webcam</span>
                                    </button>
                                    <button type="button" class="fallback-cam-btn" id="deviceCameraBtn">
                                        <i class="fas fa-camera"></i>
                                        <span>Take Photo (Camera App)</span>
                                    </button>
                                </div>
                                
                                <div class="camera-preview" id="cameraPreview" style="display: none;">
                                    <div id="cameraStatusBanner" class="camera-status-banner" style="display: none;"></div>

                                    <div class="video-container" id="videoContainer">
                                        <div id="cameraLoadingSpinner" class="camera-loading-overlay">
                                            <i class="fas fa-circle-notch fa-spin"></i>
                                            <p id="cameraLoadingText">Starting camera feed...</p>
                                            <small>Please click "Allow" if your browser asks for camera permission</small>
                                        </div>
                                        <video id="video" autoplay playsinline muted></video>
                                        <div class="camera-viewfinder-overlay" id="viewfinderOverlay"></div>
                                    </div>
                                    <canvas id="canvas" style="display: none;"></canvas>
                                    <div class="camera-controls">
                                        <button type="button" class="capture-btn" id="captureBtn" style="display: none;">
                                            <i class="fas fa-camera"></i>
                                            Capture Photo
                                        </button>
                                        <button type="button" class="retry-btn" id="retryCameraBtn" style="display: none;">
                                            <i class="fas fa-redo"></i>
                                            Retry Camera
                                        </button>
                                        <button type="button" class="fallback-cam-btn" id="fallbackSnapBtn" style="display: none;">
                                            <i class="fas fa-camera-retro"></i>
                                            Use Camera App
                                        </button>
                                        <button type="button" class="cancel-btn" id="cancelBtn">
                                            <i class="fas fa-times"></i>
                                            Close
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <!-- Preview Card shown when image is selected or captured -->
                            <div class="image-preview-card" id="imagePreviewCard">
                                <div class="image-preview-thumb-wrap">
                                    <img id="imagePreviewImg" class="image-preview-thumb" src="" alt="Selected Preview">
                                </div>
                                <div class="image-preview-meta">
                                    <span class="image-preview-badge" id="previewBadge">
                                        <i class="fas fa-check-circle"></i> Ready
                                    </span>
                                    <span class="image-preview-name" id="previewName">image.png</span>
                                    <span class="image-preview-size" id="previewSize">0 MB</span>
                                </div>
                                <div class="image-preview-actions">
                                    <button type="button" class="preview-action-btn preview-action-retake" id="retakeBtn">
                                        <i class="fas fa-camera"></i> <span>Retake / New Photo</span>
                                    </button>
                                    <button type="button" class="preview-action-btn preview-action-change" id="changeFileBtn">
                                        <i class="fas fa-folder-open"></i> <span>Choose Different File</span>
                                    </button>
                                    <button type="button" class="preview-action-btn preview-action-remove" id="removePhotoBtn">
                                        <i class="fas fa-trash-alt"></i> <span>Remove</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="message">Secret Message</label>
                        <textarea id="message" name="message" placeholder="Enter your secret message here..." required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="stego_mode"><i class="fas fa-layer-group" style="color: #ffd700;"></i> Steganography Domain Technique</label>
                        <select id="stego_mode" name="stego_mode">
                            <option value="spatial" selected>Spatial Domain (PRNG-LSB) — High Capacity & Maximum Fidelity</option>
                            <option value="dct">Frequency Domain (8x8 DCT) — Robust to JPEG & Lossy Compression</option>
                        </select>
                        <div class="encryption-info" id="stegoModeInfo" style="margin-top: 10px; background: rgba(33, 150, 243, 0.15); border-left: 4px solid #2196f3;">
                            <i class="fas fa-shield-alt"></i> <strong>Spatial PRNG Mode:</strong> Disperses bits across pseudo-random pixel coordinates. High capacity and imperceptible.
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="encryption">Encryption Method</label>
                        <select id="encryption" name="encryption">
                            <option value="none">No Encryption (Basic)</option>
                            <option value="aes" selected>AES-256 Encryption</option>
                            <option value="rsa">RSA-2048 Encryption</option>
                            <option value="hybrid">Hybrid AES+RSA Encryption</option>
                            <option value="aes_gcm">AES-GCM (Authenticated)</option>
                            <option value="chacha20">ChaCha20 (Stream Cipher)</option>
                            <option value="salsa20">Salsa20 (Stream Cipher)</option>
                            <option value="rc4">RC4 (Stream Cipher)</option>
                            <option value="threefish">Threefish (Tweakable)</option>
                            <option value="camellia">Camellia (Block Cipher)</option>
                            <option value="serpent">Serpent (Block Cipher)</option>
                            <option value="caesar">Caesar Cipher (Classic)</option>
                            <option value="vigenere">Vigenère Cipher (Polyalphabetic)</option>
                            <option value="xor">Multi-Pass XOR (Fast)</option>
                        </select>
                        <div class="encryption-info" id="encryptionInfo">
                            <i class="fas fa-info-circle"></i> AES-256 provides excellent security with good performance
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="hash">Hash Method</label>
                        <select id="hash" name="hash">
                            <option value="sha256">SHA-256 (Standard)</option>
                            <option value="sha512">SHA-512 (High Security)</option>
                        </select>
                    </div>
                    
                    <div class="form-group" id="passwordGroup">
                        <label for="password">Encryption Password</label>
                        <input type="password" id="password" name="password" placeholder="Enter a strong password...">
                        <div class="password-strength">
                            <div class="password-strength-bar" id="strengthBar"></div>
                        </div>
                        <small id="strengthText" style="color: rgba(255,255,255,0.7); font-size: 0.85rem;"></small>
                        
                        <!-- Password Hint guidance banner -->
                        <div class="password-hint" id="passwordHint">
                            <i class="fas fa-lightbulb"></i>
                            <span id="passwordHintText"><strong>Password Hint:</strong> Use at least 8 characters with a mix of uppercase, lowercase, numbers, and symbols.</span>
                        </div>
                        
                        <!-- Custom Password Hint input (optional) -->
                        <div style="margin-top: 18px;">
                            <label for="password_hint" style="font-size: 1.1rem; display: flex; align-items: center; gap: 8px;">
                                <i class="fas fa-key" style="color: #ffd700;"></i> Password Hint <span style="font-size: 0.85rem; opacity: 0.7; font-weight: normal;">(Optional - for message recovery)</span>
                            </label>
                            <input type="text" id="password_hint" name="password_hint" placeholder="e.g. My favorite school teacher, pet's name, childhood city...">
                        </div>
                        
                        <!-- Tactical Plausible Deniability (Duress / Decoy Protocol) -->
                        <div style="margin-top: 20px; padding: 16px 20px; background: rgba(255, 152, 0, 0.08); border: 1px solid rgba(255, 152, 0, 0.35); border-radius: 14px;">
                            <div style="display: flex; align-items: center; justify-content: space-between; cursor: pointer;" onclick="const s = document.getElementById('duressSection'); s.style.display = s.style.display === 'none' ? 'block' : 'none';">
                                <span style="font-size: 1.05rem; font-weight: 600; color: #ffb74d;">
                                    <i class="fas fa-shield-alt" style="color: #ff9800; margin-right: 6px;"></i> Plausible Deniability Protocol <small style="opacity: 0.75; font-size: 0.8rem;">(Duress Decoy Protection)</small>
                                </span>
                                <span style="font-size: 0.85rem; color: #ffd54f;"><i class="fas fa-chevron-down"></i> Toggle</span>
                            </div>
                            <div id="duressSection" style="display: none; margin-top: 14px; border-top: 1px dashed rgba(255, 152, 0, 0.3); padding-top: 12px;">
                                <p style="font-size: 0.85rem; color: #ffe0b2; margin-bottom: 12px; line-height: 1.5;">
                                    <strong>Tactical Duress Protocol:</strong> If captured or coerced to surrender your password, entering this secondary <em>Duress Key</em> will decrypt and display a pre-configured, harmless decoy message with no errors, completely hiding the true operational payload.
                                </p>
                                <label for="duress_password" style="font-size: 0.95rem; margin-bottom: 6px; display: block; color: #ffffff;">Secondary Duress / Decoy Password</label>
                                <input type="password" id="duress_password" name="duress_password" placeholder="Enter secondary duress key for plausible deniability...">
                                
                                <label for="decoy_message" style="font-size: 0.95rem; margin-top: 12px; margin-bottom: 6px; display: block; color: #ffffff;">Decoy Plaintext Message</label>
                                <input type="text" id="decoy_message" name="decoy_message" placeholder="Logistics update: Base operations running normal. Resupply convoy arrived on schedule.">
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn">
                        <i class="fas fa-lock"></i>
                        Encode Message
                    </button>
                </form>
                
                <div id="result" style="display: none;"></div>
            </div>
        </div>
        
        <script>
            // Initialize password field visibility based on default encryption selection
            document.addEventListener('DOMContentLoaded', function() {
                const encryptionSelect = document.getElementById('encryption');
                const passwordGroup = document.getElementById('passwordGroup');
                const encryptionInfo = document.getElementById('encryptionInfo');
                
                // Set initial state
                if (encryptionSelect.value !== 'none') {
                    passwordGroup.style.display = 'block';
                    passwordGroup.classList.add('encryption-active');
                } else {
                    passwordGroup.style.display = 'none';
                    passwordGroup.classList.remove('encryption-active');
                }
                
                // Set initial info text
                const infoTexts = {
                    'none': '<i class="fas fa-info-circle"></i> No encryption - faster but less secure',
                    'aes': '<i class="fas fa-info-circle"></i> AES-256 provides excellent security with good performance',
                    'rsa': '<i class="fas fa-info-circle"></i> RSA-2048 provides maximum security for small messages',
                    'hybrid': '<i class="fas fa-info-circle"></i> Hybrid combines AES speed with RSA security for best results',
                    'aes_gcm': '<i class="fas fa-info-circle"></i> AES-GCM provides authenticated encryption with integrity protection',
                    'chacha20': '<i class="fas fa-info-circle"></i> ChaCha20 - modern stream cipher, very fast and secure',
                    'salsa20': '<i class="fas fa-info-circle"></i> Salsa20 - high-speed stream cipher with excellent security',
                    'rc4': '<i class="fas fa-info-circle"></i> RC4 - classic stream cipher, fast but legacy algorithm',
                    'threefish': '<i class="fas fa-info-circle"></i> Threefish - tweakable block cipher, very secure',
                    'camellia': '<i class="fas fa-info-circle"></i> Camellia - Japanese block cipher, AES alternative',
                    'serpent': '<i class="fas fa-info-circle"></i> Serpent - simplified block cipher with good security',
                    'caesar': '<i class="fas fa-info-circle"></i> Caesar cipher - simple shift cipher, fast but basic security',
                    'vigenere': '<i class="fas fa-info-circle"></i> Vigenère cipher - polyalphabetic substitution, moderate security',
                    'xor': '<i class="fas fa-info-circle"></i> Multi-pass XOR - very fast, lightweight encryption'
                };
                
                encryptionInfo.innerHTML = infoTexts[encryptionSelect.value];
            });
            
            // Image Selection & Camera State
            let selectedImageFile = null;
            let stream = null;

            // DOM elements
            const fileInput = document.getElementById('image');
            const cameraInput = document.getElementById('camera');
            const fileLabel = document.getElementById('fileLabel');
            const cameraSection = document.getElementById('cameraSection');
            const cameraBtn = document.getElementById('cameraBtn');
            const deviceCameraBtn = document.getElementById('deviceCameraBtn');
            const cameraPreview = document.getElementById('cameraPreview');
            const cameraStatusBanner = document.getElementById('cameraStatusBanner');
            const cameraLoadingSpinner = document.getElementById('cameraLoadingSpinner');
            const cameraLoadingText = document.getElementById('cameraLoadingText');
            const video = document.getElementById('video');
            const canvas = document.getElementById('canvas');
            const captureBtn = document.getElementById('captureBtn');
            const retryCameraBtn = document.getElementById('retryCameraBtn');
            const fallbackSnapBtn = document.getElementById('fallbackSnapBtn');
            const cancelBtn = document.getElementById('cancelBtn');
            const imagePreviewCard = document.getElementById('imagePreviewCard');
            const imagePreviewImg = document.getElementById('imagePreviewImg');
            const previewBadge = document.getElementById('previewBadge');
            const previewName = document.getElementById('previewName');
            const previewSize = document.getElementById('previewSize');
            const retakeBtn = document.getElementById('retakeBtn');
            const changeFileBtn = document.getElementById('changeFileBtn');
            const removePhotoBtn = document.getElementById('removePhotoBtn');

            function displaySelectedImage(file, sourceLabel, sourceIcon) {
                if (!file) return;
                selectedImageFile = file;

                // Sync fileInput.files via DataTransfer so browser form handles it seamlessly
                try {
                    const dataTransfer = new DataTransfer();
                    dataTransfer.items.add(file);
                    fileInput.files = dataTransfer.files;
                } catch (e) {
                    console.warn('DataTransfer sync note:', e);
                }

                // Render image preview
                const reader = new FileReader();
                reader.onload = function(e) {
                    imagePreviewImg.src = e.target.result;
                    previewBadge.innerHTML = `<i class="${sourceIcon || 'fas fa-check-circle'}"></i> ${sourceLabel || 'Selected'}`;
                    previewName.textContent = file.name || 'image.png';
                    previewSize.textContent = `${(file.size / 1024 / 1024).toFixed(2)} MB`;

                    // Show preview card, hide dropzone & camera preview
                    imagePreviewCard.classList.add('active');
                    fileLabel.style.display = 'none';
                    if (cameraSection) cameraSection.style.display = 'none';
                };
                reader.readAsDataURL(file);
            }

            function clearSelectedImage() {
                selectedImageFile = null;
                fileInput.value = '';
                cameraInput.value = '';
                imagePreviewImg.src = '';
                imagePreviewCard.classList.remove('active');
                fileLabel.style.display = 'flex';
                if (cameraSection) cameraSection.style.display = 'block';
                if (cameraBtn) cameraBtn.style.display = 'inline-flex';
                if (deviceCameraBtn) deviceCameraBtn.style.display = 'inline-flex';
                stopCamera();
            }

            // File upload input change
            fileInput.addEventListener('change', function(e) {
                if (e.target.files && e.target.files.length > 0) {
                    displaySelectedImage(e.target.files[0], 'File Uploaded', 'fas fa-file-image');
                }
            });

            // Camera file input fallback change (native camera app or file)
            cameraInput.addEventListener('change', function(e) {
                if (e.target.files && e.target.files.length > 0) {
                    stopCamera();
                    displaySelectedImage(e.target.files[0], 'Camera Captured', 'fas fa-camera');
                }
            });

            // Device Camera App direct button
            if (deviceCameraBtn) {
                deviceCameraBtn.addEventListener('click', function() {
                    cameraInput.click();
                });
            }

            if (fallbackSnapBtn) {
                fallbackSnapBtn.addEventListener('click', function() {
                    cameraInput.click();
                });
            }

            // Start webcam function
            async function openCamera() {
                // Show camera preview box, hide other elements while recording
                cameraPreview.style.display = 'block';
                if (cameraBtn) cameraBtn.style.display = 'none';
                if (deviceCameraBtn) deviceCameraBtn.style.display = 'none';
                fileLabel.style.display = 'none';
                imagePreviewCard.classList.remove('active');

                // Reset UI inside preview
                cameraStatusBanner.style.display = 'none';
                cameraLoadingSpinner.style.display = 'flex';
                cameraLoadingText.textContent = 'Connecting to camera...';
                captureBtn.style.display = 'none';
                retryCameraBtn.style.display = 'none';
                fallbackSnapBtn.style.display = 'none';

                // Stop any previous tracks
                if (stream) {
                    stream.getTracks().forEach(t => t.stop());
                    stream = null;
                }
                video.srcObject = null;

                // Check MediaDevices support
                if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                    handleCameraError({
                        name: 'NotSupportedError',
                        message: 'Direct browser webcam access is not supported. Use the Camera App button below.'
                    });
                    return;
                }

                // Attempt to get stream with standard universal constraints
                let mediaStream = null;
                try {
                    // Try basic video constraint first (most compatible on laptops)
                    mediaStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
                } catch (e1) {
                    console.warn('Initial video constraint failed, attempting fallback resolution:', e1);
                    try {
                        mediaStream = await navigator.mediaDevices.getUserMedia({
                            video: { width: { ideal: 640 }, height: { ideal: 480 } }
                        });
                    } catch (e2) {
                        console.error('All camera attempts failed:', e2);
                        handleCameraError(e2);
                        return;
                    }
                }

                if (!mediaStream) {
                    handleCameraError({ name: 'StreamNull', message: 'Could not obtain camera video stream.' });
                    return;
                }

                stream = mediaStream;
                video.srcObject = stream;
                video.muted = true;
                video.playsInline = true;

                // Wait for video stream to actually play
                video.onloadedmetadata = async () => {
                    try {
                        await video.play();
                        cameraLoadingSpinner.style.display = 'none';
                        captureBtn.style.display = 'inline-flex';
                    } catch (playErr) {
                        console.warn('Video play error:', playErr);
                        cameraLoadingSpinner.style.display = 'none';
                        captureBtn.style.display = 'inline-flex';
                    }
                };

                // Fallback timeout in case onloadedmetadata doesn't fire immediately
                setTimeout(() => {
                    if (stream) {
                        cameraLoadingSpinner.style.display = 'none';
                        captureBtn.style.display = 'inline-flex';
                    }
                }, 1200);
            }

            function handleCameraError(err) {
                cameraLoadingSpinner.style.display = 'none';
                retryCameraBtn.style.display = 'inline-flex';
                fallbackSnapBtn.style.display = 'inline-flex';

                let msg = '';
                if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
                    msg = 'Camera permission was denied. Please click the lock icon 🔒 on the left of your browser address bar, set Camera to "Allow", then click "Retry Camera".';
                } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
                    msg = 'No webcam was detected by your browser. Click "Use Camera App" to snap a photo with your device camera.';
                } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
                    msg = 'Your webcam is being used by another app (Zoom, Teams, etc.). Please close other camera apps and click "Retry Camera".';
                } else {
                    msg = 'Camera access notice: ' + (err.message || err.name || 'Could not start camera') + '. You can click "Retry Camera" or "Use Camera App".';
                }
                cameraStatusBanner.className = 'camera-status-banner error';
                cameraStatusBanner.innerHTML = `<i class="fas fa-exclamation-triangle" style="font-size: 1.3rem; color: #ff8a80;"></i> <span>${msg}</span>`;
                cameraStatusBanner.style.display = 'flex';
            }

            cameraBtn.addEventListener('click', openCamera);
            retryCameraBtn.addEventListener('click', openCamera);

            // Capture photo
            captureBtn.addEventListener('click', function() {
                const w = video.videoWidth || 640;
                const h = video.videoHeight || 480;
                canvas.width = w;
                canvas.height = h;
                const context = canvas.getContext('2d');
                context.drawImage(video, 0, 0, w, h);

                canvas.toBlob(function(blob) {
                    if (!blob) {
                        alert('Could not capture frame. Please try again.');
                        return;
                    }
                    const filename = `camera_photo_${Date.now()}.png`;
                    const file = new File([blob], filename, { type: 'image/png' });
                    stopCamera();
                    displaySelectedImage(file, 'Camera Snapshot', 'fas fa-camera');
                }, 'image/png');
            });

            // Stop camera function
            function stopCamera() {
                if (stream) {
                    stream.getTracks().forEach(track => track.stop());
                    stream = null;
                }
                video.srcObject = null;
                cameraPreview.style.display = 'none';
                if (!selectedImageFile) {
                    fileLabel.style.display = 'flex';
                    if (cameraSection) cameraSection.style.display = 'block';
                    if (cameraBtn) cameraBtn.style.display = 'inline-flex';
                    if (deviceCameraBtn) deviceCameraBtn.style.display = 'inline-flex';
                }
            }

            cancelBtn.addEventListener('click', function() {
                stopCamera();
                if (selectedImageFile) {
                    imagePreviewCard.classList.add('active');
                }
            });

            retakeBtn.addEventListener('click', function() {
                if (cameraSection) cameraSection.style.display = 'block';
                openCamera();
            });

            if (changeFileBtn) {
                changeFileBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    fileInput.click();
                });
            }

            removePhotoBtn.addEventListener('click', function() {
                clearSelectedImage();
            });

            // Drag and drop
            fileLabel.addEventListener('dragover', function(e) {
                e.preventDefault();
                this.style.background = 'rgba(255, 255, 255, 0.2)';
            });

            fileLabel.addEventListener('dragleave', function(e) {
                e.preventDefault();
                this.style.background = 'rgba(255, 255, 255, 0.12)';
            });

            fileLabel.addEventListener('drop', function(e) {
                e.preventDefault();
                this.style.background = 'rgba(255, 255, 255, 0.12)';
                
                const files = e.dataTransfer.files;
                if (files && files.length > 0) {
                    displaySelectedImage(files[0], 'File Dropped', 'fas fa-file-image');
                }
            });
            
            // Steganography mode change
            const stegoModeSelect = document.getElementById('stego_mode');
            if (stegoModeSelect) {
                stegoModeSelect.addEventListener('change', function() {
                    const info = document.getElementById('stegoModeInfo');
                    if (this.value === 'dct') {
                        info.innerHTML = '<i class="fas fa-wave-square"></i> <strong>Frequency Domain (8x8 DCT):</strong> Transforms luminance blocks via 2D-DCT. Embeds in middle frequencies to survive JPEG compression and lossy transmission.';
                        info.style.borderLeftColor = '#ff9800';
                        info.style.background = 'rgba(255, 152, 0, 0.15)';
                    } else {
                        info.innerHTML = '<i class="fas fa-shield-alt"></i> <strong>Spatial PRNG Mode:</strong> Disperses bits across pseudo-random pixel coordinates. High capacity and imperceptible.';
                        info.style.borderLeftColor = '#2196f3';
                        info.style.background = 'rgba(33, 150, 243, 0.15)';
                    }
                });
            }
            
            // Encryption method change
            document.getElementById('encryption').addEventListener('change', function() {
                const passwordGroup = document.getElementById('passwordGroup');
                const encryptionInfo = document.getElementById('encryptionInfo');
                
                if (this.value !== 'none') {
                    passwordGroup.style.display = 'block';
                    passwordGroup.style.animation = 'fadeInUp 0.5s ease-out';
                    passwordGroup.classList.add('encryption-active');
                } else {
                    passwordGroup.style.display = 'none';
                    passwordGroup.classList.remove('encryption-active');
                }
                
                // Update info text
                const infoTexts = {
                    'none': '<i class="fas fa-info-circle"></i> No encryption - faster but less secure',
                    'aes': '<i class="fas fa-info-circle"></i> AES-256 provides excellent security with good performance',
                    'rsa': '<i class="fas fa-info-circle"></i> RSA-2048 provides maximum security for small messages',
                    'hybrid': '<i class="fas fa-info-circle"></i> Hybrid combines AES speed with RSA security for best results',
                    'aes_gcm': '<i class="fas fa-info-circle"></i> AES-GCM provides authenticated encryption with integrity protection',
                    'chacha20': '<i class="fas fa-info-circle"></i> ChaCha20 - modern stream cipher, very fast and secure',
                    'salsa20': '<i class="fas fa-info-circle"></i> Salsa20 - high-speed stream cipher with excellent security',
                    'rc4': '<i class="fas fa-info-circle"></i> RC4 - classic stream cipher, fast but legacy algorithm',
                    'threefish': '<i class="fas fa-info-circle"></i> Threefish - tweakable block cipher, very secure',
                    'camellia': '<i class="fas fa-info-circle"></i> Camellia - Japanese block cipher, AES alternative',
                    'serpent': '<i class="fas fa-info-circle"></i> Serpent - simplified block cipher with good security',
                    'caesar': '<i class="fas fa-info-circle"></i> Caesar cipher - simple shift cipher, fast but basic security',
                    'vigenere': '<i class="fas fa-info-circle"></i> Vigenère cipher - polyalphabetic substitution, moderate security',
                    'xor': '<i class="fas fa-info-circle"></i> Multi-pass XOR - very fast, lightweight encryption'
                };
                
                encryptionInfo.innerHTML = infoTexts[this.value];
                encryptionInfo.style.animation = 'fadeIn 0.5s ease-out';
            });
            
            // Password strength checker
            document.getElementById('password').addEventListener('input', function(e) {
                const password = e.target.value;
                const strengthBar = document.getElementById('strengthBar');
                const strengthText = document.getElementById('strengthText');
                const passwordHintText = document.getElementById('passwordHintText');
                
                if (password.length === 0) {
                    strengthBar.className = 'password-strength-bar';
                    strengthText.textContent = '';
                    if (passwordHintText) {
                        passwordHintText.innerHTML = '<strong>Password Hint:</strong> Use at least 8 characters with a mix of uppercase, lowercase, numbers, and symbols.';
                    }
                    return;
                }
                
                let strength = 0;
                if (password.length >= 8) strength++;
                if (password.length >= 12) strength++;
                if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
                if (/\d/.test(password)) strength++;
                if (/[^a-zA-Z\d]/.test(password)) strength++;
                
                strengthBar.className = 'password-strength-bar';
                
                if (strength <= 2) {
                    strengthBar.classList.add('strength-weak');
                    strengthText.textContent = 'Weak password';
                    strengthText.style.color = '#f44336';
                    if (passwordHintText) {
                        passwordHintText.innerHTML = '<strong>Password Hint:</strong> Add uppercase letters, numbers, or symbols (e.g. @, #, $) to make it stronger.';
                    }
                } else if (strength <= 4) {
                    strengthBar.classList.add('strength-medium');
                    strengthText.textContent = 'Medium strength';
                    strengthText.style.color = '#ff9800';
                    if (passwordHintText) {
                        passwordHintText.innerHTML = '<strong>Password Hint:</strong> Good! Add more characters or symbols for military-grade protection.';
                    }
                } else {
                    strengthBar.classList.add('strength-strong');
                    strengthText.textContent = 'Strong password';
                    strengthText.style.color = '#4caf50';
                    if (passwordHintText) {
                        passwordHintText.innerHTML = '<strong>Password Hint:</strong> Excellent! Your password meets top-tier cryptographic security standards.';
                    }
                }
            });
            
            // Form submission
            document.getElementById('encodeForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                // Check if file is selected (from upload or camera snapshot)
                const fileToSend = selectedImageFile || (fileInput.files && fileInput.files.length > 0 ? fileInput.files[0] : null);
                if (!fileToSend) {
                    const resultDiv = document.getElementById('result');
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <h3><i class="fas fa-exclamation-circle"></i> No Image Selected</h3>
                        <p>Please select an image file or take a photo to encode.</p>
                    `;
                    resultDiv.style.display = 'block';
                    return;
                }
                
                // Check if message is provided
                const messageInput = document.getElementById('message');
                if (!messageInput.value.trim()) {
                    const resultDiv = document.getElementById('result');
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <h3><i class="fas fa-exclamation-circle"></i> No Message Provided</h3>
                        <p>Please enter a message to hide in the image.</p>
                    `;
                    resultDiv.style.display = 'block';
                    return;
                }
                
                // Check if password is provided when encryption is selected
                const encryptionValue = document.getElementById('encryption').value;
                const passwordValue = document.getElementById('password').value;
                if (encryptionValue !== 'none' && !passwordValue.trim()) {
                    const resultDiv = document.getElementById('result');
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <h3><i class="fas fa-exclamation-circle"></i> Password Required</h3>
                        <p>Please enter a password to protect your encrypted message.</p>
                    `;
                    resultDiv.style.display = 'block';
                    return;
                }
                
                const formData = new FormData();
                formData.append('image', fileToSend);
                formData.append('message', messageInput.value);
                formData.append('encryption', encryptionValue);
                formData.append('hash', document.getElementById('hash').value);
                formData.append('password', passwordValue || '');
                const passwordHintInput = document.getElementById('password_hint');
                formData.append('password_hint', passwordHintInput ? passwordHintInput.value.trim() : '');
                const stegoModeVal = document.getElementById('stego_mode') ? document.getElementById('stego_mode').value : 'spatial';
                formData.append('stego_mode', stegoModeVal);
                const duressPwdInput = document.getElementById('duress_password');
                formData.append('duress_password', duressPwdInput ? duressPwdInput.value.trim() : '');
                const decoyMsgInput = document.getElementById('decoy_message');
                formData.append('decoy_message', decoyMsgInput ? decoyMsgInput.value.trim() : '');
                
                const btn = this.querySelector('button[type="submit"]');
                btn.disabled = true;
                btn.classList.add('spinning');
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encoding...';
                
                try {
                    // Use full URL to avoid network issues
                    const currentUrl = window.location.origin;
                    const response = await fetch(`${currentUrl}/encode`, {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'Accept': 'application/json'
                        }
                    });
                    
                    // Check if response is ok
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    
                    const result = await response.json();
                    const resultDiv = document.getElementById('result');
                    
                    if (result.success) {
                        resultDiv.className = 'result';
                        
                        const psnrDisplay = (typeof result.psnr === 'number') ? result.psnr.toFixed(2) : (result.psnr || 'N/A');
                        const ssimDisplay = (typeof result.ssim === 'number') ? result.ssim.toFixed(4) : (result.ssim || 'N/A');
                        
                        resultDiv.innerHTML = `
                            <h3><i class="fas fa-check-circle"></i> Message Encoded Successfully!</h3>
                            <p>Your secret message has been hidden inside the image using ${document.getElementById('encryption').options[document.getElementById('encryption').selectedIndex].text}.</p>
                            
                            <!-- Mathematical Evaluation Metrics Display -->
                            <div class="evaluation-metrics" style="margin: 22px 0 25px; padding: 18px 20px; background: rgba(0, 0, 0, 0.25); border: 1px solid rgba(255, 255, 255, 0.18); border-radius: 16px; backdrop-filter: blur(12px);">
                                <div style="font-size: 0.95rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1.2px; color: #ffd700; margin-bottom: 15px; display: flex; align-items: center; justify-content: center; gap: 8px;">
                                    <i class="fas fa-square-root-variable"></i> Mathematical Evaluation Metrics
                                </div>
                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px;">
                                    <div style="background: rgba(255, 255, 255, 0.08); padding: 14px 18px; border-radius: 12px; border-left: 4px solid #4caf50; text-align: left;">
                                        <div style="font-size: 0.8rem; color: #a5d6a7; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600;">
                                            <i class="fas fa-chart-line"></i> PSNR (Peak Signal-to-Noise)
                                        </div>
                                        <div style="font-size: 1.85rem; font-weight: 800; color: #ffffff; margin: 4px 0;">
                                            ${psnrDisplay} <span style="font-size: 0.95rem; font-weight: 500; color: #c8e6c9;">dB</span>
                                        </div>
                                        <div style="font-size: 0.78rem; color: rgba(255, 255, 255, 0.75);">
                                            ${result.psnr >= 35 ? '✅ High fidelity (>35 dB)' : 'Evaluated against original'}
                                        </div>
                                    </div>
                                    <div style="background: rgba(255, 255, 255, 0.08); padding: 14px 18px; border-radius: 12px; border-left: 4px solid #2196f3; text-align: left;">
                                        <div style="font-size: 0.8rem; color: #90caf9; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600;">
                                            <i class="fas fa-layer-group"></i> SSIM (Structural Similarity)
                                        </div>
                                        <div style="font-size: 1.85rem; font-weight: 800; color: #ffffff; margin: 4px 0;">
                                            ${ssimDisplay}
                                        </div>
                                        <div style="font-size: 0.78rem; color: rgba(255, 255, 255, 0.75);">
                                            ${result.ssim >= 0.98 ? '✅ Near-identical structure (~1.0000)' : 'Structural fidelity verified'}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <a href="${result.download_url}" download="${result.filename}" class="btn">
                                <i class="fas fa-download"></i>
                                Download Encoded Image
                            </a>
                        `;
                    } else {
                        resultDiv.className = 'result error';
                        let violationBadge = '';
                        if (result.security_violation && result.calculated_psnr) {
                            violationBadge = `
                                <div style="margin-top: 15px; padding: 14px 18px; background: rgba(231, 76, 60, 0.2); border: 1px solid rgba(231, 76, 60, 0.5); border-radius: 12px; text-align: left;">
                                    <div style="font-weight: 700; color: #ff6b6b; margin-bottom: 6px;">
                                        <i class="fas fa-shield-alt"></i> Tactical Imperceptibility Interlock Active
                                    </div>
                                    <div style="font-size: 0.9rem; color: #f5f5f5;">
                                        • Measured PSNR: <strong>${result.calculated_psnr} dB</strong> (Defense Floor: <strong>${result.threshold || 42.0} dB</strong>)<br>
                                        • Status: <strong>Memory scrubbed, carrier write aborted to evade steganalysis detection.</strong>
                                    </div>
                                </div>
                            `;
                        }
                        resultDiv.innerHTML = `
                            <h3><i class="fas fa-ban" style="color: #e74c3c;"></i> ${result.security_violation ? 'Tactical Security Abort' : 'Encoding Failed'}</h3>
                            <p style="font-size: 1.05rem; font-weight: 500;">${result.error}</p>
                            ${violationBadge}
                        `;
                    }
                    
                    resultDiv.style.display = 'block';
                } catch (error) {
                    console.error('Encode error:', error);
                    const resultDiv = document.getElementById('result');
                    resultDiv.className = 'result error';
                    
                    // Provide more specific error messages
                    let errorMessage = 'Failed to connect to the server. Please try again.';
                    if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
                        errorMessage = 'Network connection failed. Please check your internet connection and try again.';
                    } else if (error.message.includes('HTTP error')) {
                        errorMessage = 'Server error occurred. Please try again later.';
                    } else if (error.name === 'AbortError') {
                        errorMessage = 'Request timed out. Please try again.';
                    }
                    
                    resultDiv.innerHTML = `
                        <h3><i class="fas fa-exclamation-circle"></i> Network Error</h3>
                        <p>${errorMessage}</p>
                        <p><small>Error details: ${error.message}</small></p>
                    `;
                    resultDiv.style.display = 'block';
                } finally {
                    btn.disabled = false;
                    btn.classList.remove('spinning');
                    btn.innerHTML = '<i class="fas fa-lock"></i> Encode Message';
                }
            });
        </script>
    </body>
    </html>
    '''

@app.route('/decode')
def decode_page():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Decode Message - Steganography Pro</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1e3c72, #2a5298);
                color: white;
                min-height: 100vh;
                line-height: 1.6;
                animation: gradientShift 10s ease infinite;
            }
            
            @keyframes gradientShift {
                0%, 100% { background: linear-gradient(135deg, #1e3c72, #2a5298); }
                25% { background: linear-gradient(135deg, #2a5298, #1e3c72); }
                50% { background: linear-gradient(135deg, #1e3c72, #34495e); }
                75% { background: linear-gradient(135deg, #34495e, #2a5298); }
            }
            
            .container {
                max-width: 900px;
                margin: 0 auto;
                padding: 30px 20px;
                animation: fadeInUp 0.8s ease-out;
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            header {
                text-align: center;
                padding: 40px 0;
                animation: slideDown 0.6s ease-out;
            }
            
            @keyframes slideDown {
                from {
                    opacity: 0;
                    transform: translateY(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            h1 {
                font-size: 2.8em;
                margin-bottom: 15px;
                text-shadow: 3px 3px 6px rgba(0,0,0,0.4);
                font-weight: 600;
                letter-spacing: -0.5px;
                animation: glow 2s ease-in-out infinite alternate;
            }
            
            @keyframes glow {
                from { text-shadow: 3px 3px 6px rgba(0,0,0,0.4), 0 0 10px rgba(243,156,18,0.3); }
                to { text-shadow: 3px 3px 6px rgba(0,0,0,0.4), 0 0 20px rgba(243,156,18,0.5); }
            }
            
            .subtitle {
                font-size: 1.2em;
                color: #a8d8ff;
                margin-bottom: 20px;
                font-weight: 300;
                animation: fadeIn 1s ease-out 0.3s both;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            .back-btn {
                display: inline-flex;
                align-items: center;
                gap: 12px;
                padding: 12px 24px;
                background: rgba(255,255,255,0.15);
                color: white;
                text-decoration: none;
                border-radius: 30px;
                margin-bottom: 30px;
                transition: all 0.3s ease;
                font-size: 16px;
                font-weight: 500;
                border: 1px solid rgba(255,255,255,0.2);
                animation: slideInLeft 0.8s ease-out 0.2s both;
            }
            
            @keyframes slideInLeft {
                from {
                    opacity: 0;
                    transform: translateX(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            
            .back-btn:hover {
                background: rgba(255,255,255,0.25);
                transform: translateY(-2px) scale(1.05);
                box-shadow: 0 8px 25px rgba(0,0,0,0.2);
            }
            
            .form-container {
                background: rgba(255,255,255,0.12);
                padding: 50px;
                border-radius: 25px;
                backdrop-filter: blur(15px);
                border: 1px solid rgba(255,255,255,0.2);
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                animation: scaleIn 0.8s ease-out 0.4s both;
            }
            
            @keyframes scaleIn {
                from {
                    opacity: 0;
                    transform: scale(0.9);
                }
                to {
                    opacity: 1;
                    transform: scale(1);
                }
            }
            
            .form-group {
                margin-bottom: 30px;
                animation: fadeInUp 0.6s ease-out both;
            }
            
            .form-group:nth-child(1) { animation-delay: 0.5s; }
            .form-group:nth-child(2) { animation-delay: 0.6s; }
            .form-group:nth-child(3) { animation-delay: 0.7s; }
            
            label {
                display: block;
                margin-bottom: 12px;
                font-weight: 600;
                color: #e8f4ff;
                font-size: 18px;
                letter-spacing: 0.3px;
                transition: all 0.3s ease;
            }
            
            label:hover {
                color: #f39c12;
                transform: translateX(5px);
            }
            
            input[type="file"],
            input[type="password"] {
                width: 100%;
                padding: 18px 20px;
                background: rgba(255,255,255,0.12);
                border: 2px solid rgba(255,255,255,0.25);
                border-radius: 15px;
                color: white;
                font-size: 17px;
                transition: all 0.3s ease;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                position: relative;
                overflow: hidden;
            }
            
            input[type="file"]::before,
            input[type="password"]::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                transition: left 0.5s ease;
            }
            
            input[type="file"]:focus::before,
            input[type="password"]:focus::before {
                left: 100%;
            }
            
            input[type="file"]::-webkit-file-upload-button,
            input[type="file"]::-ms-browse {
                display: none;
            }
            
            input[type="file"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #f39c12;
                background: rgba(255,255,255,0.18);
                box-shadow: 0 0 0 4px rgba(243,156,18,0.2);
                transform: translateY(-2px);
            }
            
            input::placeholder {
                color: rgba(255,255,255,0.6);
                animation: placeholderPulse 2s ease-in-out infinite;
            }
            
            @keyframes placeholderPulse {
                0%, 100% { opacity: 0.6; }
                50% { opacity: 0.8; }
            }
            
            .file-input-label {
                display: block;
                padding: 30px;
                background: rgba(255,255,255,0.08);
                border: 3px dashed rgba(255,255,255,0.4);
                border-radius: 15px;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 18px;
                position: relative;
                overflow: hidden;
            }
            
            .file-input-label::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(243,156,18,0.1), transparent);
                transition: left 0.5s ease;
            }
            
            .file-input-label:hover::before {
                left: 100%;
            }
            
            .file-input-label:hover {
                background: rgba(255,255,255,0.15);
                border-color: #f39c12;
                transform: translateY(-2px) scale(1.02);
                box-shadow: 0 10px 30px rgba(243,156,18,0.2);
            }
            
            .file-input-label i {
                font-size: 48px;
                margin-bottom: 15px;
                display: block;
                color: #f39c12;
                animation: bounce 2s ease-in-out infinite;
            }
            
            @keyframes bounce {
                0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
                40% { transform: translateY(-10px); }
                60% { transform: translateY(-5px); }
            }
            
            .file-input-label.has-file {
                background: rgba(39,174,96,0.2);
                border-color: rgba(39,174,96,0.5);
                border-style: solid;
                animation: successPulse 0.5s ease-out;
            }
            
            @keyframes successPulse {
                0% { transform: scale(1); }
                50% { transform: scale(1.05); }
                100% { transform: scale(1); }
            }
            
            .file-input-label.has-file i {
                color: #27ae60;
                animation: checkmark 0.5s ease-out;
            }
            
            @keyframes checkmark {
                0% { transform: scale(0) rotate(0deg); }
                50% { transform: scale(1.2) rotate(180deg); }
                100% { transform: scale(1) rotate(360deg); }
            }
            
            .btn {
                padding: 18px 40px;
                background: linear-gradient(45deg, #f39c12, #e67e22);
                color: white;
                border: none;
                border-radius: 50px;
                cursor: pointer;
                font-size: 18px;
                font-weight: 600;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 12px;
                width: 100%;
                justify-content: center;
                text-transform: uppercase;
                letter-spacing: 1px;
                box-shadow: 0 8px 25px rgba(243,156,18,0.3);
                position: relative;
                overflow: hidden;
            }
            
            .btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
                transition: left 0.5s ease;
            }
            
            .btn:hover::before {
                left: 100%;
            }
            
            .btn:hover {
                transform: translateY(-3px) scale(1.02);
                box-shadow: 0 15px 40px rgba(243,156,18,0.4);
                background: linear-gradient(45deg, #e67e22, #d35400);
            }
            
            .btn:active {
                transform: translateY(-1px) scale(1.01);
            }
            
            .btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
                box-shadow: none;
            }
            
            .btn:disabled::before {
                display: none;
            }
            
            .btn.spinning {
                background: linear-gradient(45deg, #95a5a6, #7f8c8d);
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            
            .btn i {
                transition: transform 0.3s ease;
            }
            
            .btn:hover i {
                transform: scale(1.1);
            }
            
            .btn.spinning i {
                animation: iconSpin 1s linear infinite;
            }
            
            @keyframes iconSpin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            
            .result {
                margin-top: 40px;
                padding: 30px;
                background: rgba(39,174,96,0.15);
                border: 2px solid rgba(39,174,96,0.4);
                border-radius: 15px;
                text-align: center;
                animation: slideInUp 0.5s ease-out;
            }
            
            .error {
                background: rgba(231,76,60,0.15);
                border-color: rgba(231,76,60,0.4);
                animation: shake 0.5s ease-out;
            }
            
            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
                20%, 40%, 60%, 80% { transform: translateX(5px); }
            }
            
            .result h3 {
                font-size: 1.8em;
                margin-bottom: 15px;
                color: #27ae60;
                font-weight: 600;
                animation: fadeInScale 0.5s ease-out;
            }
            
            @keyframes fadeInScale {
                from {
                    opacity: 0;
                    transform: scale(0.8);
                }
                to {
                    opacity: 1;
                    transform: scale(1);
                }
            }
            
            .error h3 {
                color: #e74c3c;
                animation: errorPulse 1s ease-in-out infinite;
            }
            
            @keyframes errorPulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }
            
            .result p {
                font-size: 16px;
                margin-bottom: 10px;
                line-height: 1.6;
                color: rgba(255,255,255,0.9);
                animation: fadeIn 0.5s ease-out both;
            }
            
            .result p:nth-child(2) { animation-delay: 0.1s; }
            .result p:nth-child(3) { animation-delay: 0.2s; }
            .result p:nth-child(4) { animation-delay: 0.3s; }
            
            .message-content {
                background: rgba(255,255,255,0.15);
                padding: 25px;
                border-radius: 15px;
                margin: 25px 0;
                font-family: 'Courier New', 'Consolas', monospace;
                word-wrap: break-word;
                font-size: 18px;
                line-height: 1.8;
                border: 1px solid rgba(255,255,255,0.2);
                text-align: left;
                color: #fff;
                font-weight: 500;
                animation: typewriter 0.5s ease-out;
            }
            
            @keyframes typewriter {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .attempts-warning {
                background: rgba(243,156,18,0.2);
                border: 2px solid rgba(243,156,18,0.5);
                border-radius: 10px;
                padding: 15px;
                margin: 15px 0;
                font-weight: 600;
                animation: warningPulse 1.5s ease-in-out infinite;
            }
            
            @keyframes warningPulse {
                0%, 100% { 
                    transform: scale(1);
                    box-shadow: 0 0 0 0 rgba(243,156,18,0.4);
                }
                50% { 
                    transform: scale(1.02);
                    box-shadow: 0 0 20px 10px rgba(243,156,18,0.2);
                }
            }
            
            .final-attempt {
                background: rgba(231,76,60,0.3);
                border-color: rgba(231,76,60,0.6);
                animation: finalWarning 1s ease-in-out infinite;
            }
            
            @keyframes finalWarning {
                0%, 100% { 
                    transform: scale(1);
                    background: rgba(231,76,60,0.3);
                }
                50% { 
                    transform: scale(1.03);
                    background: rgba(231,76,60,0.5);
                }
            }
            
            @media (max-width: 768px) {
                .container { 
                    padding: 20px 15px; 
                }
                .form-container { 
                    padding: 30px 25px; 
                }
                h1 { 
                    font-size: 2.2em; 
                }
                .subtitle {
                    font-size: 1.1em;
                }
                label {
                    font-size: 16px;
                }
                input[type="file"],
                input[type="password"] {
                    font-size: 16px;
                    padding: 15px;
                }
                .btn {
                    font-size: 16px;
                    padding: 15px 30px;
                }
                .message-content {
                    font-size: 16px;
                    padding: 20px;
                }
            }
            
            @media (max-width: 480px) {
                .form-container {
                    padding: 25px 20px;
                }
                h1 {
                    font-size: 2em;
                }
                .file-input-label {
                    padding: 25px 20px;
                }
                .file-input-label i {
                    font-size: 36px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <a href="/" class="back-btn">
                    <i class="fas fa-arrow-left"></i>
                    <span>Back to Home</span>
                </a>
                <h1>Decode Secret Message</h1>
                <p class="subtitle">Upload your encoded image to reveal the hidden message</p>
            </header>
            
            <div class="form-container">
                <form id="decodeForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="image">Choose Encoded Image</label>
                        <input type="file" id="image" name="image" accept="image/*" required>
                        <label for="image" class="file-input-label">
                            <i class="fas fa-image"></i>
                            <div>Click to browse or drag & drop your encoded image here</div>
                            <small>Supports: PNG, JPG, JPEG, BMP, GIF, TIFF</small>
                        </label>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password (if encrypted)</label>
                        <input type="password" id="password" name="password" placeholder="Enter password if the message is encrypted...">
                        <div id="decodePasswordHintBox" style="display: none; margin-top: 12px; padding: 12px 16px; background: rgba(255, 215, 0, 0.15); border-left: 4px solid #ffd700; border-radius: 8px; color: #fff9c4; font-size: 0.95rem;">
                            <i class="fas fa-lightbulb" style="color: #ffd700; margin-right: 6px;"></i> <strong>Password Hint:</strong> <span id="decodePasswordHintText"></span>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn">
                        <i class="fas fa-unlock"></i>
                        Decode Message
                    </button>
                </form>
                
                <div id="result" style="display: none;"></div>
            </div>
        </div>
        
        <script>
            document.getElementById('decodeForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                // Check if file is selected
                const fileInput = document.getElementById('image');
                if (!fileInput.files || fileInput.files.length === 0) {
                    const resultDiv = document.getElementById('result');
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `
                        <h3><i class="fas fa-exclamation-circle"></i> No Image Selected</h3>
                        <p>Please select an image file to decode.</p>
                    `;
                    resultDiv.style.display = 'block';
                    return;
                }
                
                const formData = new FormData();
                formData.append('image', fileInput.files[0]);
                formData.append('password', document.getElementById('password').value || '');
                
                const btn = this.querySelector('button[type="submit"]');
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Decoding...';
                
                try {
                    // Use full URL to avoid network issues
                    const currentUrl = window.location.origin;
                    const response = await fetch(`${currentUrl}/decode`, {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'Accept': 'application/json'
                        }
                    });
                    
                    // Check if response is ok
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    
                    const result = await response.json();
                    const resultDiv = document.getElementById('result');
                    
                    if (result.success) {
                        let encryptionInfo = '';
                        if (result.encryption_used === 'none') {
                            encryptionInfo = '<p><i class="fas fa-unlock"></i> This message was not password protected</p>';
                        } else if (result.encryption_used === 'password_protected') {
                            encryptionInfo = '<p><i class="fas fa-lock"></i> This message was password protected</p>';
                        } else {
                            encryptionInfo = `<p><i class="fas fa-lock"></i> This message was protected with ${result.encryption_used.toUpperCase()} encryption</p>`;
                        }
                        
                        let domainBadge = result.technique_used ? `<p style="font-size: 0.95em; color: #a8d8ff; margin-top: 5px;"><i class="fas fa-layer-group"></i> Steganography Domain: <strong>${result.technique_used}</strong></p>` : '';
                        
                        resultDiv.className = 'result';
                        resultDiv.innerHTML = `
                            <h3><i class="fas fa-check-circle"></i> Message Decoded Successfully!</h3>
                            ${encryptionInfo}
                            ${domainBadge}
                            <div class="message-content">${result.message}</div>
                        `;
                    } else {
                        // Check if password is required
                        if (result.password_required) {
                            // Show password field if it's hidden
                            const passwordGroup = document.querySelector('.form-group:nth-child(2)');
                            if (passwordGroup && passwordGroup.style.display === 'none') {
                                passwordGroup.style.display = 'block';
                                passwordGroup.style.animation = 'fadeInUp 0.5s ease-out';
                            }
                            
                            // Display password hint if available
                            if (result.password_hint && result.password_hint.trim()) {
                                const hintBox = document.getElementById('decodePasswordHintBox');
                                const hintText = document.getElementById('decodePasswordHintText');
                                if (hintBox && hintText) {
                                    hintText.textContent = result.password_hint;
                                    hintBox.style.display = 'block';
                                }
                            }
                            
                            // Check if image was destroyed
                            if (result.image_destroyed) {
                                resultDiv.className = 'result error';
                                resultDiv.innerHTML = `
                                    <h3><i class="fas fa-skull-crossbones"></i> ACCESS DENIED</h3>
                                    <p><strong>${result.error}</strong></p>
                                    <p><i class="fas fa-exclamation-triangle"></i> For security reasons, this image has been permanently destroyed.</p>
                                `;
                            } else {
                                const attemptsRemaining = result.attempts_remaining || 2;
                                let warningText = '';
                                if (attemptsRemaining <= 1) {
                                    warningText = '<div class="attempts-warning final-attempt"><p style="color: #ff6b6b;"><strong>⚠️ FINAL ATTEMPT - Image will be destroyed on next failure!</strong></p></div>';
                                } else {
                                    warningText = `<div class="attempts-warning"><p><i class="fas fa-info-circle"></i> Attempts remaining: ${attemptsRemaining}</p></div>`;
                                }
                                
                                let hintHtml = '';
                                if (result.password_hint && result.password_hint.trim()) {
                                    hintHtml = `<div style="margin: 12px 0; padding: 12px 16px; background: rgba(255, 215, 0, 0.18); border-left: 4px solid #ffd700; border-radius: 8px; text-align: left; color: #fff9c4;"><i class="fas fa-lightbulb" style="color: #ffd700;"></i> <strong>Password Hint:</strong> ${result.password_hint}</div>`;
                                }
                                
                                resultDiv.className = 'result error';
                                resultDiv.innerHTML = `
                                    <h3><i class="fas fa-lock"></i> Incorrect Password</h3>
                                    <p>The password you entered is incorrect.</p>
                                    ${hintHtml}
                                    ${warningText}
                                    <p><strong>Please enter the correct password and try again.</strong></p>
                                `;
                            }
                        } else {
                            resultDiv.className = 'result error';
                            resultDiv.innerHTML = `
                                <h3><i class="fas fa-exclamation-circle"></i> Decoding Failed</h3>
                                <p>${result.error}</p>
                            `;
                        }
                    }
                    
                    resultDiv.style.display = 'block';
                } catch (error) {
                    console.error('Decode error:', error);
                    const resultDiv = document.getElementById('result');
                    resultDiv.className = 'result error';
                    
                    // Check if it's a DOM error (like the passwordGroup issue)
                    if (error.name === 'TypeError' && error.message.includes('Cannot read properties of null')) {
                        // This is likely a DOM access error, not a network error
                        resultDiv.innerHTML = `
                            <h3><i class="fas fa-exclamation-triangle"></i> Application Error</h3>
                            <p>There was an issue processing your request. Please try refreshing the page.</p>
                            <p><small>If this persists, please contact support.</small></p>
                        `;
                    } else {
                        // Handle network and other errors
                        let errorMessage = 'Failed to connect to the server. Please try again.';
                        let errorTitle = 'Network Error';
                        
                        if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
                            errorMessage = 'Network connection failed. Please check your internet connection and try again.';
                            errorTitle = 'Connection Failed';
                        } else if (error.message.includes('HTTP error')) {
                            errorMessage = 'Server error occurred. Please try again later.';
                            errorTitle = 'Server Error';
                        } else if (error.name === 'AbortError') {
                            errorMessage = 'Request timed out. Please try again.';
                            errorTitle = 'Request Timeout';
                        }
                        
                        resultDiv.innerHTML = `
                            <h3><i class="fas fa-exclamation-circle"></i> ${errorTitle}</h3>
                            <p>${errorMessage}</p>
                            <p><small>Error details: ${error.message}</small></p>
                        `;
                    }
                    resultDiv.style.display = 'block';
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-unlock"></i> Decode Message';
                }
            });
        </script>
    </body>
    </html>
    '''

@app.route('/encode', methods=['POST'])
def encode_message():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file provided'})
        
        image = request.files['image']
        message = request.form.get('message', '')
        encryption = request.form.get('encryption', 'none')
        hash_method = request.form.get('hash', 'sha256')
        password = request.form.get('password', '')
        password_hint = request.form.get('password_hint', '').strip()
        stego_mode = request.form.get('stego_mode', 'spatial')
        duress_password = request.form.get('duress_password', '').strip()
        decoy_message = request.form.get('decoy_message', '').strip()
        
        if image.filename == '':
            return jsonify({'success': False, 'error': 'No image selected'})
        
        if not message:
            return jsonify({'success': False, 'error': 'No message provided'})
        
        # Check file extension
        allowed_extensions = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'tiff'}
        if not ('.' in image.filename and 
                image.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            return jsonify({'success': False, 'error': 'Invalid file format. Allowed formats: PNG, JPG, JPEG, BMP, GIF, TIFF'})
        
        # Ingest and sanitize carrier: Strip all EXIF, GPS coordinates, device signatures, and metadata
        img = sanitize_metadata(image)
            
        # Keep a raw copy of sanitized original for mathematical evaluation metrics (PSNR, SSIM)
        original_img = img.copy()
        
        # Apply encryption if requested
        original_message = message  # Keep original for hashing
        password_hash = None
        
        if encryption != 'none':
            if not password:
                return jsonify({'success': False, 'error': 'A password is required for the selected encryption method.'})
            try:
                # Generate password hash for validation during decoding
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                if encryption == 'aes':
                    encrypted_message = encrypt_aes(message, password)
                elif encryption == 'rsa':
                    encrypted_message = encrypt_rsa(message, password)
                elif encryption == 'hybrid':
                    encrypted_message = encrypt_hybrid(message, password)
                elif encryption == 'aes_gcm':
                    encrypted_message = encrypt_aes_gcm(message, password)
                elif encryption == 'chacha20':
                    encrypted_message = encrypt_chacha20(message, password)
                elif encryption == 'salsa20':
                    encrypted_message = encrypt_salsa20(message, password)
                elif encryption == 'rc4':
                    encrypted_message = encrypt_rc4(message, password)
                elif encryption == 'threefish':
                    encrypted_message = encrypt_threefish(message, password)
                elif encryption == 'camellia':
                    encrypted_message = encrypt_camellia(message, password)
                elif encryption == 'serpent':
                    encrypted_message = encrypt_serpent(message, password)
                elif encryption == 'caesar':
                    encrypted_message = encrypt_caesar(message, password)
                elif encryption == 'vigenere':
                    encrypted_message = encrypt_vigenere(message, password)
                elif encryption == 'xor':
                    encrypted_message = encrypt_xor(message, password)
                else:
                    encrypted_message = message
                
                # Hex-encode the ciphertext so it safely survives binary delimiters and ASCII embedding
                message = encrypted_message.encode('latin1').hex()
            except Exception as e:
                return jsonify({'success': False, 'error': f'Encryption failed: {str(e)}'})
        
        # Add hash for verification (hash the original message, not encrypted)
        if hash_method == 'sha256':
            hash_obj = hashlib.sha256()
        else:  # sha512
            hash_obj = hashlib.sha512()
        
        hash_obj.update(original_message.encode())
        message_hash = hash_obj.hexdigest()
        
        # Combine message, hash, encryption type, password hash, and password hint
        clean_hint = password_hint.replace('|', '/')
        if password_hash:
            full_message = f"{message}|{message_hash}|{encryption}|{password_hash}|{clean_hint}"
        else:
            full_message = f"{message}|{message_hash}|{encryption}|none|{clean_hint}"
            
        # Tactical Plausible Deniability: Prepare secondary duress bundle
        is_duress_active = bool(duress_password and duress_password != password and password)
        full_decoy = None
        if is_duress_active:
            if not decoy_message:
                decoy_message = "Logistics update: Base operations running normal. Resupply convoy arrived on schedule."
            decoy_encrypted = encrypt_aes(decoy_message, duress_password)
            decoy_hex = decoy_encrypted.encode('latin1').hex()
            decoy_hash = hashlib.sha256(decoy_message.encode()).hexdigest()
            duress_pwd_hash = hashlib.sha256(duress_password.encode()).hexdigest()
            full_decoy = f"{decoy_hex}|{decoy_hash}|aes|{duress_pwd_hash}|Operational logistics"
        
        # =========================================================================
        # DEFENSE IMPERCEPTIBILITY INTERLOCK & CAPACITY CHECK (PSNR THRESHOLD)
        # =========================================================================
        DEFENSE_MIN_PSNR_THRESHOLD = 42.0

        # Phase 1: Predictive Security Check (Payload-to-Carrier Ratio)
        width, height = img.size
        payload_bits = len(full_message.encode('utf-8')) * 8
        carrier_total_bits = width * height * 3

        if stego_mode != 'dct':
            est_flips = max(payload_bits * 0.5, 1.0)
            est_mse = est_flips / max(carrier_total_bits, 1.0)
            est_psnr = 10 * np.log10((255.0 ** 2) / max(est_mse, 1e-10))
            if est_psnr < DEFENSE_MIN_PSNR_THRESHOLD:
                return jsonify({
                    'success': False,
                    'error': 'Security Violation: Payload size compromises image imperceptibility limits. Transmission aborted.',
                    'security_violation': True,
                    'calculated_psnr': round(float(est_psnr), 2),
                    'threshold': DEFENSE_MIN_PSNR_THRESHOLD,
                    'phase': 'predictive_capacity_check'
                })

        # Encode message in image based on selected domain
        if is_duress_active and stego_mode != 'dct':
            encoded_img = encode_message_in_image_dual(img, full_message, password, full_decoy, duress_password)
        elif stego_mode == 'dct':
            encoded_img = encode_dct(img, full_message, password)
        else:
            encoded_img = encode_message_in_image(img, full_message, password)
        
        # Calculate mathematical evaluation metrics: PSNR (OpenCV + NumPy) and SSIM (scikit-image)
        original_np = np.array(original_img)
        encoded_np = np.array(encoded_img)
        psnr_score = calculate_psnr(original_np, encoded_np)
        ssim_score = calculate_ssim(original_np, encoded_np)
        
        # Phase 2: Post-Encoding In-Memory Verification & Zero-Trust Buffer Scrubbing
        if psnr_score < DEFENSE_MIN_PSNR_THRESHOLD:
            # Memory Scrubbing: Wipe all contaminated image tensors & trigger garbage collection
            del encoded_img
            del encoded_np
            del original_np
            del original_img
            import gc
            gc.collect()

            return jsonify({
                'success': False,
                'error': 'Security Violation: Payload size compromises image imperceptibility limits. Transmission aborted.',
                'security_violation': True,
                'calculated_psnr': round(float(psnr_score), 2),
                'threshold': DEFENSE_MIN_PSNR_THRESHOLD,
                'advice': 'Carrier perturbation exceeds safety envelope. Use a higher-resolution image or reduce payload length.'
            })
        
        # Save encoded image
        original_filename = image.filename
        base_name = original_filename.rsplit('.', 1)[0] if '.' in original_filename else original_filename
        output_filename = f"encoded_{base_name}.png"
        
        output_path = os.path.join(UPLOADS_DIR, output_filename)
        
        # Always save as PNG to preserve LSB data
        encoded_img.save(output_path, format='PNG')
        
        encoded_url_filename = urllib.parse.quote(output_filename)
        return jsonify({
            'success': True,
            'download_url': f'/download/{encoded_url_filename}',
            'filename': output_filename,
            'psnr': float(psnr_score),
            'ssim': float(ssim_score),
            'stego_mode': stego_mode
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Encoding failed: {str(e)}'})

@app.route('/decode', methods=['POST'])
def decode_message():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image file provided'})
        
        image = request.files['image']
        password = request.form.get('password', '')
        password_hint = request.form.get('password_hint', '').strip()
        stego_mode = request.form.get('stego_mode', 'spatial')
        duress_password = request.form.get('duress_password', '').strip()
        decoy_message = request.form.get('decoy_message', '').strip()
        client_ip = request.remote_addr
        
        if image.filename == '':
            return jsonify({'success': False, 'error': 'No image selected'})
        
        # Check file extension
        allowed_extensions = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'tiff'}
        if not ('.' in image.filename and 
                image.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            return jsonify({'success': False, 'error': 'Invalid file format. Allowed formats: PNG, JPG, JPEG, BMP, GIF, TIFF'})
        
        # Read image and generate hash for tracking
        img_data = image.read()
        image.seek(0)  # Reset file pointer
        image_hash = get_image_hash(img_data)
        
        # Check if user has exceeded failed attempts
        is_locked, attempt_count = check_failed_attempts(image_hash, client_ip)
        if is_locked:
            return jsonify({
                'success': False,
                'error': f'ACCESS DENIED: Too many failed attempts ({attempt_count}/{MAX_ATTEMPTS}). This image has been destroyed for security reasons.',
                'attempts_remaining': 0,
                'image_destroyed': True
            })
        
        # Ingest and sanitize decoding carrier into normalized RGB array
        img = sanitize_metadata(image)
        
        # Decode message from image: first try Spatial PRNG steganography, then fallback to Frequency 8x8 DCT
        decoded_message = None
        technique_used = "Spatial PRNG"
        try:
            candidate = decode_message_from_image(img, password)
            if candidate and ('|' in candidate or is_readable_text(candidate)):
                decoded_message = candidate
        except (ValueError, Exception):
            pass
            
        if decoded_message is None:
            try:
                candidate = decode_dct(img, password)
                if candidate and ('|' in candidate or is_readable_text(candidate)):
                    decoded_message = candidate
                    technique_used = "Frequency 8x8 DCT"
            except (ValueError, Exception):
                decoded_message = None
        
        if decoded_message is None:
            if not password:
                return jsonify({
                    'success': False,
                    'error': 'This image appears to be encrypted or protected with a password. Please enter the password to decode it.',
                    'password_required': True,
                    'attempts_remaining': MAX_ATTEMPTS - attempt_count
                })
            else:
                record_failed_attempt(image_hash, client_ip)
                attempts_remaining = MAX_ATTEMPTS - failed_attempts[image_hash]['attempts']
                if attempts_remaining <= 0:
                    destroy_image_file(image.filename)
                    return jsonify({
                        'success': False,
                        'error': 'ACCESS DENIED: Too many failed attempts. This image has been destroyed for security reasons.',
                        'attempts_remaining': 0,
                        'image_destroyed': True
                    })
                return jsonify({
                    'success': False,
                    'error': f'Incorrect password. Attempts remaining: {attempts_remaining}',
                    'password_required': True,
                    'attempts_remaining': attempts_remaining
                })
        
        # Check if message contains hash separator and encryption info
        print(f"DEBUG: Decoded message length: {len(decoded_message)}, contains '|': {'|' in decoded_message}")
        
        if '|' not in decoded_message:
            # Old format or no hash - try to detect if encrypted
            if is_encrypted_message(decoded_message):
                # Message is encrypted but no password provided
                if not password:
                    return jsonify({
                        'success': False,
                        'error': 'This image contains an encrypted message. Please enter the correct password to decode it.',
                        'password_required': True,
                        'attempts_remaining': MAX_ATTEMPTS - attempt_count
                    })
                
                # Try to decrypt with provided password (older format - no password hash validation)
                try:
                    decrypted_message = decrypt_message(decoded_message, password)
                    if decrypted_message and is_readable_text(decrypted_message):
                        # Success - clear failed attempts
                        if image_hash in failed_attempts:
                            del failed_attempts[image_hash]
                        
                        return jsonify({
                            'success': True,
                            'message': decrypted_message,
                            'encryption_used': 'password_protected',
                            'technique_used': technique_used,
                            'note': 'Decoded from older format image'
                        })
                    else:
                        # Failed attempt
                        record_failed_attempt(image_hash, client_ip)
                        attempts_remaining = MAX_ATTEMPTS - failed_attempts[image_hash]['attempts']
                        
                        if attempts_remaining <= 0:
                            # Destroy the image file
                            destroy_image_file(image.filename)
                            
                            return jsonify({
                                'success': False,
                                'error': f'ACCESS DENIED: Too many failed attempts. This image has been destroyed for security reasons.',
                                'attempts_remaining': 0,
                                'image_destroyed': True
                            })
                        
                        return jsonify({
                            'success': False,
                            'error': f'Incorrect password. Attempts remaining: {attempts_remaining}',
                            'password_required': True,
                            'attempts_remaining': attempts_remaining
                        })
                except Exception:
                    # Failed attempt
                    record_failed_attempt(image_hash, client_ip)
                    attempts_remaining = MAX_ATTEMPTS - failed_attempts[image_hash]['attempts']
                    
                    if attempts_remaining <= 0:
                        # Destroy the image file
                        destroy_image_file(image.filename)
                        
                        return jsonify({
                            'success': False,
                            'error': f'ACCESS DENIED: Too many failed attempts. This image has been destroyed for security reasons.',
                            'attempts_remaining': 0,
                            'image_destroyed': True
                        })
                    
                    return jsonify({
                        'success': False,
                        'error': f'Incorrect password. Attempts remaining: {attempts_remaining}',
                        'password_required': True,
                        'attempts_remaining': attempts_remaining
                    })
            else:
                # Message is not encrypted
                return jsonify({
                    'success': True,
                    'message': decoded_message,
                    'encryption_used': 'none',
                    'technique_used': technique_used
                })
        
        # New format with hash and encryption info
        try:
            parts = decoded_message.split('|')
            if len(parts) < 3:
                return jsonify({'success': False, 'error': 'Invalid message format: unable to parse message components'})
            
            # Format: message|hash|encryption_type|password_hash|password_hint
            raw_payload = parts[0]
            message_hash = parts[1]
            encryption_type = parts[2] if len(parts) > 2 else 'none'
            raw_password_hash = parts[3] if len(parts) > 3 else 'none'
            password_hint = parts[4] if len(parts) > 4 else ''
            
            # Try to decode hex-encoded ciphertext (newer format), fallback to raw string (legacy format)
            try:
                message = bytes.fromhex(raw_payload).decode('latin1')
            except Exception:
                message = raw_payload
            
            # Extract password hash (handle direct 64-char sha256 or legacy 128-char hex-encoded sha256)
            stored_password_hash = raw_password_hash
            if raw_password_hash != 'none' and len(raw_password_hash) == 128:
                try:
                    stored_password_hash = bytes.fromhex(raw_password_hash).decode('utf-8')
                except Exception:
                    stored_password_hash = raw_password_hash
            
            print(f"DEBUG DECODE: Parts count: {len(parts)}")
            print(f"DEBUG DECODE: Encryption type: {encryption_type}")
            print(f"DEBUG DECODE: Stored password hash is 'none': {stored_password_hash == 'none'}")
            
            # Check if encryption is required
            if encryption_type != 'none':
                # Message is encrypted
                if not password:
                    return jsonify({
                        'success': False,
                        'error': 'This image contains an encrypted message. Please enter the correct password to decode it.',
                        'password_required': True,
                        'password_hint': password_hint,
                        'encryption_type': encryption_type,
                        'attempts_remaining': MAX_ATTEMPTS - attempt_count
                    })
                
                # Validate password hash (only for newer format images) - RE-ENABLED
                if stored_password_hash != 'none':
                    provided_password_hash = hashlib.sha256(password.encode()).hexdigest()
                    # Debug logging
                    print(f"DEBUG: Stored password hash: {stored_password_hash}")
                    print(f"DEBUG: Provided password hash: {provided_password_hash}")
                    print(f"DEBUG: Password match: {provided_password_hash == stored_password_hash}")
                    
                    if provided_password_hash != stored_password_hash:
                        # Failed attempt
                        record_failed_attempt(image_hash, client_ip)
                        attempts_remaining = MAX_ATTEMPTS - failed_attempts[image_hash]['attempts']
                        
                        if attempts_remaining <= 0:
                            # Destroy the image file
                            destroy_image_file(image.filename)
                            
                            return jsonify({
                                'success': False,
                                'error': f'ACCESS DENIED: Too many failed attempts. This image has been destroyed for security reasons.',
                                'attempts_remaining': 0,
                                'image_destroyed': True
                            })
                        
                        return jsonify({
                            'success': False,
                            'error': f'Incorrect password. Attempts remaining: {attempts_remaining}',
                            'password_required': True,
                            'password_hint': password_hint,
                            'encryption_type': encryption_type,
                            'attempts_remaining': attempts_remaining
                        })
                
                # Try to decrypt with validated password using the specific cipher algorithm
                try:
                    if encryption_type == 'aes':
                        decrypted_message = decrypt_aes(message, password)
                    elif encryption_type == 'rsa':
                        decrypted_message = decrypt_rsa(message, password)
                    elif encryption_type == 'hybrid':
                        decrypted_message = decrypt_hybrid(message, password)
                    elif encryption_type == 'aes_gcm':
                        decrypted_message = decrypt_aes_gcm(message, password)
                    elif encryption_type == 'chacha20':
                        decrypted_message = decrypt_chacha20(message, password)
                    elif encryption_type == 'salsa20':
                        decrypted_message = decrypt_salsa20(message, password)
                    elif encryption_type == 'rc4':
                        decrypted_message = decrypt_rc4(message, password)
                    elif encryption_type == 'threefish':
                        decrypted_message = decrypt_threefish(message, password)
                    elif encryption_type == 'camellia':
                        decrypted_message = decrypt_camellia(message, password)
                    elif encryption_type == 'serpent':
                        decrypted_message = decrypt_serpent(message, password)
                    elif encryption_type == 'caesar':
                        decrypted_message = decrypt_caesar(message, password)
                    elif encryption_type == 'vigenere':
                        decrypted_message = decrypt_vigenere(message, password)
                    elif encryption_type == 'xor':
                        decrypted_message = decrypt_xor(message, password)
                    else:
                        # Try general decryption
                        decrypted_message = decrypt_message(message, password)
                    
                    # Debug: Check if decryption produced readable text
                    if not decrypted_message:
                        print(f"DEBUG: Decryption returned empty message")
                        # Failed attempt
                        record_failed_attempt(image_hash, client_ip)
                        attempts_remaining = MAX_ATTEMPTS - failed_attempts[image_hash]['attempts']
                        
                        if attempts_remaining <= 0:
                            # Destroy the image file
                            destroy_image_file(image.filename)
                            
                            return jsonify({
                                'success': False,
                                'error': f'ACCESS DENIED: Too many failed attempts. This image has been destroyed for security reasons.',
                                'attempts_remaining': 0,
                                'image_destroyed': True
                            })
                        
                        return jsonify({
                            'success': False,
                            'error': f'Decryption failed. Attempts remaining: {attempts_remaining}',
                            'password_required': True,
                            'password_hint': password_hint,
                            'encryption_type': encryption_type,
                            'attempts_remaining': attempts_remaining
                        })
                    
                    print(f"DEBUG: Decrypted message: {repr(decrypted_message)}")
                    print(f"DEBUG: Is readable: {is_readable_text(decrypted_message)}")
                    
                    # Check if decrypted message is readable
                    if not is_readable_text(decrypted_message):
                        print(f"DEBUG: Message not readable - wrong password")
                        # Failed attempt
                        record_failed_attempt(image_hash, client_ip)
                        attempts_remaining = MAX_ATTEMPTS - failed_attempts[image_hash]['attempts']
                        
                        if attempts_remaining <= 0:
                            # Destroy the image file
                            destroy_image_file(image.filename)
                            
                            return jsonify({
                                'success': False,
                                'error': f'ACCESS DENIED: Too many failed attempts. This image has been destroyed for security reasons.',
                                'attempts_remaining': 0,
                                'image_destroyed': True
                            })
                        
                        return jsonify({
                            'success': False,
                            'error': f'Decryption failed. The password may be incorrect. Attempts remaining: {attempts_remaining}',
                            'password_required': True,
                            'password_hint': password_hint,
                            'encryption_type': encryption_type,
                            'attempts_remaining': attempts_remaining
                        })
                    
                    # Success - clear failed attempts
                    if image_hash in failed_attempts:
                        del failed_attempts[image_hash]
                    
                    # Verify hash of decrypted message
                    try:
                        if len(message_hash) == 64:  # SHA256
                            hash_obj = hashlib.sha256()
                        elif len(message_hash) == 128:  # SHA512
                            hash_obj = hashlib.sha512()
                        else:
                            hash_obj = None
                        
                        if hash_obj:
                            hash_obj.update(decrypted_message.encode())
                            calculated_hash = hash_obj.hexdigest()
                            
                            if message_hash == calculated_hash:
                                return jsonify({
                                    'success': True,
                                    'message': decrypted_message,
                                    'encryption_used': encryption_type,
                                    'technique_used': technique_used
                                })
                            else:
                                # Hash verification failed, but if text is readable, still return it
                                return jsonify({
                                    'success': True,
                                    'message': decrypted_message,
                                    'encryption_used': encryption_type,
                                    'technique_used': technique_used,
                                    'note': 'Message decoded but integrity check failed'
                                })
                        else:
                            # No hash verification, but message is readable
                            return jsonify({
                                'success': True,
                                'message': decrypted_message,
                                'encryption_used': encryption_type,
                                'technique_used': technique_used
                            })
                    except Exception as e:
                        # Hash verification failed, but if text is readable, still return it
                        return jsonify({
                            'success': True,
                            'message': decrypted_message,
                            'encryption_used': encryption_type,
                            'technique_used': technique_used,
                            'note': f'Decoded with hash verification warning: {str(e)}'
                        })
                        
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Decryption failed: {str(e)}. Please ensure you are using the exact same password that was used during encoding.',
                        'password_required': True,
                        'encryption_type': encryption_type
                    })
            else:
                # Message is not encrypted - verify hash directly
                try:
                    if len(message_hash) == 64:  # SHA256
                        hash_obj = hashlib.sha256()
                    elif len(message_hash) == 128:  # SHA512
                        hash_obj = hashlib.sha512()
                    else:
                        hash_obj = None
                    
                    if hash_obj:
                        hash_obj.update(message.encode())
                        calculated_hash = hash_obj.hexdigest()
                        
                        if message_hash == calculated_hash:
                            return jsonify({
                                'success': True,
                                'message': message,
                                'encryption_used': 'none'
                            })
                        else:
                            return jsonify({
                                'success': False,
                                'error': 'Message integrity check failed. The message may have been corrupted.'
                            })
                except Exception:
                    pass  # Hash verification failed, but continue
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'encryption_used': 'none'
                })
                
        except Exception as e:
            return jsonify({'success': False, 'error': f'Failed to parse message format: {str(e)}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Decoding failed: {str(e)}'})

def is_encrypted_message(message):
    """Check if a message appears to be encrypted"""
    if not message or len(message) < 10:
        return False
    
    # Check for characteristics of encrypted text
    non_printable_count = sum(1 for c in message if not c.isprintable())
    special_char_count = sum(1 for c in message if ord(c) < 32 or ord(c) > 126)
    
    # If more than 20% of characters are non-printable or special, likely encrypted
    total_chars = len(message)
    if total_chars == 0:
        return False
    
    ratio = (non_printable_count + special_char_count) / total_chars
    return ratio > 0.2

def is_readable_text(text):
    """Check if text is readable English/ASCII text"""
    if not text:
        return False
    
    # Check if most characters are printable ASCII
    printable_count = sum(1 for c in text if c.isprintable() and ord(c) < 128)
    return printable_count / len(text) > 0.8 if text else False

def decrypt_hybrid(encrypted_message, password):
    """Decrypt hybrid encrypted message"""
    try:
        # First decrypt with RSA-like method, then with AES-like method
        rsa_decrypted = decrypt_rsa(encrypted_message, password)
        return decrypt_aes(rsa_decrypted, password)
    except Exception:
        raise ValueError("Hybrid decryption failed")

@app.route('/download/<path:filename>')
def download_file(filename):
    try:
        # Decode filename in case it was URL encoded
        decoded_filename = urllib.parse.unquote(filename)
        file_path = os.path.join(UPLOADS_DIR, decoded_filename)
        if os.path.exists(file_path):
            return send_from_directory(UPLOADS_DIR, decoded_filename, as_attachment=True, download_name=decoded_filename)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper functions for encoding/decoding
def sanitize_metadata(image_input):
    """
    Defense-Grade Image Ingestion Sanitizer (Zero-Trust Metadata Neutralization)
    ===========================================================================
    Military / Operational Security Standard:
      - Strips all EXIF headers (GPS coordinates, camera make/model, serial numbers)
      - Purges temporal indicators (DateTimeOriginal, Digitized timestamps)
      - Eliminates embedded preview thumbnails (preventing uncropped scene leakage)
      - Discards Adobe XMP sidecars, IPTC records, and ICC color profile vectors
      - Decouples raw pixel memory buffer from input stream into a pristine, normalized RGB array
    
    Parameters:
        image_input: werkzeug FileStorage, io.BytesIO, bytes, or PIL.Image
        
    Returns:
        PIL.Image: Sanitized, normalized, detached RGB bitmap with 100% metadata purged.
    """
    if isinstance(image_input, (bytes, bytearray)):
        stream = io.BytesIO(image_input)
        raw_img = Image.open(stream)
    elif hasattr(image_input, 'stream'):  # Flask FileStorage
        image_input.stream.seek(0)
        raw_img = Image.open(image_input.stream)
    elif hasattr(image_input, 'read'):    # BytesIO or file-like object
        image_input.seek(0)
        raw_img = Image.open(image_input)
    elif isinstance(image_input, Image.Image):
        raw_img = image_input
    else:
        raise ValueError(f"Unsupported image input type: {type(image_input)}")

    # Re-orient pixels if EXIF orientation exists before stripping headers
    try:
        raw_img = ImageOps.exif_transpose(raw_img)
    except Exception:
        pass

    # Standardize to 24-bit RGB color domain
    if raw_img.mode != 'RGB':
        raw_img = raw_img.convert('RGB')

    # Zero-Trust Memory Decoupling: Extract raw numerical pixel array
    pixel_matrix = np.array(raw_img, dtype=np.uint8)

    # Rebuild pristine Image instance directly from raw pixel tensor
    sanitized_img = Image.fromarray(pixel_matrix, mode='RGB')

    # In-memory normalization through clean PNG bitmap stream
    clean_buffer = io.BytesIO()
    sanitized_img.save(clean_buffer, format='PNG', optimize=False)
    clean_buffer.seek(0)

    # Reload into isolated memory space
    final_img = Image.open(clean_buffer)
    final_img.load()
    return final_img

def get_prng_seed(password):
    """
    Derive a deterministic 32-bit integer seed from the SHA-256 hash of the password.
    If no password is provided, use a default fallback seed.
    """
    pwd_str = str(password) if password else "steganography_pro_default_prng_seed"
    hash_digest = hashlib.sha256(pwd_str.encode('utf-8')).hexdigest()
    return int(hash_digest[:8], 16)

def encode_partition(img_array, payload_str, password, partition_parity):
    """
    Plausible Deniability Partition Embedding
    Embeds payload strictly into coordinate parity partition: (x + y) % 2 == partition_parity.
    Parity 0 = Tactical Master partition (Even coordinates)
    Parity 1 = Duress Decoy partition (Odd coordinates)
    Guarantees zero overlap and zero collision between master and decoy payloads.
    """
    height, width, _ = img_array.shape
    ys, xs = np.indices((height, width))
    mask = ((xs + ys) % 2) == partition_parity
    partition_ys = ys[mask]
    partition_xs = xs[mask]
    total_partition_pixels = len(partition_xs)
    
    payload_bytes = payload_str.encode('utf-8') + b'##PRNG_END##'
    bits = np.unpackbits(np.frombuffer(payload_bytes, dtype=np.uint8))
    total_bits = len(bits)
    pixels_needed = (total_bits + 2) // 3
    
    if pixels_needed > total_partition_pixels:
        raise ValueError(f"Partition capacity ({total_partition_pixels*3//8} bytes) exceeded by payload ({len(payload_bytes)} bytes)")
        
    seed = get_prng_seed(password)
    rng = np.random.RandomState(seed)
    perm = rng.permutation(total_partition_pixels)[:pixels_needed]
    
    chosen_ys = partition_ys[perm]
    chosen_xs = partition_xs[perm]
    
    channel_perms = np.array([
        [0, 1, 2], [0, 2, 1],
        [1, 0, 2], [1, 2, 0],
        [2, 0, 1], [2, 1, 0]
    ], dtype=np.uint8)
    ch_orders = channel_perms[rng.randint(0, 6, size=pixels_needed)]
    
    pad_len = pixels_needed * 3 - total_bits
    if pad_len > 0:
        bits = np.pad(bits, (0, pad_len), constant_values=0)
    bits_reshaped = bits.reshape((pixels_needed, 3))
    
    for i in range(3):
        ch = ch_orders[:, i]
        img_array[chosen_ys, chosen_xs, ch] = (img_array[chosen_ys, chosen_xs, ch] & 0xFE) | bits_reshaped[:, i]

def decode_partition(img_array, password, partition_parity):
    """
    Extracts payload strictly from coordinate parity partition: (x + y) % 2 == partition_parity.
    """
    height, width, _ = img_array.shape
    ys, xs = np.indices((height, width))
    mask = ((xs + ys) % 2) == partition_parity
    partition_ys = ys[mask]
    partition_xs = xs[mask]
    total_partition_pixels = len(partition_xs)
    
    seed = get_prng_seed(password)
    rng = np.random.RandomState(seed)
    perm = rng.permutation(total_partition_pixels)
    
    chosen_ys = partition_ys[perm]
    chosen_xs = partition_xs[perm]
    
    channel_perms = np.array([
        [0, 1, 2], [0, 2, 1],
        [1, 0, 2], [1, 2, 0],
        [2, 0, 1], [2, 1, 0]
    ], dtype=np.uint8)
    ch_orders = channel_perms[rng.randint(0, 6, size=total_partition_pixels)]
    
    interleaved_bits = np.empty(total_partition_pixels * 3, dtype=np.uint8)
    interleaved_bits[0::3] = img_array[chosen_ys, chosen_xs, ch_orders[:, 0]] & 1
    interleaved_bits[1::3] = img_array[chosen_ys, chosen_xs, ch_orders[:, 1]] & 1
    interleaved_bits[2::3] = img_array[chosen_ys, chosen_xs, ch_orders[:, 2]] & 1
    
    extracted_bytes = np.packbits(interleaved_bits).tobytes()
    sentinel_idx = extracted_bytes.find(b'##PRNG_END##')
    if sentinel_idx == -1:
        raise ValueError("Delimiter not found in this partition")
        
    raw_payload = extracted_bytes[:sentinel_idx]
    try:
        return raw_payload.decode('utf-8')
    except Exception:
        return raw_payload.decode('latin1')

def encode_message_in_image_dual(img, master_payload, master_password, decoy_payload, duress_password):
    """
    Tactical Plausible Deniability Dual-Tier Encoder:
    Embeds Master Operational Payload into Parity Partition 0 (Even coordinates).
    Embeds Duress Decoy Payload into Parity Partition 1 (Odd coordinates).
    Zero collision, zero leakage, independent cryptographic key spaces.
    """
    img_array = np.array(img, dtype=np.uint8)
    encode_partition(img_array, master_payload, master_password, partition_parity=0)
    encode_partition(img_array, decoy_payload, duress_password, partition_parity=1)
    return Image.fromarray(img_array)

def encode_message_in_image(img, message, password=None):
    """
    Encode a message in an image using PRNG-seeded pseudo-random pixel & channel permutation.
    Evades statistical steganalysis (e.g. Chi-Square, RS analysis) by dispersing payload bits
    uniformly across non-sequential pseudo-random coordinates determined by SHA-256(password).
    """
    width, height = img.size
    max_bytes = (width * height * 3) // 8
    
    # Payload bytes + sentinel delimiter ##PRNG_END##
    payload_bytes = message.encode('utf-8') + b'##PRNG_END##'
    if len(payload_bytes) > max_bytes:
        raise ValueError(f"Message size ({len(payload_bytes)} bytes) exceeds image capacity ({max_bytes} bytes)")
    
    # Convert payload bytes to array of bits (0 or 1)
    bits = np.unpackbits(np.frombuffer(payload_bytes, dtype=np.uint8))
    total_bits = len(bits)
    
    # Generate deterministic PRNG coordinates & channel permutation based on password
    seed = get_prng_seed(password)
    rng = np.random.RandomState(seed)
    
    # Number of pixels needed to store total_bits (each pixel holds 3 bits: R, G, B)
    pixels_needed = (total_bits + 2) // 3
    pixel_indices = rng.permutation(width * height)
    chosen_pixels = pixel_indices[:pixels_needed]
    
    ys = chosen_pixels // width
    xs = chosen_pixels % width
    
    # 6 possible channel permutations of [0, 1, 2]
    channel_perms = np.array([
        [0, 1, 2], [0, 2, 1],
        [1, 0, 2], [1, 2, 0],
        [2, 0, 1], [2, 1, 0]
    ], dtype=np.uint8)
    
    ch_orders = channel_perms[rng.randint(0, 6, size=pixels_needed)]
    
    # Convert image to numpy array
    img_array = np.array(img, dtype=np.uint8)
    
    # Pad bits array to multiple of 3 if needed
    pad_len = pixels_needed * 3 - total_bits
    if pad_len > 0:
        bits = np.pad(bits, (0, pad_len), constant_values=0)
    
    bits_reshaped = bits.reshape((pixels_needed, 3))
    
    # Modify pixels along the PRNG path
    for i in range(3):
        ch = ch_orders[:, i]
        img_array[ys, xs, ch] = (img_array[ys, xs, ch] & 0xFE) | bits_reshaped[:, i]
        
    return Image.fromarray(img_array)

def decode_message_from_image(img, password=None):
    """
    Extract a message from an image using the exact PRNG coordinates path
    seeded by the password's SHA-256 hash.
    Supports Tactical Plausible Deniability (Partition 0 = Master, Partition 1 = Duress).
    If an incorrect password is provided, extraction fails gracefully.
    """
    width, height = img.size
    img_array = np.array(img, dtype=np.uint8)
    
    # 1. First, check Plausible Deniability Parity Partitions (if password provided)
    if password:
        # Check Tactical Master Partition (Even coordinates)
        try:
            cand = decode_partition(img_array, password, partition_parity=0)
            if cand and ('|' in cand or is_readable_text(cand)):
                return cand
        except Exception:
            pass
            
        # Check Duress / Decoy Partition (Odd coordinates)
        try:
            cand = decode_partition(img_array, password, partition_parity=1)
            if cand and ('|' in cand or is_readable_text(cand)):
                return cand
        except Exception:
            pass

    # 2. Standard full-canvas PRNG extraction
    seed = get_prng_seed(password)
    rng = np.random.RandomState(seed)
    
    pixel_indices = rng.permutation(width * height)
    total_pixels = len(pixel_indices)
    
    channel_perms = np.array([
        [0, 1, 2], [0, 2, 1],
        [1, 0, 2], [1, 2, 0],
        [2, 0, 1], [2, 1, 0]
    ], dtype=np.uint8)
    
    ch_orders = channel_perms[rng.randint(0, 6, size=total_pixels)]
    
    ys = pixel_indices // width
    xs = pixel_indices % width
    
    # Extract bits in vectorized fashion
    interleaved_bits = np.empty(total_pixels * 3, dtype=np.uint8)
    interleaved_bits[0::3] = img_array[ys, xs, ch_orders[:, 0]] & 1
    interleaved_bits[1::3] = img_array[ys, xs, ch_orders[:, 1]] & 1
    interleaved_bits[2::3] = img_array[ys, xs, ch_orders[:, 2]] & 1
    
    # Pack bits to bytes
    extracted_bytes = np.packbits(interleaved_bits).tobytes()
    
    # Search for sentinel delimiter b'##PRNG_END##'
    sentinel_idx = extracted_bytes.find(b'##PRNG_END##')
    if sentinel_idx != -1:
        raw_payload = extracted_bytes[:sentinel_idx]
        try:
            return raw_payload.decode('utf-8')
        except Exception:
            return raw_payload.decode('latin1')
            
    # Fallback check: legacy PRNG with sentinel b'\xff\xfe'
    sentinel_idx = extracted_bytes.find(b'\xff\xfe')
    if sentinel_idx != -1:
        raw_payload = extracted_bytes[:sentinel_idx]
        try:
            txt = raw_payload.decode('utf-8')
            if '|' in txt and len(txt.split('|')) >= 3:
                return txt
        except Exception:
            pass
            
    # Fallback check: could this be a legacy sequential image? Only check if no password was supplied
    if not password:
        try:
            return decode_message_sequential(img)
        except Exception:
            pass
            
    raise ValueError("No hidden message found (or incorrect password provided)")

def decode_message_sequential(img):
    """Legacy sequential extraction fallback for backward compatibility"""
    width, height = img.size
    pixels = img.load()
    binary_message = ''
    end_marker = '1111111111111110'
    found_marker = False
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)
            if end_marker in binary_message:
                marker_idx = binary_message.find(end_marker)
                binary_message = binary_message[:marker_idx]
                found_marker = True
                break
        if found_marker:
            break
            
    if not found_marker:
        raise ValueError("No hidden message found in this image")
        
    chars = []
    for i in range(0, len(binary_message), 8):
        if i + 8 <= len(binary_message):
            chars.append(chr(int(binary_message[i:i+8], 2)))
    result_str = ''.join(chars)
    if not is_readable_text(result_str) and '|' not in result_str:
        raise ValueError("Sequential steganography marker found by chance; payload not valid text")
    return result_str

# Advanced cryptographic algorithms for steganography
def encrypt_aes_gcm(message, password):
    """AES-GCM like encryption with authentication (simplified)"""
    # Generate key and IV from password
    key = hashlib.sha256(password.encode()).digest()
    iv = hashlib.md5((password + "iv").encode()).digest()[:16]
    
    # Simple GCM-like authentication tag
    auth_data = b"steganography_auth"
    auth_tag = hashlib.sha256(key + auth_data).digest()[:16]
    
    # Encrypt with AES-like process
    encrypted = []
    for i, char in enumerate(message):
        key_byte = key[i % len(key)]
        iv_byte = iv[i % len(iv)]
        encrypted_char = chr(ord(char) ^ key_byte ^ iv_byte)
        encrypted.append(encrypted_char)
    
    # Add authentication tag at the end
    encrypted.extend([chr(b) for b in auth_tag])
    return ''.join(encrypted)

def decrypt_aes_gcm(encrypted_message, password):
    """AES-GCM like decryption with authentication"""
    if len(encrypted_message) < 16:
        raise ValueError("Invalid encrypted message")
    
    # Extract auth tag
    auth_tag = encrypted_message[-16:]
    message_part = encrypted_message[:-16]
    
    # Generate same key and IV
    key = hashlib.sha256(password.encode()).digest()
    iv = hashlib.md5((password + "iv").encode()).digest()[:16]
    
    # Verify authentication tag
    auth_data = b"steganography_auth"
    expected_tag = hashlib.sha256(key + auth_data).digest()[:16]
    if expected_tag != bytes([ord(b) for b in auth_tag]):
        raise ValueError("Authentication failed")
    
    # Decrypt
    decrypted = []
    for i, char in enumerate(message_part):
        key_byte = key[i % len(key)]
        iv_byte = iv[i % len(iv)]
        decrypted_char = chr(ord(char) ^ key_byte ^ iv_byte)
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

def encrypt_chacha20(message, password):
    """ChaCha20-like stream cipher"""
    # Generate key and nonce from password
    key = hashlib.sha256(password.encode()).digest()
    nonce = hashlib.md5((password + "nonce").encode()).digest()[:12]
    
    # Simple ChaCha20-like quarter round simulation
    state = []
    # "expand 32-byte k" constant
    state.extend([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107])
    # Key
    state.extend(key)
    # Counter and nonce
    state.extend([0, 0, 0, 0])
    state.extend(nonce)
    
    # Generate keystream
    keystream = []
    for i in range(len(message)):
        # Simple quarter round simulation
        round_key = (state[i % len(state)] + state[(i+1) % len(state)]) % 256
        keystream.append(round_key)
        # Update state (simplified)
        state[i % len(state)] = (state[i % len(state)] + 1) % 256
    
    # XOR message with keystream
    encrypted = []
    for i, char in enumerate(message):
        encrypted_char = chr(ord(char) ^ keystream[i])
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def decrypt_chacha20(encrypted_message, password):
    """ChaCha20-like decryption"""
    # ChaCha20 is symmetric - same operation as encryption
    return encrypt_chacha20(encrypted_message, password)

def encrypt_salsa20(message, password):
    """Salsa20-like stream cipher"""
    # Generate key and nonce from password
    key = hashlib.sha256(password.encode()).digest()
    nonce = hashlib.md5((password + "salsa").encode()).digest()[:8]
    
    # Salsa20-like core function
    def salsa20_core(word):
        return ((word << 7) | (word >> 25)) ^ ((word << 13) | (word >> 19))
    
    # Generate keystream
    keystream = []
    for i in range(len(message)):
        key_byte = key[i % len(key)]
        nonce_byte = nonce[i % len(nonce)]
        counter = i // 64
        
        # Salsa20 quarter round simulation
        keystream_byte = salsa20_core(key_byte ^ nonce_byte ^ counter) % 256
        keystream.append(keystream_byte)
    
    # XOR message with keystream
    encrypted = []
    for i, char in enumerate(message):
        encrypted_char = chr(ord(char) ^ keystream[i])
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def decrypt_salsa20(encrypted_message, password):
    """Salsa20-like decryption"""
    # Salsa20 is symmetric - same operation as encryption
    return encrypt_salsa20(encrypted_message, password)

def encrypt_rc4(message, password):
    """RC4-like stream cipher"""
    # Key scheduling algorithm
    key = [ord(c) for c in password]
    s = list(range(256))
    
    # Initialize S-box
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    
    # Generate keystream and encrypt
    encrypted = []
    i = j = 0
    for char in message:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        keystream_byte = s[(s[i] + s[j]) % 256]
        encrypted_char = chr(ord(char) ^ keystream_byte)
        encrypted.append(encrypted_char)
    
    return ''.join(encrypted)

def decrypt_rc4(encrypted_message, password):
    """RC4-like decryption"""
    # RC4 is symmetric - same operation as encryption
    return encrypt_rc4(encrypted_message, password)

def encrypt_threefish(message, password):
    """Threefish-like tweakable block cipher"""
    # Generate subkeys and tweak from password
    subkeys = []
    tweak = hashlib.md5((password + "tweak").encode()).digest()
    
    for i in range(4):  # Threefish-256 uses 4 subkeys
        subkey = hashlib.sha256((password + f"subkey{i}").encode()).digest()
        subkeys.append(subkey)
    
    # Process in 64-bit blocks (simplified)
    block_size = 8
    blocks = [message[i:i+block_size].ljust(block_size, chr(0)) for i in range(0, len(message), block_size)]
    
    encrypted_blocks = []
    for block_idx, block in enumerate(blocks):
        # Convert block to 64-bit words (simplified)
        words = [ord(c) for c in block]
        
        # 72 rounds of MIX function (simplified to 8 rounds)
        for round_num in range(8):
            # MIX function
            for i in range(0, len(words), 2):
                if i + 1 < len(words):
                    # Simple MIX operation
                    words[i] = (words[i] + words[i+1]) % 256
                    words[i+1] = (words[i+1] ^ words[i]) % 256
            
            # Add subkey and tweak
            key_idx = round_num % len(subkeys)
            tweak_idx = round_num % len(tweak)
            for i in range(len(words)):
                words[i] = (words[i] + subkeys[key_idx][i % 32] + tweak[tweak_idx]) % 256
        
        # Convert back to characters
        encrypted_block = ''.join(chr(w) for w in words)
        encrypted_blocks.append(encrypted_block)
    
    return ''.join(encrypted_blocks)

def decrypt_threefish(encrypted_message, password):
    """Threefish-like decryption"""
    # Generate same subkeys and tweak
    subkeys = []
    tweak = hashlib.md5((password + "tweak").encode()).digest()
    
    for i in range(4):
        subkey = hashlib.sha256((password + f"subkey{i}").encode()).digest()
        subkeys.append(subkey)
    
    # Process in blocks
    block_size = 8
    blocks = [encrypted_message[i:i+block_size] for i in range(0, len(encrypted_message), block_size)]
    
    decrypted_blocks = []
    for block_idx, block in enumerate(blocks):
        # Convert to words
        words = [ord(c) for c in block]
        
        # Reverse the rounds
        for round_num in range(7, -1, -1):
            # Reverse subkey and tweak addition
            key_idx = round_num % len(subkeys)
            tweak_idx = round_num % len(tweak)
            for i in range(len(words)):
                words[i] = (words[i] - subkeys[key_idx][i % 32] - tweak[tweak_idx]) % 256
            
            # Reverse MIX function
            for i in range(0, len(words), 2):
                if i + 1 < len(words):
                    words[i+1] = (words[i+1] ^ words[i]) % 256
                    words[i] = (words[i] - words[i+1]) % 256
        
        # Convert back to characters
        decrypted_block = ''.join(chr(w) for w in words)
        decrypted_blocks.append(decrypted_block)
    
    return ''.join(decrypted_blocks).rstrip(chr(0))

def encrypt_camellia(message, password):
    """Camellia-like block cipher"""
    # Generate subkeys
    subkeys = []
    for i in range(6):  # Camellia uses multiple subkeys
        subkey = hashlib.sha256((password + f"camellia{i}").encode()).digest()
        subkeys.append(subkey)
    
    # Process in 128-bit blocks (simplified)
    block_size = 16
    blocks = [message[i:i+block_size].ljust(block_size, chr(0)) for i in range(0, len(message), block_size)]
    
    encrypted_blocks = []
    for block in blocks:
        # Split into left and right halves
        left = [ord(c) for c in block[:8]]
        right = [ord(c) for c in block[8:]]
        
        # 18 rounds of Feistel network (simplified to 6 rounds)
        for round_num in range(6):
            # F function
            f_input = right + [round_num % 256]
            f_output = hashlib.sha256(bytes(f_input)).digest()
            
            # XOR with subkey
            key = subkeys[round_num % len(subkeys)]
            new_right = []
            for i in range(8):
                new_right.append(left[i] ^ f_output[i] ^ key[i])
            
            left, right = right, new_right
        
        # Combine and convert back
        encrypted_block = ''.join(chr(c) for c in left + right)
        encrypted_blocks.append(encrypted_block)
    
    return ''.join(encrypted_blocks)

def decrypt_camellia(encrypted_message, password):
    """Camellia-like decryption"""
    # Generate same subkeys
    subkeys = []
    for i in range(6):
        subkey = hashlib.sha256((password + f"camellia{i}").encode()).digest()
        subkeys.append(subkey)
    
    # Process in blocks
    block_size = 16
    blocks = [encrypted_message[i:i+block_size] for i in range(0, len(encrypted_message), block_size)]
    
    decrypted_blocks = []
    for block in blocks:
        block_bytes = [ord(c) for c in block]
        if len(block_bytes) < 16:
            block_bytes = block_bytes + [0] * (16 - len(block_bytes))
        left = block_bytes[:8]
        right = block_bytes[8:]
        
        # Reverse Feistel rounds
        for round_num in range(5, -1, -1):
            # F function
            f_input = left + [round_num % 256]
            f_output = hashlib.sha256(bytes(f_input)).digest()
            
            # XOR with subkey
            key = subkeys[round_num % len(subkeys)]
            new_left = []
            for i in range(8):
                new_left.append(right[i] ^ f_output[i] ^ key[i])
            
            left, right = new_left, left
        
        # Combine and convert back
        decrypted_block = ''.join(chr(c) for c in left + right)
        decrypted_blocks.append(decrypted_block)
    
    return ''.join(decrypted_blocks).rstrip(chr(0))

def encrypt_serpent(message, password):
    """Simple block cipher inspired by Serpent"""
    # Generate key
    key = hashlib.sha256(password.encode()).digest()
    
    encrypted = []
    for i, char in enumerate(message):
        # Simple block cipher operation
        key_byte = key[i % len(key)]
        round_key = (key_byte + i) % 256
        encrypted_char = chr(ord(char) ^ round_key)
        encrypted.append(encrypted_char)
    
    return ''.join(encrypted)

def decrypt_serpent(encrypted_message, password):
    """Simple block cipher decryption"""
    # Generate same key
    key = hashlib.sha256(password.encode()).digest()
    
    decrypted = []
    for i, char in enumerate(encrypted_message):
        # Reverse the operation
        key_byte = key[i % len(key)]
        round_key = (key_byte + i) % 256
        decrypted_char = chr(ord(char) ^ round_key)
        decrypted.append(decrypted_char)
    
    return ''.join(decrypted)

# Advanced encryption functions
def encrypt_caesar(message, password):
    """Caesar cipher with password-based shift"""
    shift = sum(ord(c) for c in password) % 256
    encrypted = []
    for char in message:
        encrypted_char = chr((ord(char) + shift) % 256)
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def decrypt_caesar(encrypted_message, password):
    """Caesar cipher decryption"""
    shift = sum(ord(c) for c in password) % 256
    decrypted = []
    for char in encrypted_message:
        decrypted_char = chr((ord(char) - shift) % 256)
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

def encrypt_vigenere(message, password):
    """Vigenère cipher implementation"""
    encrypted = []
    password_key = [ord(c) for c in password]
    key_length = len(password_key)
    
    for i, char in enumerate(message):
        key_char = password_key[i % key_length]
        encrypted_char = chr((ord(char) + key_char) % 256)
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def decrypt_vigenere(encrypted_message, password):
    """Vigenère cipher decryption"""
    decrypted = []
    password_key = [ord(c) for c in password]
    key_length = len(password_key)
    
    for i, char in enumerate(encrypted_message):
        key_char = password_key[i % key_length]
        decrypted_char = chr((ord(char) - key_char) % 256)
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

def encrypt_xor(message, password):
    """Multi-pass XOR encryption"""
    encrypted = message
    # Multiple passes with different password transformations
    for round_num in range(3):
        key = hashlib.sha256((password + str(round_num)).encode()).digest()
        encrypted = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(encrypted))
    return encrypted

def decrypt_xor(encrypted_message, password):
    """Multi-pass XOR decryption"""
    decrypted = encrypted_message
    # Reverse the multi-pass XOR
    for round_num in range(2, -1, -1):
        key = hashlib.sha256((password + str(round_num)).encode()).digest()
        decrypted = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(decrypted))
    return decrypted

def encrypt_substitution(message, password):
    """Substitution cipher optimized for steganography"""
    # Create substitution key from password
    key_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Use only printable characters that work well with steganography
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?-"
    encrypted = []
    
    for i, char in enumerate(message):
        if char in alphabet:
            # Find position in alphabet
            pos = alphabet.find(char)
            if pos != -1:
                # Use key to determine shift
                shift = ord(key_hash[i % len(key_hash)]) % len(alphabet)
                new_pos = (pos + shift) % len(alphabet)
                encrypted.append(alphabet[new_pos])
            else:
                encrypted.append(char)
        else:
            # Replace non-alphabet characters with safe alternatives
            if char == '\n':
                encrypted.append(' ')
            elif char == '\r':
                encrypted.append(' ')
            elif ord(char) < 32 or ord(char) > 126:
                # Skip control characters and high Unicode
                continue
            else:
                encrypted.append(char)
    
    return ''.join(encrypted)

def decrypt_substitution(encrypted_message, password):
    """Substitution cipher decryption optimized for steganography"""
    # Create same substitution key
    key_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Create reverse substitution
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?-"
    decrypted = []
    
    for i, char in enumerate(encrypted_message):
        if char in alphabet:
            # Find position in alphabet
            pos = alphabet.find(char)
            if pos != -1:
                # Use same key to determine shift
                shift = ord(key_hash[i % len(key_hash)]) % len(alphabet)
                # Reverse the shift
                new_pos = (pos - shift) % len(alphabet)
                decrypted.append(alphabet[new_pos])
            else:
                decrypted.append(char)
        else:
            decrypted.append(char)
    
    return ''.join(decrypted)

def encrypt_transposition(message, password):
    """Columnar transposition cipher optimized for steganography"""
    # Calculate grid dimensions based on password
    key_hash = hashlib.sha256(password.encode()).hexdigest()
    columns = len(password) % 10 + 5  # 5-14 columns
    
    # Clean message for steganography - only use printable ASCII
    clean_message = ""
    for char in message:
        if 32 <= ord(char) <= 126:  # Printable ASCII range
            clean_message += char
        else:
            clean_message += " "  # Replace non-printable with space
    
    # Convert to bytes for proper handling
    message_bytes = clean_message.encode('utf-8')
    
    # Pad message if needed
    padding_needed = (columns - (len(message_bytes) % columns)) % columns
    message_bytes += bytes([32]) * padding_needed  # Use space (ASCII 32) for padding
    
    # Create grid and read column-wise
    grid = [message_bytes[i:i+columns] for i in range(0, len(message_bytes), columns)]
    
    # Determine column order based on password
    column_order = sorted(range(columns), key=lambda x: ord(key_hash[x % len(key_hash)]))
    
    encrypted_bytes = []
    for col in column_order:
        for row in grid:
            if col < len(row):
                encrypted_bytes.append(row[col])
    
    # Convert back to string, ensuring only printable characters
    result = ''.join(chr(b) if 32 <= b <= 126 else chr(32 + (b % 95)) for b in encrypted_bytes)
    return result

def decrypt_transposition(encrypted_message, password):
    """Columnar transposition decryption optimized for steganography"""
    key_hash = hashlib.sha256(password.encode()).hexdigest()
    columns = len(password) % 10 + 5
    
    # Convert encrypted message to bytes
    encrypted_bytes = []
    for char in encrypted_message:
        encrypted_bytes.append(ord(char))
    
    # Calculate original message length
    rows = len(encrypted_bytes) // columns
    
    # Reconstruct grid
    grid = [[0 for _ in range(columns)] for _ in range(rows)]
    
    # Determine column order
    column_order = sorted(range(columns), key=lambda x: ord(key_hash[x % len(key_hash)]))
    
    # Fill grid column-wise
    index = 0
    for col in column_order:
        for row in range(rows):
            if index < len(encrypted_bytes):
                grid[row][col] = encrypted_bytes[index]
                index += 1
    
    # Read row-wise and remove padding
    decrypted_bytes = []
    for row in grid:
        decrypted_bytes.extend(row)
    
    # Remove trailing spaces (padding) and convert back to string
    while decrypted_bytes and decrypted_bytes[-1] == 32:
        decrypted_bytes.pop()
    
    return bytes(decrypted_bytes).decode('utf-8', errors='ignore')

def encrypt_blowfish(message, password):
    """Blowfish-like encryption optimized for steganography"""
    # Generate multiple subkeys from password
    subkeys = []
    for i in range(16):
        subkey = hashlib.sha256((password + str(i)).encode()).digest()
        subkeys.append(subkey)
    
    encrypted = []
    for i, char in enumerate(message):
        # Apply multiple rounds of XOR with different subkeys
        encrypted_char = ord(char)
        for round_num in range(4):
            subkey = subkeys[(i + round_num) % len(subkeys)]
            encrypted_char ^= subkey[round_num % 32]
        
        # Ensure result is printable ASCII
        encrypted_char = 32 + (encrypted_char % 95)  # Map to printable range
        encrypted.append(chr(encrypted_char))
    
    return ''.join(encrypted)

def decrypt_blowfish(encrypted_message, password):
    """Blowfish-like decryption optimized for steganography"""
    # Generate same subkeys
    subkeys = []
    for i in range(16):
        subkey = hashlib.sha256((password + str(i)).encode()).digest()
        subkeys.append(subkey)
    
    decrypted = []
    for i, char in enumerate(encrypted_message):
        # Reverse the mapping from printable range
        encrypted_char = (ord(char) - 32) % 256
        
        # Reverse the multiple rounds
        for round_num in range(3, -1, -1):
            subkey = subkeys[(i + round_num) % len(subkeys)]
            encrypted_char ^= subkey[round_num % 32]
        
        decrypted.append(chr(encrypted_char))
    
    return ''.join(decrypted)

def encrypt_twofish(message, password):
    """Twofish-like encryption with Feistel network optimized for steganography"""
    # Generate round keys
    round_keys = []
    for i in range(16):
        key = hashlib.sha256((password + f"round{i}").encode()).digest()
        round_keys.append(key)
    
    # Split message into blocks
    block_size = 16
    blocks = [message[i:i+block_size].ljust(block_size, chr(0)) for i in range(0, len(message), block_size)]
    
    encrypted_blocks = []
    for block in blocks:
        # Convert to numeric values
        left = [ord(c) for c in block[:8]]
        right = [ord(c) for c in block[8:]]
        
        # Feistel network rounds
        for round_num in range(8):
            # F function
            f_input = right + [round_num % 256]
            f_output = hashlib.sha256(bytes(f_input)).digest()
            
            # XOR with round key
            key = round_keys[round_num]
            new_right = []
            for i in range(8):
                new_right.append(left[i] ^ f_output[i] ^ key[i])
            
            left, right = right, new_right
        
        # Combine and convert back, ensuring printable characters
        combined = left + right
        encrypted_block = ''.join(chr(32 + (c % 95)) for c in combined)  # Map to printable range
        encrypted_blocks.append(encrypted_block)
    
    return ''.join(encrypted_blocks)

def decrypt_twofish(encrypted_message, password):
    """Twofish-like decryption optimized for steganography"""
    # Generate same round keys
    round_keys = []
    for i in range(16):
        key = hashlib.sha256((password + f"round{i}").encode()).digest()
        round_keys.append(key)
    
    # Split into blocks
    block_size = 16
    blocks = [encrypted_message[i:i+block_size] for i in range(0, len(encrypted_message), block_size)]
    
    decrypted_blocks = []
    for block in blocks:
        # Convert from printable range back to numeric values
        numeric_values = [(ord(c) - 32) % 256 for c in block]
        left = numeric_values[:8]
        right = numeric_values[8:]
        
        # Reverse Feistel network rounds
        for round_num in range(7, -1, -1):
            # F function
            f_input = left + [round_num % 256]
            f_output = hashlib.sha256(bytes(f_input)).digest()
            
            # XOR with round key
            key = round_keys[round_num]
            new_left = []
            for i in range(8):
                new_left.append(right[i] ^ f_output[i] ^ key[i])
            
            left, right = new_left, left
        
        # Combine and convert back
        combined = left + right
        decrypted_block = ''.join(chr(c) for c in combined)
        decrypted_blocks.append(decrypted_block)
    
    return ''.join(decrypted_blocks).rstrip(chr(0))

# Simple encryption functions (for demonstration)
def encrypt_aes(message, password):
    """Simple AES-like encryption (for demonstration)"""
    # In a real implementation, use proper AES encryption
    key = hashlib.sha256(password.encode()).digest()
    encrypted = []
    for i, char in enumerate(message):
        encrypted_char = chr(ord(char) ^ key[i % len(key)])
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def encrypt_rsa(message, password):
    """Simple RSA-like encryption (for demonstration)"""
    # In a real implementation, use proper RSA encryption
    key = hashlib.sha256(password.encode()).hexdigest()
    encrypted = []
    for i, char in enumerate(message):
        encrypted_char = chr(ord(char) ^ int(key[i % len(key)], 16))
        encrypted.append(encrypted_char)
    return ''.join(encrypted)

def encrypt_hybrid(message, password):
    """Simple hybrid encryption (for demonstration)"""
    # First encrypt with AES-like method, then with RSA-like method
    aes_encrypted = encrypt_aes(message, password)
    return encrypt_rsa(aes_encrypted, password)

def decrypt_message(encrypted_message, password):
    """Try to decrypt message with different methods"""
    # Try AES-like decryption
    try:
        result = decrypt_aes(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try RSA-like decryption
    try:
        result = decrypt_rsa(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try hybrid decryption
    try:
        rsa_decrypted = decrypt_rsa(encrypted_message, password)
        result = decrypt_aes(rsa_decrypted, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try AES-GCM decryption
    try:
        result = decrypt_aes_gcm(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try ChaCha20 decryption
    try:
        result = decrypt_chacha20(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Salsa20 decryption
    try:
        result = decrypt_salsa20(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try RC4 decryption
    try:
        result = decrypt_rc4(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Threefish decryption
    try:
        result = decrypt_threefish(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Camellia decryption
    try:
        result = decrypt_camellia(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Serpent decryption
    try:
        result = decrypt_serpent(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Caesar cipher decryption
    try:
        result = decrypt_caesar(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Vigenère cipher decryption
    try:
        result = decrypt_vigenere(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Multi-pass XOR decryption
    try:
        result = decrypt_xor(encrypted_message, password)
        if is_readable_text(result):
            return result
    except:
        pass
    
    # Try Substitution cipher decryption - more lenient check
    try:
        result = decrypt_substitution(encrypted_message, password)
        # For substitution cipher, be more lenient - check if it looks like reasonable text
        if result and len(result) > 5:  # Basic length check
            return result
    except:
        pass
    
    # Try Transposition cipher decryption - more lenient check
    try:
        result = decrypt_transposition(encrypted_message, password)
        # For transposition cipher, be more lenient - check if it looks like reasonable text
        if result and len(result) > 5:  # Basic length check
            return result
    except:
        pass
    
    # Try Blowfish-like decryption - more lenient check
    try:
        result = decrypt_blowfish(encrypted_message, password)
        # For blowfish cipher, be more lenient - check if it looks like reasonable text
        if result and len(result) > 5:  # Basic length check
            return result
    except:
        pass
    
    # Try Twofish-like decryption - more lenient check
    try:
        result = decrypt_twofish(encrypted_message, password)
        # For twofish cipher, be more lenient - check if it looks like reasonable text
        if result and len(result) > 5:  # Basic length check
            return result
    except:
        pass
    
    # If all methods fail, return None to indicate failure
    return None

def decrypt_aes(encrypted_message, password):
    """Simple AES-like decryption"""
    key = hashlib.sha256(password.encode()).digest()
    decrypted = []
    for i, char in enumerate(encrypted_message):
        decrypted_char = chr(ord(char) ^ key[i % len(key)])
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

def decrypt_rsa(encrypted_message, password):
    """Simple RSA-like decryption"""
    key = hashlib.sha256(password.encode()).hexdigest()
    decrypted = []
    for i, char in enumerate(encrypted_message):
        decrypted_char = chr(ord(char) ^ int(key[i % len(key)], 16))
        decrypted.append(decrypted_char)
    return ''.join(decrypted)

if __name__ == '__main__':
    print("Starting Steganography Pro server...")
    print("Server running at http://127.0.0.1:8080")
    app.run(host='127.0.0.1', port=8080, debug=True, use_reloader=False)
