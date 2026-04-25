"""
Malware Binary to Image Converter
PART 1: Image Processing Module - PRODUCTION CODE ONLY

This module converts binary files (.exe, .dll, .elf) to images.
Your teammates will import and use these functions.
"""

import numpy as np
from PIL import Image
import os
import math
from typing import Tuple, Optional, List

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TARGET_SIZE = (224, 224)  # Standard size for most AI models
ENTROPY_BLOCK_SIZE = 64           # 64 bytes per block for entropy calculation


# ============================================================
# FUNCTION 1: Binary to Grayscale
# ============================================================

def binary_to_grayscale(
    file_path: str,
    output_path: Optional[str] = None,
    target_size: Tuple[int, int] = DEFAULT_TARGET_SIZE
) -> np.ndarray:
    """
    Convert a binary file to a grayscale image.

    Args:
        file_path: Path to the .exe, .dll, or .elf file
        output_path: Where to save the PNG (optional)
        target_size: (height, width) for the output image

    Returns:
        A numpy array representing the image (values 0-255)
    """

    # Read the binary file
    with open(file_path, 'rb') as f:
        byte_data = f.read()

    file_size = len(byte_data)
    pixels = np.frombuffer(byte_data, dtype=np.uint8)

    # Calculate image dimensions (square-ish)
    width = int(math.sqrt(file_size))
    width = max(32, min(width, 1024))  # Keep reasonable bounds
    height = math.ceil(file_size / width)

    # Pad with zeros if needed
    total_needed = width * height
    if file_size < total_needed:
        padding_count = total_needed - file_size
        pixels = np.pad(pixels, (0, padding_count), mode='constant', constant_values=0)

    # Reshape to 2D image
    img_array = pixels.reshape(height, width)

    # Resize to target size
    img = Image.fromarray(img_array, mode='L')
    target_height, target_width = target_size
    img_resized = img.resize((target_width, target_height), Image.Resampling.LANCZOS)
    result = np.array(img_resized)

    # Save if output path provided
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        Image.fromarray(result, mode='L').save(output_path, 'PNG')

    return result


# ============================================================
# FUNCTION 2: Entropy Map
# ============================================================

def shannon_entropy(byte_block: bytes) -> float:
    """Calculate Shannon entropy for a block of bytes."""
    if not byte_block:
        return 0.0

    freq = {}
    for byte in byte_block:
        freq[byte] = freq.get(byte, 0) + 1

    block_size = len(byte_block)
    entropy = 0.0

    for count in freq.values():
        prob = count / block_size
        if prob > 0:
            entropy -= prob * math.log2(prob)

    return entropy


def create_entropy_map(
    file_path: str,
    block_size: int = ENTROPY_BLOCK_SIZE,
    output_path: Optional[str] = None,
    target_size: Tuple[int, int] = DEFAULT_TARGET_SIZE
) -> np.ndarray:
    """Create an entropy heatmap of the binary file."""

    with open(file_path, 'rb') as f:
        data = f.read()

    file_size = len(data)

    # Calculate grid dimensions for entropy blocks
    blocks_x = int(math.sqrt(file_size / block_size))
    if blocks_x < 1:
        blocks_x = 1

    blocks_y = math.ceil((file_size / block_size) / blocks_x)

    # Create entropy grid
    entropy_grid = np.zeros((blocks_y, blocks_x))

    for y in range(blocks_y):
        for x in range(blocks_x):
            idx = y * blocks_x + x
            start = idx * block_size
            end = min(start + block_size, file_size)

            if start < file_size:
                block = data[start:end]
                entropy = shannon_entropy(block)
                entropy_grid[y, x] = (entropy / 8.0) * 255

    # Convert to image and scale up
    img = Image.fromarray(entropy_grid.astype(np.uint8), mode='L')
    scale = 4
    img_scaled = img.resize((blocks_x * scale, blocks_y * scale), Image.Resampling.NEAREST)
    img_final = img_scaled.resize((target_size[1], target_size[0]), Image.Resampling.LANCZOS)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        img_final.save(output_path, 'PNG')

    return np.array(img_final)


# ============================================================
# FUNCTION 3: RGB Encoding
# ============================================================

def binary_to_rgb(
    file_path: str,
    output_path: Optional[str] = None,
    encoding: str = 'triplet',
    target_size: Tuple[int, int] = DEFAULT_TARGET_SIZE
) -> np.ndarray:
    """Convert binary to RGB color image."""

    with open(file_path, 'rb') as f:
        data = f.read()

    file_size = len(data)

    if encoding == 'triplet':
        # Pad to multiple of 3
        if file_size % 3 != 0:
            padding = 3 - (file_size % 3)
            data += b'\x00' * padding
        rgb_pixels = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)

    elif encoding == 'modulo':
        pixels = np.frombuffer(data, dtype=np.uint8)
        R = pixels
        G = (pixels >> 4) * 16
        B = (pixels & 0x0F) * 16
        rgb_pixels = np.stack([R, G, B], axis=1)

    else:
        raise ValueError(f"Unknown encoding: {encoding}")

    # Calculate dimensions
    width = int(math.sqrt(len(rgb_pixels)))
    if width < 1:
        width = 1
    height = math.ceil(len(rgb_pixels) / width)

    # Pad if needed
    total_pixels = width * height
    if len(rgb_pixels) < total_pixels:
        padding = np.zeros((total_pixels - len(rgb_pixels), 3), dtype=np.uint8)
        rgb_pixels = np.vstack([rgb_pixels, padding])

    # Reshape and resize
    img_array = rgb_pixels.reshape(height, width, 3)
    img = Image.fromarray(img_array, mode='RGB')
    img_resized = img.resize((target_size[1], target_size[0]), Image.Resampling.LANCZOS)
    result = np.array(img_resized)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        Image.fromarray(result, mode='RGB').save(output_path, 'PNG')

    return result


# ============================================================
# MAIN CLASS - Your teammates will use THIS
# ============================================================

class MalwareImageProcessor:
    """Main class for converting malware binaries to images."""

    def __init__(self, target_size: Tuple[int, int] = (224, 224)):
        self.target_size = target_size

    def to_grayscale(self, file_path: str, output_path: Optional[str] = None) -> np.ndarray:
        """Convert binary to grayscale image."""
        return binary_to_grayscale(file_path, output_path, self.target_size)

    def to_entropy(self, file_path: str, output_path: Optional[str] = None,
                   block_size: int = ENTROPY_BLOCK_SIZE) -> np.ndarray:
        """Create entropy heatmap."""
        return create_entropy_map(file_path, block_size, output_path, self.target_size)

    def to_rgb(self, file_path: str, output_path: Optional[str] = None,
               encoding: str = 'triplet') -> np.ndarray:
        """Convert to RGB color image."""
        return binary_to_rgb(file_path, output_path, encoding, self.target_size)
# Compatibility shim for cli.py

def file_to_image(path, target_size: Tuple[int, int] = DEFAULT_TARGET_SIZE) -> Image.Image:
    """Wrapper used by cli.py — returns a grayscale float32 array in [0, 1]."""
    raw = binary_to_grayscale(str(path), target_size=target_size)
    return Image.fromarray(raw,mode='L')
