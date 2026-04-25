import json
import math
from importlib.resources import files
from pathlib import Path

import numpy as np
import onnxruntime as ort
from PIL import Image

IMAGE_SIZE = 224
DEFAULT_CONFIDENCE_THRESHOLD = 0.90


def get_model_path() -> str:
    return str(files("malviz").joinpath(
        "models/combined_resnet18_benign_plus_malimg.onnx"
    ))


def get_class_names_path() -> str:
    return str(files("malviz").joinpath(
        "models/combined_class_names.json"
    ))


def pe_file_to_image_dynamic(file_path: str | Path) -> Image.Image:
    """
    Convert a binary file into a grayscale image using the same
    dynamic-width conversion used during training.
    """
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        byte_data = f.read()

    if len(byte_data) == 0:
        raise ValueError("Empty file.")

    byte_array = np.frombuffer(byte_data, dtype=np.uint8)

    b = int(len(byte_array) ** 0.5)
    if b <= 0:
        raise ValueError("File too small to convert.")

    b = 2 ** (int(math.log(b, 2)) + 1)
    a = int(len(byte_array) / b)

    usable_size = a * b
    if usable_size == 0:
        raise ValueError("File too small after reshaping.")

    byte_array = byte_array[:usable_size]
    image_array = byte_array.reshape((a, b))

    return Image.fromarray(image_array.astype(np.uint8))


def preprocess_image(image: Image.Image) -> np.ndarray:
    """
    Match training preprocessing:
    RGB, resize 224x224, ImageNet normalization, HWC → CHW, batch dim.
    """
    image = image.convert("RGB")
    image = image.resize((IMAGE_SIZE, IMAGE_SIZE))

    arr = np.asarray(image).astype(np.float32) / 255.0
    mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    std  = np.array([0.229, 0.224, 0.225], dtype=np.float32)
    arr  = (arr - mean) / std
    arr  = np.transpose(arr, (2, 0, 1))
    arr  = np.expand_dims(arr, axis=0)

    return arr.astype(np.float32)


def softmax(logits: np.ndarray) -> np.ndarray:
    logits = logits - np.max(logits, axis=1, keepdims=True)
    exp = np.exp(logits)
    return exp / np.sum(exp, axis=1, keepdims=True)


def load_class_names() -> list[str]:
    with open(get_class_names_path(), "r", encoding="utf-8") as f:
        class_names = json.load(f)
    if "Benign" not in class_names:
        raise ValueError("Class names file does not contain 'Benign'.")
    return class_names


# Lazy-loaded globals
_session     = None
_class_names = None

def _load():
    global _session, _class_names
    _session     = ort.InferenceSession(
        get_model_path(), providers=["CPUExecutionProvider"]
    )
    _class_names = load_class_names()


def scan_file(
    file_path: str | Path,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
) -> dict:
    global _session, _class_names
    if _session is None:
        _load()

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    image  = pe_file_to_image_dynamic(file_path)
    x      = preprocess_image(image)

    input_name  = _session.get_inputs()[0].name
    output_name = _session.get_outputs()[0].name

    logits = _session.run([output_name], {input_name: x})[0]
    probs  = softmax(logits)

    pred_idx        = int(np.argmax(probs, axis=1)[0])
    pred_label      = _class_names[pred_idx]
    confidence      = float(probs[0, pred_idx])
    benign_prob     = float(probs[0, _class_names.index("Benign")])

    if confidence < threshold:
        result = "uncertain"
    elif pred_label == "Benign":
        result = "benign"
    else:
        result = "malware"

    return {
        "file":              str(file_path),
        "result":            result,
        "prediction":        pred_label,
        "confidence":        confidence,
        "benign_probability": benign_prob,
    }
