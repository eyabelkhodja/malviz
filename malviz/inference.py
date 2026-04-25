import numpy as np
import onnxruntime as ort
import joblib
import json
from PIL import Image
from scipy import ndimage as ndi
from sklearn.exceptions import InconsistentVersionWarning
from skimage.filters import gabor_kernel
import importlib.resources as pkg_resources
import warnings

warnings.filterwarnings("ignore",category=InconsistentVersionWarning)

# ── GIST config (must match notebook cells 15-16 exactly) ────────────────────
GIST_IMAGE_SIZE             = 128
GIST_GRID                   = 4
GIST_ORIENTATIONS_PER_SCALE = [8, 8, 4, 4]
GIST_FREQUENCIES            = [0.10, 0.20, 0.30, 0.40]

def _build_kernels():
    kernels = []
    for freq, n_ori in zip(GIST_FREQUENCIES, GIST_ORIENTATIONS_PER_SCALE):
        for theta_idx in range(n_ori):
            theta  = theta_idx / n_ori * np.pi
            kernel = np.real(gabor_kernel(
                frequency=freq, theta=theta, sigma_x=3, sigma_y=3
            ))
            kernels.append(np.asarray(kernel, dtype=np.float32))
    return kernels

_KERNELS = _build_kernels()

# ── Lazy-loaded globals ───────────────────────────────────────────────────────
_session     = None
_scaler      = None
_svm         = None
_class_names = None

def _load():
    global _session, _scaler, _svm, _class_names
    base         = pkg_resources.files("malviz")
    _session     = ort.InferenceSession(
        str(base.joinpath("resnet18_features.onnx")),
        providers=["CPUExecutionProvider"]
    )
    _scaler      = joblib.load(str(base.joinpath("scaler.joblib")))
    _svm         = joblib.load(str(base.joinpath("svm.joblib")))
    _class_names = json.load(open(str(base.joinpath("class_names.json"))))

# ── ResNet18 preprocessing (matches val_transform from notebook) ──────────────
MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
STD  = np.array([0.229, 0.224, 0.225], dtype=np.float32)

def _resnet_features(img: Image.Image) -> np.ndarray:
    img    = img.convert("RGB").resize((224, 224), Image.LANCZOS)
    tensor = np.array(img, dtype=np.float32) / 255.0
    tensor = tensor.transpose(2, 0, 1)
    for c in range(3):
        tensor[c] = (tensor[c] - MEAN[c]) / STD[c]
    return _session.run(["features"],
                        {"image": tensor[np.newaxis]})[0]  # (1, 512)

def _gist_features(img: Image.Image) -> np.ndarray:
    img   = img.convert("L").resize((GIST_IMAGE_SIZE, GIST_IMAGE_SIZE))
    arr   = np.asarray(img, dtype=np.float32) / 255.0
    bh    = GIST_IMAGE_SIZE // GIST_GRID
    bw    = GIST_IMAGE_SIZE // GIST_GRID
    feats = []
    for kernel in _KERNELS:
        resp = np.abs(ndi.convolve(arr, kernel, mode='reflect'))
        for gy in range(GIST_GRID):
            for gx in range(GIST_GRID):
                feats.append(resp[gy*bh:(gy+1)*bh,
                                  gx*bw:(gx+1)*bw].mean())
    return np.array(feats, dtype=np.float32)[np.newaxis]  # (1, 384)

# ── Public API ────────────────────────────────────────────────────────────────
def predict(img: Image.Image) -> tuple[str, float]:
    """
    Accepts a PIL Image (as returned by converter.file_to_image).
    Returns (class_label, confidence) where confidence is in [0, 1].
    """
    global _session, _scaler, _svm, _class_names
    if _session is None:
        _load()

    fused  = np.concatenate([_resnet_features(img),
                              _gist_features(img)], axis=1)  # (1, 896)
    scaled = _scaler.transform(fused)
    idx    = _svm.predict(scaled)[0]
    conf   = float(_svm.predict_proba(scaled)[0][idx])
    return _class_names[idx], conf
