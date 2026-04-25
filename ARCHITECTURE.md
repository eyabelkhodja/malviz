# malviz — Technical Architecture

This document describes the internal architecture of malviz, the design decisions behind each component, and the full CI/CD release pipeline.

---

## Table of Contents

- [High-Level Overview](#high-level-overview)
- [Inference Pipeline](#inference-pipeline)
- [Component Reference](#component-reference)
- [Model Architecture](#model-architecture)
- [Packaging Strategy](#packaging-strategy)
- [Release Pipeline](#release-pipeline)
- [Design Decisions](#design-decisions)

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        malviz v1.2.0                        │
├─────────────────┬───────────────────────────────────────────┤
│   cli.py        │  Interactive session manager               │
│                 │  • Banner + help screen                    │
│                 │  • Threshold configuration                 │
│                 │  • File path collection                    │
│                 │  • Result formatting and display           │
├─────────────────┼───────────────────────────────────────────┤
│   scanner.py    │  Core inference engine                     │
│                 │  • Binary → grayscale image conversion     │
│                 │  • ImageNet preprocessing                  │
│                 │  • ONNX inference via onnxruntime          │
│                 │  • Softmax + threshold verdict             │
├─────────────────┼───────────────────────────────────────────┤
│   models/       │  Bundled model artifacts                   │
│                 │  • ResNet18 ONNX weights                   │
│                 │  • Class name mapping (26 classes)         │
└─────────────────┴───────────────────────────────────────────┘
```

---

## Inference Pipeline

### Stage 1 — Binary to image

```python
def pe_file_to_image_dynamic(file_path) -> Image.Image
```

Raw bytes are read from the file and reshaped into a 2D grayscale matrix. The width is computed as the next power of two above the square root of the file size, matching the conversion method used during model training on the malimg dataset:

```
file_size = len(byte_array)
b = next_power_of_two(sqrt(file_size))
a = floor(file_size / b)
image = byte_array[:a*b].reshape(a, b)
```

Trailing bytes that do not fit the rectangle are discarded. The result is a PIL Image in mode `L` (grayscale).

### Stage 2 — Preprocessing

```python
def preprocess_image(image) -> np.ndarray  # shape: (1, 3, 224, 224)
```

Replicates `val_transform` from the training notebook exactly:

| Step | Operation |
|------|-----------|
| 1 | Convert grayscale to RGB (3-channel repeat) |
| 2 | Resize to 224×224 using LANCZOS resampling |
| 3 | Normalize to `[0, 1]` by dividing by 255 |
| 4 | Apply ImageNet normalization: `mean=[0.485, 0.456, 0.406]`, `std=[0.229, 0.224, 0.225]` |
| 5 | Transpose HWC → CHW |
| 6 | Add batch dimension → `(1, 3, 224, 224)` |

### Stage 3 — ONNX inference

```python
session = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
logits = session.run([output_name], {input_name: x})[0]  # shape: (1, 26)
```

The ONNX session is loaded lazily on first call and reused across all subsequent scans in the same session (singleton pattern via module-level `_session` global).

### Stage 4 — Softmax + verdict

```python
probs = softmax(logits)             # (1, 26) probabilities
pred_idx = argmax(probs)            # index of highest probability class
confidence = probs[0, pred_idx]     # scalar in [0, 1]
```

Verdict logic:

```python
if confidence < threshold:
    result = "uncertain"
elif class_names[pred_idx] == "Benign":
    result = "benign"
else:
    result = "malware"
```

---

## Component Reference

### `cli.py`

| Symbol | Type | Description |
|--------|------|-------------|
| `BANNER` | `str` | ASCII art banner printed at startup |
| `HELP_TEXT` | `str` | Full help screen displayed on `help` command |
| `DIVIDER` | `str` | Visual separator line |
| `BINARY_EXTENSIONS` | `set[str]` | Whitelisted file extensions for scanning |
| `is_binary_file(path)` | `func` | Two-stage binary detection: extension check + byte entropy check |
| `scan_files(targets, threshold)` | `func` | Iterates over targets, calls `scan_file`, formats output |
| `prompt(msg)` | `func` | Global input handler — intercepts `quit` and `help` at every prompt |
| `main()` | `func` | Entry point — session loop, threshold config, file collection |

### `scanner.py`

| Symbol | Type | Description |
|--------|------|-------------|
| `IMAGE_SIZE` | `int` | `224` — ResNet18 input size |
| `DEFAULT_CONFIDENCE_THRESHOLD` | `float` | `0.90` |
| `get_model_path()` | `func` | Returns absolute path to ONNX file via `importlib.resources` |
| `get_class_names_path()` | `func` | Returns absolute path to class names JSON |
| `pe_file_to_image_dynamic(path)` | `func` | Binary → PIL Image (grayscale) |
| `preprocess_image(image)` | `func` | PIL Image → `(1,3,224,224)` float32 ndarray |
| `softmax(logits)` | `func` | Numerically stable softmax |
| `load_class_names()` | `func` | Loads and validates class names from JSON |
| `scan_file(path, threshold)` | `func` | Full pipeline — returns result dict |
| `_session` | `global` | Lazy-loaded ONNX InferenceSession singleton |
| `_class_names` | `global` | Lazy-loaded class name list |

### `scan_file()` return value

```python
{
    "file":               str,    # absolute path to scanned file
    "result":             str,    # "benign" | "malware" | "uncertain"
    "prediction":         str,    # class name (e.g. "Allaple.A" or "Benign")
    "confidence":         float,  # probability of predicted class in [0, 1]
    "benign_probability": float,  # probability of Benign class specifically
}
```

---

## Model Architecture

### Base model

- **Architecture:** ResNet18
- **Pretrained weights:** ImageNet (torchvision `ResNet18_Weights.DEFAULT`)
- **Final layer:** `nn.Linear(512, 26)` replacing the original `nn.Linear(512, 1000)`
- **Fine-tuning:** Full fine-tuning (all layers trainable)

### Training dataset

- **Malware samples:** malimg dataset — 9,342 images across 25 Windows PE malware families
- **Benign samples:** Clean Windows binaries added to form the 26th class
- **Split:** 80% train / 10% validation / 10% test (stratified)
- **Imbalance handling:** `WeightedRandomSampler` (sampler_only experiment)

### Training configuration

| Parameter | Value |
|-----------|-------|
| Image size | 224×224 |
| Batch size | 32 |
| Optimizer | Adam |
| Learning rate | 1e-4 |
| Weight decay | 1e-4 |
| LR scheduler | ReduceLROnPlateau (patience=3, factor=0.5) |
| Max epochs | 15 |
| Early stopping | patience=8 |

### Export

The model was exported to ONNX format using `torch.onnx.export` with `opset_version=17` and dynamic batch axis. The large external data file (`.onnx.data`) is produced automatically when model weights exceed the ONNX inline threshold.

---

## Packaging Strategy

malviz uses two parallel distribution channels:

### PyPI (pip install malviz)

- Distributes Python source + model artifacts bundled as package data
- Works on Linux, Windows, macOS — any platform with Python 3.10+
- Model files included in the wheel via `[tool.setuptools.package-data]`
- Users run `malviz` directly after `pip install`

### Standalone binary (.deb / direct download)

- Built with **PyInstaller** `--onefile` mode
- Bundles Python interpreter + all dependencies + model into a single ELF binary
- No Python installation required on the target machine
- Suitable for distribution via APT repository or direct download
- Built on Ubuntu, targets `amd64` architecture

### Build commands

```bash
# PyPI wheel
python3 -m build

# Standalone binary
pyinstaller --onefile \
  --name malviz \
  --add-data "malviz/models/combined_resnet18_benign_plus_malimg.onnx:malviz/models" \
  --add-data "malviz/models/combined_resnet18_benign_plus_malimg.onnx.data:malviz/models" \
  --add-data "malviz/models/combined_class_names.json:malviz/models" \
  --hidden-import onnxruntime \
  entry.py
```

---

## Release Pipeline

### Manual release steps

```
1. Update model artifacts in malviz/models/ (if model changed)
2. Bump version in pyproject.toml and malviz/__init__.py
3. python3 -m build
4. twine upload dist/malviz-X.Y.Z.*
5. pyinstaller ... entry.py
6. git add . && git commit -m "Release vX.Y.Z"
7. git tag vX.Y.Z
8. git push origin main --tags
```

### Automated release (GitHub Actions)

The workflow in `.github/workflows/release.yml` triggers on any tag matching `v*`:

```
Push tag vX.Y.Z
      │
      ▼
┌─────────────────────────┐
│  Checkout code           │
│  Set up Python 3.12      │
│  Download model artifacts│  ← from MODEL_ARTIFACTS_URL secret
│  Install dependencies    │
└────────────┬────────────┘
             │
      ┌──────┴──────┐
      ▼             ▼
┌──────────┐  ┌──────────────┐
│  Build   │  │  PyInstaller │
│  PyPI    │  │  binary      │
│  wheel   │  │  (amd64)     │
└────┬─────┘  └──────┬───────┘
     │               │
     ▼               ▼
┌──────────┐  ┌──────────────┐
│  twine   │  │  GitHub      │
│  upload  │  │  Release     │
│  PyPI    │  │  + binary    │
└──────────┘  └──────────────┘
```

### Required GitHub Secrets

| Secret | Value |
|--------|-------|
| `PYPI_API_TOKEN` | PyPI API token starting with `pypi-` |
| `MODEL_ARTIFACTS_URL` | URL to zipped model artifacts (Google Drive or similar) |
| `GITHUB_TOKEN` | Automatically provided by GitHub Actions |

---

## Design Decisions

**Why ONNX instead of PyTorch at inference time?**
`onnxruntime` is a lightweight C++ inference engine with Python bindings. It has no dependency on PyTorch, CUDA, or any training framework — making the deployed package significantly smaller and more portable. A full PyTorch install would add ~2GB to the binary.

**Why a single ONNX model instead of ResNet18 features + GIST + SVM?**
Early versions of malviz used a three-stage pipeline (ResNet18 feature extractor → GIST descriptor → SVM classifier). This was replaced in v1.2.0 with a single end-to-end ResNet18 classifier that includes a proper Benign class. The single-model approach is simpler, faster at inference, and produces a much smaller deployment artifact.

**Why a confidence threshold instead of always returning the top-1 class?**
The model was trained on 25 specific malware families plus one Benign class. Files that are outside this distribution (Linux ELF binaries, Android APKs, documents) will produce low-confidence predictions across all classes rather than confidently matching any family. The threshold surfaces this uncertainty explicitly rather than returning a misleading verdict.

**Why interactive CLI instead of argument-based CLI?**
The tool is intended for use by security analysts who may scan many files across multiple sessions. An interactive loop avoids re-launching the binary for each file, keeps the model loaded in memory across scans, and provides a cleaner UX for batch scanning workflows.
