# Malviz

> CNN-image-based Windows malware scanner — converts binary executables to grayscale images and classifies them using a fine-tuned ResNet18 model trained on the malimg dataset extended with clean Benign samples.

![Version](https://img.shields.io/badge/version-1.2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![PyPI](https://img.shields.io/pypi/v/malviz)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Supported Malware Families](#supported-malware-families)
- [Installation](#installation)
- [Usage](#usage)
- [Result Legend](#result-legend)
- [Project Structure](#project-structure)
- [Scope and Limitations](#scope-and-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**malviz** is a research-grade malware classification tool developed as a Personal Professional Project (PPP). It implements the binary-to-image technique — a well-established approach in malware analysis where raw binary files are interpreted as grayscale pixel matrices and fed into a convolutional neural network for classification.

The tool is designed to be deployed on Linux systems and used by security analysts to triage suspicious Windows PE files without executing them.

---

## How It Works

The classification pipeline consists of three stages:

```
Binary file (.exe, .dll, .sys ...)
        │
        ▼
┌───────────────────────────┐
│   Binary → Image          │
│   pe_file_to_image()      │
│   dynamic width reshape   │
│   grayscale pixel matrix  │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│   Preprocessing           │
│   RGB conversion          │
│   Resize to 224×224       │
│   ImageNet normalization  │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│   ResNet18 (ONNX)         │
│   fine-tuned on malimg    │
│   + Benign class          │
│   outputs 26-class logits │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│   Softmax + Threshold     │
│   confidence ≥ threshold  │
│   → verdict               │
└───────────────────────────┘
        │
        ▼
  Benign / Malware Family / Uncertain
```

### Binary to Image Conversion

The raw bytes of the file are read and reshaped into a 2D matrix using a dynamic width calculated as the next power of two above the square root of the file size. This produces a grayscale image where byte patterns — such as packed sections, encrypted payloads, or repetitive structures — become visually distinguishable.

### Model

The classifier is a **ResNet18** architecture pretrained on ImageNet and fine-tuned on the **malimg dataset** augmented with a curated set of clean Windows binaries forming the Benign class. The model is exported to ONNX format and runs via `onnxruntime` — no GPU or PyTorch installation required at inference time.

- **Input:** `(1, 3, 224, 224)` float32 tensor, ImageNet-normalized
- **Output:** `(1, 26)` logits over 26 classes (25 malware families + Benign)
- **Runtime:** CPU only via `onnxruntime`

---

## Supported Malware Families

| Index | Family | Index | Family |
|-------|--------|-------|--------|
| 0 | Adialer.C | 13 | Lolyda.AA1 |
| 1 | Agent.FYI | 14 | Lolyda.AA2 |
| 2 | Allaple.A | 15 | Lolyda.AA3 |
| 3 | Allaple.L | 16 | Lolyda.AT |
| 4 | Alueron.gen!J | 17 | Malex.gen!J |
| 5 | Autorun.K | 18 | Obfuscator.AD |
| 6 | **Benign** | 19 | Rbot!gen |
| 7 | C2LOP.P | 20 | Skintrim.N |
| 8 | C2LOP.gen!g | 21 | Swizzor.gen!E |
| 9 | Dialplatform.B | 22 | Swizzor.gen!I |
| 10 | Dontovo.A | 23 | VB.AT |
| 11 | Fakerean | 24 | Wintrim.BX |
| 12 | Instantaccess | 25 | Yuner.A |

---

## Installation

### Via pip (recommended — works on Linux, Windows, macOS)

```bash
pip install malviz
```

### Requirements

- Python 3.10 or higher
- Dependencies installed automatically: `onnxruntime`, `numpy`, `Pillow`

### From source

```bash
git clone https://github.com/eyabelkhodja/Malviz.git
cd Malviz
pip install -e .
```

> **Note:** The model files (`*.onnx`, `*.onnx.data`, `*.json`) are not included in the repository due to their size. Download them separately and place them in `malviz/models/`. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Usage

Launch the interactive scanner:

```bash
malviz
```

The tool will guide you through the following steps:

**1. Set confidence threshold**
```
Confidence threshold (default: 0.9)
Press Enter to keep default, or type a value (e.g. 0.75)

threshold > 0.85
Using threshold: 0.85
```

**2. Choose how many files to scan**
```
How many files do you want to scan?
(enter 0 to scan ALL files in the current directory)

> 2
```

**3. Provide file paths**
```
Path to file 1: /path/to/suspicious.exe
Path to file 2: /path/to/sample.dll
```

**4. Read results**
```
  ──────────────────────────────────────────────────────
  ⚠  MALWARE    [97.3%]  Allaple.A             /path/to/suspicious.exe
  ✓  Benign     [91.2%]  Benign                /path/to/sample.dll
  ──────────────────────────────────────────────────────

  ✓  Benign     : 1
  ⚠  Malware    : 1
  ?  Uncertain  : 0
  ✗  Errors     : 0
  ⊘  Skipped    : 0
```

### Built-in commands

| Command | Effect |
|---------|--------|
| `help` | Display the help screen with full usage instructions |
| `quit` | Exit malviz cleanly |

### Confidence threshold

The threshold controls how conservative the classifier is:

| Threshold | Behavior |
|-----------|----------|
| `0.90` (default) | Conservative — only high-confidence verdicts |
| `0.75` | Balanced — fewer uncertain results |
| `0.50` | Permissive — more verdicts, higher false positive risk |

Results below the threshold are reported as `UNCERTAIN` rather than forcing a potentially wrong verdict.

---

## Result Legend

| Symbol | Label | Meaning |
|--------|-------|---------|
| ✓ | Benign | File classified as clean with confidence ≥ threshold |
| ⚠ | MALWARE | File matched a known malware family with confidence ≥ threshold |
| ? | UNCERTAIN | Confidence below threshold — result unreliable |
| ⊘ | SKIPPED | File format not supported (non-binary) |
| ✗ | ERROR | File could not be processed |

---

## Project Structure

```
malviz/
├── entry.py                        ← PyInstaller entry point
├── pyproject.toml                  ← package metadata and build config
├── README.md                       ← this file
├── CONTRIBUTING.md                 ← contributor guide
├── ARCHITECTURE.md                 ← technical architecture details
├── LICENSE
├── .gitignore
├── .github/
│   └── workflows/
│       └── release.yml             ← automated release pipeline
└── malviz/
    ├── __init__.py
    ├── cli.py                      ← interactive CLI (prompt loop, banner, help)
    ├── scanner.py                  ← binary→image conversion + ONNX inference
    └── models/                     ← model artifacts (not tracked in git)
        ├── combined_resnet18_benign_plus_malimg.onnx
        ├── combined_resnet18_benign_plus_malimg.onnx.data
        └── combined_class_names.json
```

---

## Scope and Limitations

- **Designed for Windows PE binaries** (`.exe`, `.dll`, `.sys`, `.scr`, `.drv`). Results on Linux ELF, Android APK, or other formats are unreliable and will typically show as UNCERTAIN.
- **Research prototype** — not a replacement for a production antivirus engine.
- **Static analysis only** — the file is never executed. No sandboxing or dynamic behavior analysis is performed.
- **25 malware families** from the malimg dataset. Malware families not present in the training data will not be correctly identified.
- **CPU inference only** — no GPU acceleration at inference time.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide including how to set up the development environment, update the model, and publish new releases.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

> **Disclaimer:** malviz is a student research tool. It is not intended for use as a primary security control. Always verify results with professional-grade antivirus software.
