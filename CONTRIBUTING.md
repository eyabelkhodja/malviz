# Contributing to malviz

This document explains how to set up the development environment, work with the model artifacts, update the pipeline, and publish new releases. This tool was created as a Personal Professional Project whose scope doesn't allow for too many risks. As such, many changes could potentially be implemented (creating versions compatible with Android and Linux for example). Any and all contributions are welcome, as long as all due credits are given.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Model Artifacts](#model-artifacts)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Publishing a New Release](#publishing-a-new-release)
- [Automated Release Pipeline](#automated-release-pipeline)

---

## Development Setup

### Prerequisites

- Ubuntu 22.04+ or Debian 12+ (development was done on Ubuntu 24.04)
- Python 3.10 or higher
- `git`
- Access to the shared model artifacts (see [Model Artifacts](#model-artifacts))

### Clone and install

```bash
git clone https://github.com/eyabelkhodja/Malviz.git
cd Malviz

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with all dependencies
pip install -e .
```

### Verify the installation

```bash
malviz
# The banner should appear and the prompt should be functional
```

---

## Project Structure

```
malviz/
├── entry.py              ← PyInstaller entry point (do not rename)
├── pyproject.toml        ← package metadata, version, dependencies
├── README.md
├── CONTRIBUTING.md       ← this file
├── ARCHITECTURE.md
├── LICENSE
├── .gitignore
├── .github/
│   └── workflows/
│       └── release.yml   ← GitHub Actions release automation
└── malviz/
    ├── __init__.py       ← exposes __version__
    ├── cli.py            ← interactive CLI logic
    ├── scanner.py        ← binary→image conversion + ONNX inference
    └── models/           ← NOT tracked in git — see below
        ├── combined_resnet18_benign_plus_malimg.onnx
        ├── combined_resnet18_benign_plus_malimg.onnx.data
        └── combined_class_names.json
```

---

## Model Artifacts

The model files are excluded from the repository because of their size. They must be obtained separately and placed in `malviz/models/` before running or building the tool.

### Files required

| File | Description |
|------|-------------|
| `combined_resnet18_benign_plus_malimg.onnx` | ONNX model weights |
| `combined_resnet18_benign_plus_malimg.onnx.data` | External ONNX data file (required alongside .onnx) |
| `combined_class_names.json` | Ordered list of 26 class names |

### How to obtain them

The model was trained on Kaggle. The artifacts are shared via the team's shared drive. Contact the ML team member for access.

Once obtained:
```bash
mkdir -p malviz/models/
cp combined_resnet18_benign_plus_malimg.onnx      malviz/models/
cp combined_resnet18_benign_plus_malimg.onnx.data malviz/models/
cp combined_class_names.json                       malviz/models/
```

---

## Making Changes

### Modifying the CLI (`cli.py`)

The CLI is fully interactive and self-contained. Key constants to be aware of:

```python
DEFAULT_CONFIDENCE_THRESHOLD = 0.90   # defined in scanner.py
BINARY_EXTENSIONS = {".exe", ".dll", ".sys", ...}  # file type filter
```

The `prompt()` function handles `quit` and `help` globally — all user input should go through it rather than calling `input()` directly.

### Modifying the scanner (`scanner.py`)

The scanner handles two responsibilities:
1. **Binary → image conversion** via `pe_file_to_image_dynamic()`
2. **ONNX inference** via `scan_file()`

If the model is retrained and a new ONNX file is produced, only the file names in `get_model_path()` and `get_class_names_path()` need to change — the rest of the pipeline is format-agnostic.

### Updating the model

When a new model version is trained on Kaggle:

1. Export the new ResNet18 to ONNX (see `export_feature_extractor.py` in the ML repo)
2. Replace the files in `malviz/models/`
3. Update `combined_class_names.json` if the class list changed
4. Bump the version in `pyproject.toml` and `malviz/__init__.py`
5. Follow the release process below

---

## Testing

There is no automated test suite yet. Manual testing procedure:

```bash
# Activate venv
source .venv/bin/activate

# Install in editable mode
pip install -e .

# Test with a known Windows binary
malviz
# Enter threshold: 0.9
# Enter number of files: 1
# Enter path: /path/to/a/windows/exe

# Test scan-all on a directory of PE files
cd /path/to/pe/samples
malviz
# Enter 0 to scan all
```

Expected results:
- Clean Windows system binaries → `✓ Benign`
- Known malware samples → `⚠ MALWARE` with correct family
- Text files, Python scripts → `⊘ SKIPPED`
- Files with ambiguous patterns → `? UNCERTAIN`

---

## Publishing a New Release

### Manual process

```bash
# 1. Bump version in pyproject.toml
nano pyproject.toml
# change: version = "1.2.0" → version = "1.3.0"

# 2. Bump version in __init__.py
nano malviz/__init__.py
# change: __version__ = "1.2.0" → __version__ = "1.3.0"

# 3. Rebuild PyPI package
python3 -m build

# 4. Upload to PyPI
twine upload dist/malviz-1.3.0.tar.gz dist/malviz-1.3.0-py3-none-any.whl
# Username: __token__
# Password: your PyPI API token

# 5. Rebuild standalone binary (for .deb / direct download)
rm -rf build/ dist/ malviz.spec
pyinstaller --onefile \
  --name malviz \
  --add-data "malviz/models/combined_resnet18_benign_plus_malimg.onnx:malviz/models" \
  --add-data "malviz/models/combined_resnet18_benign_plus_malimg.onnx.data:malviz/models" \
  --add-data "malviz/models/combined_class_names.json:malviz/models" \
  --hidden-import onnxruntime \
  entry.py

# 6. Commit and tag
git add .
git commit -m "Release v1.3.0 — <description of changes>"
git tag v1.3.0
git push origin main --tags
```

### Automated process (GitHub Actions)

Once the GitHub Actions workflow is configured (see `.github/workflows/release.yml`), the entire release is triggered by pushing a version tag:

```bash
git tag v1.3.0
git push origin main --tags
```

The workflow will automatically build, publish to PyPI, and attach the binary to a GitHub Release.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full CI/CD pipeline details.

---

## Branch Convention

| Branch | Purpose |
|--------|---------|
| `main` | Stable, released code |
| `dev` | Active development |
| `feature/xxx` | Feature branches — merge into `dev` |
| `fix/xxx` | Bug fix branches — merge into `dev` |

All pull requests should target `dev`, not `main`. `main` is only updated via release commits.
