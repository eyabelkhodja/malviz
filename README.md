# malviz

CNN-image-based malware scanner. Converts binary executables to grayscale
images and classifies them using a ResNet18 + GIST + SVM pipeline trained
on the malimg dataset (25 Windows PE malware families).

## Installation

pip install malviz

## Usage

malviz

Type the number of files to scan, then provide their paths.
Type 'help' for instructions. Type 'quit' to exit.

## Scope

Designed for Windows PE binaries (.exe, .dll, .sys, .scr, .drv).
Results on other formats will show as UNCERTAIN.

## Requirements

Python 3.10+
