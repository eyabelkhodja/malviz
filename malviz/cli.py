import sys
from pathlib import Path
from .scanner import scan_file, DEFAULT_CONFIDENCE_THRESHOLD

BANNER = r"""
 ███╗   ███╗ █████╗ ██╗    ██╗   ██╗██╗███████╗
 ████╗ ████║██╔══██╗██║    ██║   ██║██║╚════██║
 ██╔████╔██║███████║██║    ██║   ██║██║   ███╔╝
 ██║╚██╔╝██║██╔══██║██║    ╚██╗ ██╔╝██║ ██╔╝
 ██║ ╚═╝ ██║██║  ██║███████╗╚████╔╝ ██║ ██████║
 ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═══╝  ╚═╝ ╚═════╝
   CNN-image-based Malware Scanner  |  v1.2.0
"""

HELP_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║                        MALVIZ  —  HELP                          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  WHAT IS MALVIZ?                                                 ║
║  malviz is a CNN-image-based malware scanner. It converts        ║
║  binary executables into grayscale images and classifies         ║
║  them using a ResNet18 model trained on the malimg dataset       ║
║  extended with clean Benign samples.                             ║
║                                                                  ║
║  SCOPE                                                           ║
║  Designed for Windows PE binaries: .exe  .dll  .sys  .scr        ║
║  Results on other binary formats may be unreliable.              ║
║                                                                  ║
║  HOW TO USE                                                      ║
║  1. Launch malviz                                                ║
║  2. Enter the number of files to scan                            ║
║     → enter 0 to scan ALL files in the current directory         ║
║  3. Enter the full path to each file when prompted               ║
║  4. Optionally set a confidence threshold (default: 0.90)        ║
║  4. Read the results                                             ║
║                                                                  ║
║  RESULT LEGEND                                                   ║
║  ✓  Benign     — file is clean                                   ║
║  ⚠  MALWARE    — file matched a known malware family             ║
║  ?  UNCERTAIN  — confidence below threshold, result unreliable   ║
║  ⊘  SKIPPED    — file is not a supported binary format           ║
║  ✗  ERROR      — file could not be processed                     ║
║                                                                  ║
║  CONFIDENCE THRESHOLD                                            ║
║  Default is 0.90. Lower it to get more verdicts,                 ║
║  raise it to be more conservative.                               ║
║                                                                  ║
║  COMMANDS                                                        ║
║  help   — show this help screen                                  ║
║  quit   — exit malviz                                            ║
║                                                                  ║
║  MALWARE FAMILIES DETECTED                                       ║
║  Adialer.C    Agent.FYI    Allaple.A    Allaple.L                ║
║  Alueron.gen  Autorun.K    C2LOP.P      C2LOP.gen                ║
║  Dialplatform Dontovo.A    Fakerean     Instantaccess             ║
║  Lolyda.AA1   Lolyda.AA2   Lolyda.AA3   Lolyda.AT                ║
║  Malex.gen    Obfuscator   Rbot!gen     Skintrim.N               ║
║  Swizzor.E    Swizzor.I    VB.AT        Wintrim.BX   Yuner.A     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

DIVIDER = "  " + "─" * 54
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".elf", ".bin",
    ".so", ".dylib", ".scr", ".drv", ".ocx"
}

def is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
        non_printable = sum(
            1 for b in chunk if b < 9 or (14 <= b <= 31) or b == 127
        )
        return (non_printable / max(len(chunk), 1)) > 0.30
    except Exception:
        return False


def scan_files(targets: list[Path], threshold: float):
    clean, malware, uncertain, errors, skipped = 0, 0, 0, 0, 0
    print()
    print(DIVIDER)

    for f in targets:
        if not f.is_file():
            print(f"  ⊘  SKIPPED    {f}")
            print(f"     └─ not a file")
            skipped += 1
            continue

        if not is_binary_file(f):
            print(f"  ⊘  SKIPPED    {f}")
            print(f"     └─ not a supported binary format "
                  f"(.exe .dll .sys .elf .bin .so expected)")
            skipped += 1
            continue

        try:
            result = scan_file(f, threshold=threshold)

            if result["result"] == "uncertain":
                print(f"  ?  UNCERTAIN  [{result['confidence']*100:.1f}%]  {f}")
                print(f"     └─ low confidence — file may be outside "
                      f"the model's training distribution")
                uncertain += 1

            elif result["result"] == "malware":
                print(f"  ⚠  MALWARE    [{result['confidence']*100:.1f}%]  "
                      f"{result['prediction']:<20}  {f}")
                malware += 1

            else:
                print(f"  ✓  Benign     [{result['confidence']*100:.1f}%]  "
                      f"{result['prediction']:<20}  {f}")
                clean += 1

        except Exception as e:
            print(f"  ✗  ERROR      {f}")
            print(f"     └─ {e}", file=sys.stderr)
            errors += 1

    print(DIVIDER)
    print(f"""
  ✓  Benign     : {clean}
  ⚠  Malware    : {malware}
  ?  Uncertain  : {uncertain}
  ✗  Errors     : {errors}
  ⊘  Skipped    : {skipped}
""")
    print(DIVIDER)


def prompt(msg: str) -> str:
    raw = input(msg).strip()
    if raw.lower() == "quit":
        print("\n  Goodbye. Stay safe.\n")
        sys.exit(0)
    if raw.lower() == "help":
        print(HELP_TEXT)
        return "__help__"
    return raw


def main():
    print(BANNER)
    print("  Malviz is a CNN-image-based malware scanner for Windows")
    print("  executables, developed as a Personal Professional Project.")
    print()
    print("  Type  'help'  at any prompt for instructions.")
    print("  Type  'quit'  at any prompt to exit.")
    print()

    # ── Ask for threshold once at session start ───────────────────
    print(DIVIDER)
    print(f"  Confidence threshold (default: {DEFAULT_CONFIDENCE_THRESHOLD})")
    print("  Press Enter to keep default, or type a value (e.g. 0.75)")
    print(DIVIDER)

    while True:
        raw = prompt("\n  threshold > ")
        if raw == "__help__":
            continue
        if raw == "":
            threshold = DEFAULT_CONFIDENCE_THRESHOLD
            break
        try:
            threshold = float(raw)
            if 0.0 < threshold <= 1.0:
                break
            print("  ✗  Please enter a value between 0.01 and 1.0")
        except ValueError:
            print("  ✗  Please enter a valid number, 'help', or 'quit'.")

    print(f"\n  Using threshold: {threshold}")

    while True:
        print()
        print(DIVIDER)
        print("  How many files do you want to scan?")
        print("  (enter 0 to scan ALL files in the current directory)")
        print(DIVIDER)

        while True:
            raw = prompt("\n  > ")
            if raw == "__help__":
                continue
            try:
                n = int(raw)
                if n < 0:
                    print("  ✗  Please enter 0 or a positive number.")
                    continue
                break
            except ValueError:
                print("  ✗  Please enter a valid number, 'help', or 'quit'.")

        if n == 0:
            targets = [f for f in Path(".").iterdir() if f.is_file()]
            if not targets:
                print("\n  No files found in current directory.\n")
            else:
                print(f"\n  Scanning {len(targets)} file(s) "
                      f"in current directory...\n")
                scan_files(targets, threshold)
        else:
            targets = []
            for i in range(n):
                while True:
                    raw = prompt(f"\n  Path to file {i+1}: ")
                    if raw == "__help__":
                        continue
                    p = Path(raw)
                    if p.exists():
                        targets.append(p)
                        break
                    else:
                        print(f"  ✗  File not found: {raw}  —  try again.")

            print(f"\n  Scanning {len(targets)} file(s)...")
            scan_files(targets, threshold)

        print("  Ready for next scan. "
              "(type 'quit' to exit or enter a number to scan again)")


if __name__ == "__main__":
    main()
