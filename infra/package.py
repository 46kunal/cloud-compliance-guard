"""Build the two deployment zips from this checkout.

    python infra/package.py            # writes build/app.zip and build/scanner.zip

app.zip      dashboard servers (Flask app, templates, static files, catalog, storage layer, rules)
scanner.zip  scheduled Lambda (scanner code only; boto3 comes with the Lambda runtime)
"""
import os
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD = os.path.join(ROOT, "build")

COMMON = ["db", "compliance", "lambdas"]
SCANNER_EXTRA = ["dashboard/scanner.py", "dashboard/evidence.py"]
APP_EXTRA = ["dashboard"]
SKIP_DIRS = {"__pycache__", ".pytest_cache", "venv", ".git"}
SKIP_SUFFIXES = (".pyc", ".db", ".db-journal")
SKIP_FILES = {"policyguard.db"}


def _walk(relative):
    path = os.path.join(ROOT, relative)
    if os.path.isfile(path):
        yield relative.replace(os.sep, "/")
        return
    for folder, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(SKIP_SUFFIXES) or name in SKIP_FILES:
                continue
            yield os.path.relpath(os.path.join(folder, name), ROOT).replace(os.sep, "/")


def build(name, entries):
    os.makedirs(BUILD, exist_ok=True)
    target = os.path.join(BUILD, name)
    count = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            for relative in _walk(entry):
                archive.write(os.path.join(ROOT, relative), relative)
                count += 1
    print(f"{target}: {count} files, {os.path.getsize(target) // 1024} KiB")
    return target


def main():
    build("scanner.zip", COMMON + SCANNER_EXTRA)
    build("app.zip", COMMON + APP_EXTRA)


if __name__ == "__main__":
    sys.exit(main())
