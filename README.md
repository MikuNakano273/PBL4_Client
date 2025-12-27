# Malware Scanner Project

## Prerequisites

Before setting up the project, ensure you have the following installed:

- **vcpkg** (for managing C++ dependencies)
- **Python 3.13.x**
- **MSVC** (Microsoft Visual C++ – usually installed with Visual Studio)

## Setup and Running

Open the **Developer Command Prompt for Visual Studio** and run the following commands in sequence:

```bash
# Install required dependencies via vcpkg
# Run this in Developer CMD for VS, not normal terminal
vcpkg install yara openssl:x64-windows

# Navigate to the project root folder (if not already there)
# cd path/to/your/project
# Run all below in your normal terminal

# Install the Python package
pip install .

# Run the application
python -m app

# (Optional) Build a standalone .exe
pyinstaller PB4_Client.spec