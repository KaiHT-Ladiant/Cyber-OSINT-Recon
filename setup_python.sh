#!/bin/bash
# Setup script for Python dependencies

echo "Setting up Python dependencies for Cyber OSINT Recon..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r python_modules/requirements.txt

# Make Python scripts executable
chmod +x python_modules/*.py

echo "Python setup complete!"
