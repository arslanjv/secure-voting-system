#!/bin/bash
# Secure Online Voting System - Linux/Mac Setup Script
# This script sets up the development environment

set -e  # Exit on error

echo "====================================="
echo "Secure Online Voting System - Setup"
echo "====================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed"
    echo "Please install Python 3.11 or later"
    exit 1
fi

echo "[1/6] Python detected"
python3 --version
echo ""

# Create virtual environment
echo "[2/6] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists, skipping..."
else
    python3 -m venv venv
    echo "Virtual environment created successfully"
fi
echo ""

# Activate virtual environment
echo "[3/6] Activating virtual environment..."
source venv/bin/activate
echo ""

# Install dependencies
echo "[4/6] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo ""

# Create .env file if it doesn't exist
echo "[5/6] Setting up environment configuration..."
if [ -f ".env" ]; then
    echo ".env file already exists, skipping..."
else
    cp .env.example .env
    echo ".env file created from template"
    echo "IMPORTANT: Edit .env file with your database and secret key settings"
fi
echo ""

# Create necessary directories
echo "[6/6] Creating required directories..."
mkdir -p logs
mkdir -p keys
mkdir -p app/static/uploads
echo "Directories created"
echo ""

echo "====================================="
echo "Setup Complete!"
echo "====================================="
echo ""
echo "Next steps:"
echo "1. Edit .env file with your database credentials"
echo "2. Run: python init_db.py (to initialize database)"
echo "3. Run: python run.py (to start the application)"
echo "4. Access: http://localhost:5000"
echo ""
echo "For security scanning:"
echo "- Run: bandit -r app/."
echo ""
echo "To activate virtual environment in future:"
echo "- source venv/bin/activate"
echo ""
