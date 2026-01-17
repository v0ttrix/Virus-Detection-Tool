#!/bin/bash

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Setting up environment (first time only)..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -q -r requirements.txt
    echo "Setup complete!"
else
    source venv/bin/activate
fi

# Run the scanner
python scanner.py "$@"
