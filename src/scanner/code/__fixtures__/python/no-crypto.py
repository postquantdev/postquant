"""Test fixture: Python code with no cryptographic usage."""
import os
import sys
import json

def hello():
    print("Hello, world!")
    data = json.loads('{"key": "value"}')
    return data

if __name__ == "__main__":
    hello()
