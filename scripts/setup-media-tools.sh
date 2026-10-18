#!/usr/bin/env bash
# Installs FFmpeg, OpenAI Whisper (CPU) and the HyperFrames CLI.
set -euo pipefail

if ! command -v ffmpeg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y ffmpeg
  elif command -v brew >/dev/null 2>&1; then
    brew install ffmpeg
  else
    echo "Please install FFmpeg manually: https://ffmpeg.org/download.html" >&2
    exit 1
  fi
fi

if ! command -v whisper >/dev/null 2>&1; then
  # Prefer the smaller CPU-only torch build; fall back to PyPI if that index is unreachable.
  python3 -m pip install --index-url https://download.pytorch.org/whl/cpu torch \
    || python3 -m pip install torch
  python3 -m pip install openai-whisper
fi

if ! command -v hyperframes >/dev/null 2>&1; then
  npm install -g hyperframes
fi

ffmpeg -version | head -1
whisper --help | head -1
hyperframes --version
