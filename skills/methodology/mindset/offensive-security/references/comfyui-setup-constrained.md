# ComfyUI Setup Guide for Constrained Environments

Based on session experience setting up ComfyUI for security testing on low-disk-space systems.

## Prerequisites Check

```bash
# Check Python version
python3 --version  # Need 3.8+ (3.12 tested)

# Check available space
df -h  # Watch root partition usage
du -sh /tmp  # Monitor /tmp usage

# Minimum recommended free space: 2GB
```

## Step-by-Step Installation

### 1. Install System Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3.12-venv git

# For torch (CPU-only, no CUDA needed for testing)
# No additional system deps required for CPU torch
```

### 2. Create Virtual Environment (Space-Efficient Location)

**Critical**: Avoid /tmp if frequently cleaned. Use home directory with cleanup strategy.

```bash
# Option A: Home directory (persistent but watch quota)
mkdir -p ~/comfyui-test
python3.12 -m venv ~/comfyui-test/venv

# Option B: /tmp with manual persistence (if /tmp survives reboots)
mkdir -p /tmp/comfyui_venv
python3.12 -m venv /tmp/comfyui_venv

# Option C: External storage if available
# mkdir -p /mnt/storage/comfyui_venv
# python3.12 -m venv /mnt/storage/comfyui_venv
```

### 3. Activate Environment and Install PyTorch (CPU)

```bash
source ~/comfyui-test/venv/bin/activate  # Adjust path as needed

# Install PyTorch CPU-only (saves ~4GB vs CUDA version)
pip install torch --index-url https://download.pytorch.org/whl/cpu
# Verify: python -c "import torch; print(torch.__version__)"
```

### 4. Clone ComfyUI Repository

```bash
# Shallow clone to save space/time
git clone --depth 1 https://github.com/comfyanonymous/ComfyUI.git
cd ComfyUI

# Alternative: If space extremely tight, consider:
# git clone --filter=blob:none --no-checkout https://github.com/comfyanonymous/ComfyUI.git
# Then checkout only needed files
```

### 5. Install Requirements with Space Management

**Problem**: Standard `pip install -r requirements.txt` may fail with "No space left on device"

**Solutions**:

#### Solution A: Clean tmp first
```bash
# Clear package cache and tmp
sudo apt clean
sudo rm -rf /tmp/*  # Be careful!
pip install -r requirements.txt
```

#### Solution B: Use --no-cache-dir
```bash
pip install --no-cache-dir -r requirements.txt
```

#### Solution C: Install minimum required packages
```bash
# Core packages from requirements.txt (adjust based on version)
pip install --no-cache-dir \
    numpy \
    torchvision \
    torchaudio \
    tqdm \
    pillow \
    requests \
    aiohttp \
    websocket-client \
    flask-socketio \
    python-multipart \
    omegaconf
```

### 6. Launch ComfyUI for Testing

```bash
# Listen on all interfaces for external testing
python main.py --listen 0.0.0.0 --port 8188

# For local-only testing (more secure during dev):
# python main.py --listen 127.0.0.1 --port 8188

# Alternative ports if 8188 blocked:
# python main.py --listen 0.0.0.0 --port 8189
```

### 7. Verify Installation

```bash
# Check if running
curl http://127.0.0.1:8188/system_stats
# Should return JSON with system info

# Check models endpoint
curl http://127.0.0.1:8188/models
```

## Disk Space Optimization Tips

### Before Installation:
- Check `/var/log/journal` size: `journalctl --disk-usage`
- Clean old kernels: `sudo apt autoremove --purge`
- Clean apt cache: `sudo apt clean`
- Remove old snaps/flatpaks if applicable

### During Usage:
- ComfyUI stores outputs in `~/ComfyUI/output` by default
- Monitor: `du -sh ~/ComfyUI/output`
- Consider symlinking output to larger storage:
  ```bash
  ln -s /mnt/storage/comfyui_output ~/ComfyUI/output
  ```
- Clear cache periodically:
  ```bash
  rm -rf ~/ComfyUI/cache/*  # If cache directory exists
  ```

### Virtual Environment Management:
- Venv size: ~1.5-2GB with torch + ComfyUI deps
- To move venv: Deactivate, copy, update pyvenv.cfg paths
- Alternative: Use `pipenv` or `poetry` for better dependency control (more complex)

## Security Testing Considerations

### Network Exposure:
- By default binds to 127.0.0.1 (safe)
- `--listen 0.0.0.0` exposes to all interfaces
- **Always** test behind firewall or on isolated network
- Consider using `ssh -L` for port forwarding instead of direct exposure

### Instance Hardening for Testing:
If you need to expose intentionally for testing:
```bash
# Basic rate limiting (example using ufw)
sudo ufw allow from 192.168.0.0/24 to any port 8188  # Only your lab net
sudo ufw deny 8188  # Default deny

# Or use nginx as reverse proxy with auth:
# See references/comfyui-nginx-proxy.md
```

### Artifact Management:
- Save interesting workflows: `cp workflow_api.json ~/test-workflows/`
- Export history: `curl http://127.0.0.1:8188/history > history.json`
- Model files: Usually in `~/ComfyUI/models/` (can be large)
```
