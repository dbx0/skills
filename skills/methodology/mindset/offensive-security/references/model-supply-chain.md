# Model Supply Chain Attack Research

## Malicious Models on HuggingFace

### Documented Incidents

**JFrog Research (2024):** Data scientists targeted by malicious HuggingFace models with silent backdoor
- https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/
- Attackers uploaded models with pickled payloads that execute arbitrary code on `torch.load()`
- Models appeared legitimate (good descriptions, reasonable file counts) but contained malicious `.pt`/`.pkl` files

**HuggingFace Malware Scanning:**
- HuggingFace runs `picklescan` and `modelscan` on uploaded models
- Despite this, malicious models have been found in the wild
- The platform has since improved scanning but the attack surface remains

### Attack Vectors

**1. Pickle-based RCE (`.pt`, `.pkl` files)**
- `torch.load()` executes arbitrary Python code by default
- Mitigation: `torch.load(weights_only=True)` prevents code execution
- Many tools and tutorials still use unsafe loading

**2. Safetensors backdoors**
- Even safetensors format isn't immune
- Attacker can poison training data or embed backdoors in weight matrices
- "Sleeping agent" models: behave normally during evaluation, activate on triggers

**3. Tokenizer poisoning**
- Malicious tokenizer config can cause unexpected behavior
- Custom tokenizer files can embed malicious Python code
- BPE merge tables can be crafted to produce attacker-controlled output

**4. Weight steganography**
- Malicious payloads hidden in model weights using steganographic techniques
- Model behaves normally on standard benchmarks but activates on specific input triggers

### Real-World Examples

- **Sleeping agent models:** Researchers demonstrated models that behave normally during evaluation but activate malicious behavior on specific triggers
- **Actual malicious models on HuggingFace:** Backdoored models found that exfiltrate data or execute code
- **Fake AI repos:** Repositories impersonating popular models with malicious payloads

### Mitigations

- Always scan models before loading (`picklescan`, `modelscan`)
- Prefer safetensors format over pickle
- Verify model checksums against known-good sources
- Run model inference in sandboxed/containerized environments
- Use `torch.load(weights_only=True)` to prevent arbitrary code execution
- Check model card, author reputation, download counts, and community reviews
- Monitor for unexpected network activity during model loading/inference

### Detection Tools

- `picklescan`: https://github.com/mmaitre3197/picklescan
- `modelscan`: https://github.com/protectai/modelscan
- HuggingFace's built-in scanning (automatic on upload)
