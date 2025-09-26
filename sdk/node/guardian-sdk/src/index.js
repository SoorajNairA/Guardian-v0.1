export class Guardian {
  constructor({ apiKey, baseUrl = process.env.GUARDIAN_BASE_URL || "http://localhost:8000", timeoutMs = 10000, maxRetries = 3 } = {}) {
    this.apiKey = apiKey || process.env.GUARDIAN_API_KEY || "";
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.timeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
  }

  async analyze(text, { model_version, compliance_mode } = {}) {
    if (!this.apiKey) throw new Error("Missing API key");
    const payload = { text };
    const config = {};
    if (model_version) config.model_version = model_version;
    if (compliance_mode) config.compliance_mode = compliance_mode;
    if (Object.keys(config).length) payload.config = config;

    const url = `${this.baseUrl}/v1/analyze`;
    const headers = { "Content-Type": "application/json", "X-API-Key": this.apiKey };

    let attempt = 0;
    let backoff = 500;
    while (true) {
      try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), this.timeoutMs);
        const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload), signal: controller.signal });
        clearTimeout(id);
        if (res.status >= 500 && attempt < this.maxRetries) throw new Error(`Server error ${res.status}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
      } catch (err) {
        attempt += 1;
        if (attempt > this.maxRetries) throw err;
        await new Promise(r => setTimeout(r, backoff));
        backoff = Math.min(4000, backoff * 2);
      }
    }
  }
}



