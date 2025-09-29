import { Agent, fetch as undiciFetch } from "undici";
import debug from "debug";

const log = {
    client: debug("guardian:client"),
    request: debug("guardian:request"),
    retry: debug("guardian:retry"),
};

// --- Custom Errors ---

export class GuardianError extends Error {
    constructor(message) {
        super(message);
        this.name = "GuardianError";
    }
}

export class GuardianAPIError extends GuardianError {
    constructor(message, status, responseData) {
        super(`${message} (Status: ${status})`);
        this.name = "GuardianAPIError";
        this.status = status;
        this.responseData = responseData;
    }
}

export class GuardianTimeoutError extends GuardianError {
    constructor(message) {
        super(message);
        this.name = "GuardianTimeoutError";
    }
}

export class GuardianRateLimitError extends GuardianAPIError {
    constructor(message, status, responseData, retryAfter) {
        super(message, status, responseData);
        this.name = "GuardianRateLimitError";
        this.retryAfter = retryAfter;
    }
}

export class GuardianValidationError extends GuardianError {
    constructor(message) {
        super(message);
        this.name = "GuardianValidationError";
    }
}

// --- Guardian Client ---

export class Guardian {
    constructor(config = {}) {
        this.config = {
            apiKey: config.apiKey || process.env.GUARDIAN_API_KEY,
            baseUrl: (config.baseUrl || process.env.GUARDIAN_BASE_URL || "http://localhost:8000").replace(/\/$/, ""),
            timeoutMs: config.timeoutMs || 15000,
            maxRetries: config.maxRetries || 3,
            debug: config.debug || false,
            ...config,
        };

        if (!this.config.apiKey) {
            throw new GuardianValidationError("Missing API key. Provide `apiKey` in config or set GUARDIAN_API_KEY.");
        }

        if (this.config.debug) {
            this.enableDebugLogging();
        }

        this.fetch = typeof fetch !== "undefined" ? fetch : undiciFetch;
        this.agent = new Agent({ keepAliveTimeout: 10 * 1000, keepAliveMaxTimeout: 60 * 1000 });

        log.client("Guardian SDK initialized with base URL: %s", this.config.baseUrl);
    }

    enableDebugLogging() {
        debug.enable("guardian:*");
        log.client("Debug logging enabled.");
    }

    async analyze(text, options = {}) {
        if (!text || typeof text !== "string") {
            throw new GuardianValidationError("Input `text` must be a non-empty string.");
        }

        const payload = { text, ...options };
        const url = `${this.config.baseUrl}/v1/analyze`;
        const headers = {
            "X-API-Key": this.config.apiKey,
            "Content-Type": "application/json",
            "Accept": "application/json",
        };

        let lastError;

        for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

            try {
                log.request("Sending request to %s (attempt %d)", url, attempt + 1);
                const response = await this.fetch(url, {
                    method: "POST",
                    headers,
                    body: JSON.stringify(payload),
                    signal: controller.signal,
                    dispatcher: this.agent,
                });

                if (!response.ok) {
                    await this.handleHttpError(response);
                }

                const data = await response.json();
                log.request("Request successful", data);
                clearTimeout(timeoutId);
                return data;

            } catch (error) {
                clearTimeout(timeoutId);
                lastError = error;

                if (error.name === "AbortError") {
                    lastError = new GuardianTimeoutError(`Request timed out after ${this.config.timeoutMs}ms`);
                }

                if (attempt === this.config.maxRetries || !this.shouldRetry(error)) {
                    log.client("Request failed permanently: %s", lastError.message);
                    throw lastError;
                }

                const delay = this.calculateBackoff(attempt, error);
                log.retry("Request failed, retrying in %dms...", delay, { error: error.message });
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }

    async handleHttpError(response) {
        const responseData = await response.json().catch(() => ({ detail: "Could not parse error response." }));
        const { status } = response;

        if (status === 429) {
            const retryAfter = parseInt(response.headers.get("Retry-After") || "0", 10);
            throw new GuardianRateLimitError("Rate limit exceeded", status, responseData, retryAfter);
        }
        if (status >= 400 && status < 500) {
            throw new GuardianAPIError(`Client error: ${responseData.detail || "Unknown"}`, status, responseData);
        }
        if (status >= 500) {
            throw new GuardianAPIError(`Server error: ${responseData.detail || "Unknown"}`, status, responseData);
        }
    }

    shouldRetry(error) {
        if (error instanceof GuardianAPIError && error.status >= 400 && error.status !== 429 && error.status < 500) {
            return false; // Don't retry on most client errors
        }
        return true;
    }

    calculateBackoff(attempt, error) {
        if (error instanceof GuardianRateLimitError && error.retryAfter > 0) {
            return error.retryAfter * 1000; // Use server-provided value
        }
        const baseDelay = 1000;
        const exponentialBackoff = Math.pow(2, attempt) * baseDelay;
        const jitter = Math.random() * 500; // Add jitter
        return Math.min(exponentialBackoff + jitter, 10000); // Cap at 10 seconds
    }
}