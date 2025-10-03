// Guardian API Client
// Handles all API interactions with the Guardian backend

export interface AnalysisConfig {
  model_version?: string;
  compliance_mode?: "strict" | "moderate" | "permissive";
}

export interface AnalysisRequest {
  text: string;
  config?: AnalysisConfig;
}

export interface ThreatDetection {
  category: string;
  confidence_score: number;
  details?: string;
}

export interface AnalysisMetadata {
  is_ai_generated?: boolean;
  language?: string;
  gemini_error?: string;
}

export interface AnalysisResponse {
  request_id: string;
  risk_score: number;
  threats_detected: ThreatDetection[];
  metadata: AnalysisMetadata;
}

export interface HealthDependency {
  name: string;
  status: "healthy" | "degraded" | "unhealthy";
  latency?: number;
  error?: string;
  last_check?: string;
}

export interface HealthResponse {
  status: "healthy" | "degraded" | "unhealthy";
  timestamp: string;
  dependencies: HealthDependency[];
  version?: string;
}

export interface MetricsResponse {
  [key: string]: any;
}

export interface RateLimitHeaders {
  limit?: string;
  remaining?: string;
  reset?: string;
  retryAfter?: string;
}

export interface ApiError {
  detail?: string;
  error?: string;
  message?: string;
}

class GuardianApiClient {
  private baseUrl: string;
  private apiKey: string;

  private normalizeBaseUrl(url: string): string {
    try {
      const trimmed = url.trim().replace(/\/$/, "");
      // If user accidentally includes endpoint path, strip known suffixes
      return trimmed
        .replace(/\/v1\/analyze$/, "")
        .replace(/\/v1$/, "");
    } catch {
      return url;
    }
  }

  constructor(baseUrl?: string, apiKey?: string) {
    const initialBase = baseUrl || import.meta.env.VITE_API_URL || 'http://localhost:8000';
    this.baseUrl = this.normalizeBaseUrl(initialBase);
    this.apiKey = apiKey || import.meta.env.VITE_GUARDIAN_API_KEY || '';
  }

  updateConfig(baseUrl: string, apiKey: string) {
    this.baseUrl = this.normalizeBaseUrl(baseUrl);
    this.apiKey = apiKey;
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }
    
    return headers;
  }

  private extractRateLimitHeaders(response: Response): RateLimitHeaders {
    return {
      limit: response.headers.get('X-RateLimit-Limit') || undefined,
      remaining: response.headers.get('X-RateLimit-Remaining') || undefined,
      reset: response.headers.get('X-RateLimit-Reset') || undefined,
      retryAfter: response.headers.get('Retry-After') || undefined,
    };
  }

  private async handleResponse<T>(response: Response): Promise<{ data: T; headers: RateLimitHeaders }> {
    const rateLimitHeaders = this.extractRateLimitHeaders(response);
    
    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}`;
      
      try {
        const errorData: ApiError = await response.json();
        errorMessage = errorData.detail || errorData.error || errorData.message || errorMessage;
      } catch {
        errorMessage = response.statusText || errorMessage;
      }
      
      const error = new Error(errorMessage) as Error & { status: number; headers: RateLimitHeaders };
      error.status = response.status;
      error.headers = rateLimitHeaders;
      throw error;
    }
    
    const data = await response.json();
    return { data, headers: rateLimitHeaders };
  }

  async analyze(request: AnalysisRequest): Promise<{ data: AnalysisResponse; headers: RateLimitHeaders }> {
    const response = await fetch(`${this.baseUrl}/v1/analyze`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(request),
    });
    
    return this.handleResponse<AnalysisResponse>(response);
  }

  async health(): Promise<{ data: HealthResponse; headers: RateLimitHeaders }> {
    const response = await fetch(`${this.baseUrl}/healthz`, {
      method: 'GET',
      headers: this.getHeaders(),
    });
    
    return this.handleResponse<HealthResponse>(response);
  }

  async metrics(): Promise<{ data: MetricsResponse; headers: RateLimitHeaders }> {
    const response = await fetch(`${this.baseUrl}/metrics`, {
      method: 'GET',
      headers: this.getHeaders(),
    });
    
    return this.handleResponse<MetricsResponse>(response);
  }
}

// Singleton instance
export const guardianApi = new GuardianApiClient();

// Hook for getting current configuration
export const getApiConfig = () => {
  const stored = localStorage.getItem('guardian-api-config');
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      return {
        baseUrl: parsed.baseUrl || import.meta.env.VITE_API_URL || 'http://localhost:8000',
        apiKey: parsed.apiKey || import.meta.env.VITE_GUARDIAN_API_KEY || '',
      };
    } catch {
      // Fall through to defaults
    }
  }
  
  return {
    baseUrl: import.meta.env.VITE_API_URL || 'http://localhost:8000',
    apiKey: import.meta.env.VITE_GUARDIAN_API_KEY || '',
  };
};

// Hook for updating configuration
export const updateApiConfig = (baseUrl: string, apiKey: string) => {
  localStorage.setItem('guardian-api-config', JSON.stringify({ baseUrl, apiKey }));
  guardianApi.updateConfig(baseUrl, apiKey);
};