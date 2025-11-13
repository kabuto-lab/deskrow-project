// app/lib/api.ts
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api/v1';

class ApiClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = API_BASE_URL;
  }

  async request(endpoint: string, options: RequestInit = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    
    const config: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    };

    // Add auth token if available
    const token = localStorage.getItem('deskrow_token');
    if (token && !config.headers?.hasOwnProperty('Authorization')) {
      (config.headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, config);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
  }

  // Auth methods
  async login(username: string, password: string) {
    // Note: In the real app, password should be encrypted as in the original
    const encoder = new TextEncoder();
    const usernameData = encoder.encode(username);
    const usernameHashBuffer = await crypto.subtle.digest('SHA-256', usernameData);
    const usernameHashArray = Array.from(new Uint8Array(usernameHashBuffer));
    const usernameHash = usernameHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return this.request('/auth/signin', {
      method: 'POST',
      body: JSON.stringify({
        username_hash: usernameHash,
        password: password // In real implementation, this should be properly encrypted
      })
    });
  }

  async signup(username: string, password: string, alias: string) {
    const encoder = new TextEncoder();
    const usernameData = encoder.encode(username);
    const usernameHashBuffer = await crypto.subtle.digest('SHA-256', usernameData);
    const usernameHashArray = Array.from(new Uint8Array(usernameHashBuffer));
    const usernameHash = usernameHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return this.request('/auth/signup', {
      method: 'POST',
      body: JSON.stringify({
        username_hash: usernameHash,
        password_hash: await this.hashPassword(password),
        alias: alias
        // In real implementation: encrypt password properly as in the original
      })
    });
  }

  async checkUsername(username: string) {
    const encoder = new TextEncoder();
    const usernameData = encoder.encode(username);
    const usernameHashBuffer = await crypto.subtle.digest('SHA-256', usernameData);
    const usernameHashArray = Array.from(new Uint8Array(usernameHashBuffer));
    const usernameHash = usernameHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return this.request('/auth/check-username', {
      method: 'POST',
      body: JSON.stringify({
        username_hash: usernameHash
      })
    });
  }

  async logout() {
    return this.request('/auth/signout', {
      method: 'POST'
    });
  }

  // Identity methods
  async generateIdentity() {
    return this.request('/identity/generate', {
      method: 'POST'
    });
  }

  // Transaction methods
  async createTransaction(data: any) {
    return this.request('/transactions', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async getTransaction(hash: string) {
    return this.request(`/transactions/${hash}`, {
      method: 'GET'
    });
  }

  // Utility methods
  async getServerTime() {
    return this.request('/server-time', {
      method: 'GET'
    });
  }

  private async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

export const apiClient = new ApiClient();