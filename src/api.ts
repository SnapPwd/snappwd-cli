export interface CreateSecretRequest {
  encryptedSecret: string;
  expiration: number;
}

export interface CreateSecretResponse {
  secretId: string;
}

export interface GetSecretResponse {
  encryptedSecret: string;
}

export interface SecretPeekResponse {
  createdAt: number;
  ttlSeconds: number;
  metadata?: Record<string, any> | null;
}

export interface FileMetadata {
  originalFilename: string;
  contentType: string;
  iv: string; // Base64
}

export interface UploadFileRequest {
  metadata: FileMetadata;
  encryptedData: string; // Base64
  expiration: number;
}

export interface UploadFileResponse {
  fileId: string;
}

export interface GetFileResponse {
  metadata: FileMetadata;
  encryptedData: string; // Base64
}

export class SnapPwdApi {
  private baseUrl: string;

  constructor(baseUrl: string = "https://snappwd.io/api/v1") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, options);

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({ error: response.statusText }));
      throw new Error(`API Error (${response.status}): ${errorBody.error || response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  async createSecret(encryptedSecret: string, expiration: number = 3600): Promise<CreateSecretResponse> {
    return this.request<CreateSecretResponse>("/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ encryptedSecret, expiration }),
    });
  }

  async getSecret(id: string, peek: boolean = false): Promise<GetSecretResponse | SecretPeekResponse> {
    const url = peek ? `/secrets/${id}?peek=true` : `/secrets/${id}`;
    return this.request<GetSecretResponse | SecretPeekResponse>(url);
  }

  async uploadFile(
    metadata: FileMetadata,
    encryptedData: string,
    expiration: number = 86400
  ): Promise<UploadFileResponse> {
    return this.request<UploadFileResponse>("/files", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ metadata, encryptedData, expiration }),
    });
  }

  async getFile(id: string): Promise<GetFileResponse> {
    return this.request<GetFileResponse>(`/files/${id}`);
  }
}
