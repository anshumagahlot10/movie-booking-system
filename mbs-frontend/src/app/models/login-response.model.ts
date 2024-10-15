
export interface LoginResponse {
    isLogged: boolean;  // Matches the backend record
    role: string | null;       // Matches the backend record
  }