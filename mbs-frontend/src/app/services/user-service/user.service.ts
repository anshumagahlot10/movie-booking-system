import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, of } from 'rxjs';
import { LoginRequest } from '../../models/login-request.model';
import { LoginResponse } from '../../models/login-response.model';
import { User } from '../../models/user.model';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private userServiceBaseUrl = "http://localhost:8080/api"; // Corrected format


  constructor(private http:HttpClient) { }
  
  public loginUser(user: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.userServiceBaseUrl}/auth/login`, user, { withCredentials: true });
}

 // Method to register a new user
 public registerUser(userRegister: { name: string; username:string,email: string; phone: string; password: string }): Observable<any> {
  return this.http.post(`${this.userServiceBaseUrl}/register`, userRegister);
  }
  public getCurrentUser():Observable<User>{
    return this.http.get<User>(`${this.userServiceBaseUrl}/user`, { withCredentials: true });
  }

  public logoutUser(): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.userServiceBaseUrl}/auth/logout`, {},{ withCredentials: true });
}
}
