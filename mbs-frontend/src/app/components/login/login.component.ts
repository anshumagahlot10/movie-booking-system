import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { customEmailValidator } from '../../validators/email-validator';
import { noWhitespaceValidator } from '../../validators/no-whitespace-validator';
import { UserService } from '../../services/user-service/user.service';
import { LoginRequest } from '../../models/login-request.model';
import { LoginResponse } from '../../models/login-response.model';



@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, RouterLink
    , ReactiveFormsModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent implements OnInit{
  loginForm: FormGroup;
  passwordFieldType: string = 'password';
  incorrect: boolean = false;
  errorMessage: string = '';
  authBaseUrl: string = 'YOUR_GOOGLE_AUTH_URL'; // Replace with your actual Google Auth URL

  constructor(
    private fb: FormBuilder,
    private userService: UserService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required]
    });
  }

  ngOnInit(): void {
    // You can add any initialization logic here
    this.createForm();
    this.subscribeToFormChanges();
  }
  createForm(): void {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, customEmailValidator()]],
      password: ['', [Validators.required, noWhitespaceValidator('Password', null, null)]],
    });
  }

  // execute functionality as soon as change in form details

  // execute functionality as soon as change in form details
  subscribeToFormChanges(): void {
    this.loginForm.valueChanges.subscribe(() => {
      this.incorrect = false;
      this.errorMessage = '';
    });
  }

  // toggle password visibility
  togglePasswordVisibility(): void {
    this.passwordFieldType =
      this.passwordFieldType === 'password' ? 'text' : 'password';
  }

  /**
   * authenticates the user details and logs in the user then navigates to homepage
  */

  login(): void {

    if (this.loginForm.valid) {
      const loginRequest: LoginRequest = {
          email: this.loginForm.value.email.trim(),
          password: this.loginForm.value.password.trim()
      };

      this.userService.loginUser(loginRequest).subscribe({
          next: (response: LoginResponse) => {
              if (response.isLogged) {
                  this.router.navigate(['/']);
                  console.log("Login Successful")
              } else {
                  this.errorMessage = 'Login failed. Please try again.';
                  this.incorrect = true;
              }
          },
          error: (error) => {
              this.errorMessage = error.error.message || 'Login failed. Please try again.';
              this.incorrect = true;
          }
      });
  } else {
      this.incorrect = true;
      this.errorMessage = 'Please fill in the required fields.';
  }
  }
  resendVerification(): void {
  
  }
}
