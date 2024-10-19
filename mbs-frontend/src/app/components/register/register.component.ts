import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { UserService } from '../../services/user-service/user.service';
import { Router, RouterLink } from '@angular/router';
import { customEmailValidator } from '../../validators/email-validator';
import { noWhitespaceValidator } from '../../validators/no-whitespace-validator';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule,ReactiveFormsModule,RouterLink,FormsModule],
  templateUrl: './register.component.html',
  styleUrl: './register.component.css'
})
export class RegisterComponent {
  userData!: FormGroup;
  passwordFieldType: string = 'password';
  errorMessage: string = '';

  constructor(
    private fb: FormBuilder,
    private userService: UserService,
    private router: Router,
  ) {}

  ngOnInit(): void {
    this.createForm();
    this.subscribeToFormChanges();
  }

  createForm(): void {
    this.userData = this.fb.group({
      name: ['', [Validators.required]], // Added name field
      username:['',Validators.required],
      email: ['', [Validators.required, customEmailValidator()]],
      phone: ['', [Validators.required]], // Added phone field
      // password: ['', [Validators.required, noWhitespaceValidator('Password', 4, 20)]]

      password: ['', [
        Validators.required,
        Validators.pattern(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!*()]).{6,}$/)
      ]],
      
    });
  }

  subscribeToFormChanges(): void {
    this.userData.get('email')?.valueChanges.subscribe(() => {
      this.errorMessage = '';
    });
  }

  togglePasswordVisibility(): void {
    this.passwordFieldType = this.passwordFieldType === 'password' ? 'text' : 'password';
  }

  onSubmit(): void {
    console.log('Form submitted'); 
    if (this.userData.valid) {
     const userRegister={
      name:this.userData.value.name,
      username:this.userData.value.username,
      email:this.userData.value.email,
      phone:this.userData.value.phone,
      password:this.userData.value.password
     }
     console.log(userRegister);
     this.userService.registerUser(userRegister).subscribe({
      next: () => {
        this.router.navigate(['/login']);
      },
      error: (err) => {
        // Log the entire error object for better debugging
        console.error('Registration error:', err);
        this.errorMessage = err.error.message || 'Registration failed';
      }
    });
    } else {
      this.markAllFieldsAsTouched();
    }
  }

  markAllFieldsAsTouched(): void {
    Object.keys(this.userData.controls).forEach(field => {
      const control = this.userData.get(field);
      if (control) {
        control.markAsTouched({ onlySelf: true });
      }
    });
  }

  


}
