import { Component, OnInit } from '@angular/core';
import { UserService } from '../../services/user-service/user.service';
import { User } from '../../models/user.model';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { LoginResponse } from '../../models/login-response.model';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule,ReactiveFormsModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css'] // Fixed 'styleUrl' to 'styleUrls'
})
export class DashboardComponent implements OnInit {
  profileForm: FormGroup;
  isEditing: boolean = false;
  loginResponse!: LoginResponse;
  constructor(private fb: FormBuilder, private userService: UserService, private router: Router) {
    // Initialize the form with default values and validators
    this.profileForm = this.fb.group({
      email: [{ value: '', disabled: true }, [Validators.required, Validators.email]],
      phone: ['', [Validators.pattern(/^[0-9]{10}$/)]],
      firstName: ['', Validators.required],
      lastName: ['', Validators.required],
      birthday: [''],
      identity: [''],
      address: this.fb.group({
        pincode: ['', ],
        city: ['', ],
        state: ['',]
      })
    });
  }

  ngOnInit(): void {
    this.fetchUserDetails();
    this.subscribeToFormChanges();
  }

  fetchUserDetails() {
    this.userService.getCurrentUser().subscribe(
      (user: User) => {
        console.log("Data received from 'api/user':", user);
        // Populate the form with user details
        this.profileForm.patchValue({
          email: user.email,
          firstName: user.name.split(' ')[0], // Adjust as necessary based on your actual name format
          lastName: user.name.split(' ')[1], // Assuming name format: "First Last"
          phone: user.phone,
          address: {
            // pincode: user.address?.pincode || '', // Optional chaining in case address is undefined
            // city: user.address?.city || '',
            // state: user.address?.state || ''
          }
          // Additional fields can be populated as required
        });
      },
      (error) => {
        console.log("Error fetching user data in dashboard:", error);
        // Handle error appropriately, e.g., redirect to login or show an error message
      }
    );
  }

  subscribeToFormChanges(): void {
    this.profileForm.valueChanges.subscribe(() => {
      // Reset any form-specific error states if needed
    });
  }

  toggleEdit() {
    this.isEditing = !this.isEditing; // Toggle edit mode
  }

  onFormSubmit() {
    if (this.profileForm.valid) {
      const userDetails = this.profileForm.getRawValue();
      console.log('Updated User details:', userDetails);
      // Optionally, you can send updated data back to the server
      this.toggleEdit(); // Exit edit mode after submission
    } else {
      console.log("Form is invalid. Please check the input fields.");
    }
  }
  onLogout(){
    this.userService.logoutUser().subscribe((data) => {
      this.loginResponse=data;
      console.log("logged out");
      this.router.navigate(['/login'])
      
    },
    (error) => {
      console.error('Error logging out', error);
  }
);
  }}