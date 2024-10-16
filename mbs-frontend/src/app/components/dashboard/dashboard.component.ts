import { Component, OnInit } from '@angular/core';
import { UserService } from '../../services/user-service/user.service';
import { User } from '../../models/user.model';
import { LoginResponse } from '../../models/login-response.model';
import { Router } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent implements OnInit{
  user!: User;
  loginResponse!: LoginResponse;
  constructor(
    private userService:UserService,
    private router:Router
  ){}
  ngOnInit(): void {
      this.userService.getCurrentUser().subscribe(  (user) => {
        this.user = user;
      },
      (error) => {
        console.error('Error fetching user details', error);
      });
        
  }
onLogout(){
  this.userService.logoutUser().subscribe((data) => {
    this.loginResponse=data;
    console.log("logged out");
    this.router.navigate(['/login'])
    
  },
  (error) => {
    console.error('Error logging out', error);
  });
}
}
