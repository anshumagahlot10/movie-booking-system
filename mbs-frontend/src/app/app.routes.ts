import { Routes } from '@angular/router';
import { SideImageLayoutComponent } from './utils/side-image-layout/side-image-layout.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';

export const routes: Routes = [
    {path: '', redirectTo:'login',pathMatch:'full'},
    {path: '', component: SideImageLayoutComponent,
      children: [
        {path: 'login', component: LoginComponent},
        {path: 'register', component: RegisterComponent}
      ]
      },
     {path: 'dashboard', component: DashboardComponent}
];
