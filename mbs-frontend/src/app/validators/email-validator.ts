import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

export function customEmailValidator(): ValidatorFn {
  const emailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;

  return (control: AbstractControl): ValidationErrors | null => {
    const valid = emailRegex.test(control.value);
    return valid ? null : { invalidEmail: true };
  };
}
