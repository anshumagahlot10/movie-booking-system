import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SideImageLayoutComponent } from './side-image-layout.component';

describe('SideImageLayoutComponent', () => {
  let component: SideImageLayoutComponent;
  let fixture: ComponentFixture<SideImageLayoutComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SideImageLayoutComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SideImageLayoutComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
