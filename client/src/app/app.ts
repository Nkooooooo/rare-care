import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, HostListener, OnDestroy, inject } from '@angular/core';
import { FormsModule, NgForm, NgModel } from '@angular/forms';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { Subscription, filter, finalize } from 'rxjs';

import { Dictionary } from './content';
import { Auth } from './core/auth';
import { I18n } from './core/i18n';
import { Theme, ThemeMode } from './core/theme';
import { AuthUser, Locale, LoginForm, RegisterForm } from './models';

type AuthMode = 'login' | 'register';

@Component({
  selector: 'app-root',
  imports: [CommonModule, FormsModule, RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App implements OnDestroy {
  private readonly router = inject(Router);
  private readonly auth = inject(Auth);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly theme = inject(Theme);
  private readonly subscriptions = new Subscription();

  protected locale: Locale = this.i18n.locale;
  protected dictionary: Dictionary = this.i18n.dictionary;
  protected themeMode: ThemeMode = this.theme.mode;
  protected authUser: AuthUser | null = this.auth.user;
  protected authMenuOpen = false;
  protected menuOpen = false;
  protected authModalOpen = false;
  protected authMode: AuthMode = 'login';
  protected authPending = false;
  protected authError = '';
  protected searchQuery = '';
  protected loginForm: LoginForm = {
    identifier: '',
    password: '',
  };
  protected registerForm: RegisterForm & { confirmPassword: string } = {
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
  };

  protected readonly navTargets = [
    { key: 'events', path: '/events', label: () => this.dictionary.nav.events },
    { key: 'dailyCorner', path: '/daily-corner', label: () => this.dictionary.nav.dailyCorner },
    { key: 'contact', path: '/contact', label: () => this.dictionary.nav.contact },
    {
      key: 'diseaseInformation',
      path: '/disease-information',
      label: () => this.dictionary.nav.diseaseInformation,
    },
    { key: 'community', path: '/community', label: () => this.dictionary.nav.community },
  ];

  constructor() {
    this.auth.initialize();

    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
      }),
    );

    this.subscriptions.add(
      this.theme.mode$.subscribe(() => {
        this.themeMode = this.theme.mode;
      }),
    );

    this.subscriptions.add(
      this.auth.user$.subscribe((user) => {
        this.authUser = user;
        queueMicrotask(() => this.cdr.detectChanges());
      }),
    );

    this.subscriptions.add(
      this.router.events.pipe(filter((event) => event instanceof NavigationEnd)).subscribe(() => {
        this.menuOpen = false;
        this.authMenuOpen = false;
      }),
    );
  }

  ngOnDestroy() {
    this.subscriptions.unsubscribe();
  }

  protected route(path = '') {
    return path || '/';
  }

  protected submitSearch() {
    this.router.navigate([this.route('/disease-information')], {
      queryParams: { query: this.searchQuery || null },
    });
  }

  protected toggleMenu() {
    this.menuOpen = !this.menuOpen;
    this.authMenuOpen = false;
  }

  protected openAuthModal(mode: AuthMode) {
    this.authMode = mode;
    this.authModalOpen = true;
    this.authPending = false;
    this.authError = '';
    this.menuOpen = false;
    this.authMenuOpen = false;
  }

  protected closeAuthModal() {
    this.authModalOpen = false;
    this.authPending = false;
    this.authError = '';
  }

  protected switchAuthMode(mode: AuthMode) {
    this.authMode = mode;
    this.authError = '';
  }

  protected toggleLanguage() {
    this.i18n.toggleLocale();
  }

  protected toggleTheme() {
    this.theme.toggleTheme();
  }

  protected profileImage(user: AuthUser | null = this.authUser) {
    return user?.profileImageUrl?.trim() || '/profile-icon.png';
  }

  protected isAdmin(user: AuthUser | null = this.authUser) {
    return user?.role === 'admin';
  }

  protected toggleAuthMenu(event: MouseEvent) {
    event.stopPropagation();
    this.authMenuOpen = !this.authMenuOpen;
  }

  protected closeAuthMenu() {
    this.authMenuOpen = false;
  }

  protected languageIcon() {
    return this.locale === 'mn' ? '/mongolia.png' : '/english.png';
  }

  protected themeIcon() {
    return this.themeMode === 'light' ? '/sun.png' : '/moon.png';
  }

  protected nextLanguageLabel() {
    return this.locale === 'mn' ? 'Switch to English' : 'Монгол хэл рүү солих';
  }

  protected nextThemeLabel() {
    return this.themeMode === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
  }

  protected submitLogin(form: NgForm) {
    if (form.invalid) {
      this.authError = '';
      this.cdr.detectChanges();
      return;
    }

    this.authPending = true;
    this.authError = '';

    this.auth
      .login(this.loginForm)
      .pipe(
        finalize(() => {
          this.authPending = false;
          this.cdr.detectChanges();
        }),
      )
      .subscribe({
        next: () => {
          this.loginForm = { identifier: '', password: '' };
          this.closeAuthModal();
        },
        error: (error) => {
          this.authError = error.error?.message || this.dictionary.common.generalError;
        },
      });
  }

  protected submitRegister(form: NgForm) {
    if (form.invalid) {
      this.authError = '';
      this.cdr.detectChanges();
      return;
    }

    if (this.registerForm.password !== this.registerForm.confirmPassword) {
      this.authError = this.dictionary.auth.passwordMismatch;
      this.cdr.detectChanges();
      return;
    }

    this.authPending = true;
    this.authError = '';

    const { name, email, password } = this.registerForm;
    this.auth
      .register({ name, email, password })
      .pipe(
        finalize(() => {
          this.authPending = false;
          this.cdr.detectChanges();
        }),
      )
      .subscribe({
        next: () => {
          this.registerForm = { name: '', email: '', password: '', confirmPassword: '' };
          this.closeAuthModal();
        },
        error: (error) => {
          this.authError = error.error?.message || this.dictionary.common.generalError;
        },
      });
  }

  protected logout() {
    this.authMenuOpen = false;
    this.authPending = true;
    this.auth
      .logout()
      .pipe(
        finalize(() => {
          this.authPending = false;
          this.cdr.detectChanges();
        }),
      )
      .subscribe();
  }

  protected isFieldInvalid(field: NgModel, form: NgForm) {
    return !!field.invalid && (field.touched || form.submitted);
  }

  protected loginIdentifierError(field: NgModel, form: NgForm) {
    if (!this.isFieldInvalid(field, form)) {
      return '';
    }

    if (field.errors?.['required']) {
      return this.dictionary.auth.loginIdentifierRequired;
    }

    return '';
  }

  protected emailError(field: NgModel, form: NgForm) {
    if (!this.isFieldInvalid(field, form)) {
      return '';
    }

    if (field.errors?.['required']) {
      return this.dictionary.auth.emailRequired;
    }

    if (field.errors?.['email']) {
      return this.dictionary.auth.emailInvalid;
    }

    return '';
  }

  protected passwordError(field: NgModel, form: NgForm) {
    if (!this.isFieldInvalid(field, form)) {
      return '';
    }

    if (field.errors?.['required']) {
      return this.dictionary.auth.passwordRequired;
    }

    if (field.errors?.['minlength']) {
      return this.dictionary.auth.passwordMinLength;
    }

    return '';
  }

  protected registerNameError(field: NgModel, form: NgForm) {
    if (!this.isFieldInvalid(field, form)) {
      return '';
    }

    if (field.errors?.['required']) {
      return this.dictionary.auth.nameRequired;
    }

    if (field.errors?.['minlength']) {
      return this.dictionary.auth.nameMinLength;
    }

    return '';
  }

  protected confirmPasswordError(field: NgModel, form: NgForm) {
    if (field.errors?.['required'] && (field.touched || form.submitted)) {
      return this.dictionary.auth.confirmPasswordRequired;
    }

    if (field.errors?.['minlength'] && (field.touched || form.submitted)) {
      return this.dictionary.auth.passwordMinLength;
    }

    if ((field.touched || form.submitted) && this.registerForm.password !== this.registerForm.confirmPassword) {
      return this.dictionary.auth.passwordMismatch;
    }

    return '';
  }

  @HostListener('document:click')
  protected onDocumentClick() {
    this.authMenuOpen = false;
  }
}
