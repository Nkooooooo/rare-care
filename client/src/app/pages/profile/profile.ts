import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Auth } from '../../core/auth';
import { I18n } from '../../core/i18n';
import { AuthUser, Locale, UpdateProfileForm } from '../../models';

@Component({
  selector: 'app-profile',
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './profile.html',
  styleUrl: './profile.css',
})
export class Profile implements OnInit, OnDestroy {
  private readonly auth = inject(Auth);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();
  private readonly maxImageBytes = 4 * 1024 * 1024;

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  user: AuthUser | null = this.auth.user;
  form: UpdateProfileForm = { name: '', profileImageUrl: '' };
  selectedPhotoName = '';
  isUploadingPhoto = false;
  isSaving = false;
  feedback: { status: 'success' | 'error'; message: string } | null = null;

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.syncView();
      }),
    );

    this.subscriptions.add(
      this.auth.user$.subscribe((user) => {
        this.user = user;
        this.form = {
          name: user?.name || '',
          profileImageUrl: user?.profileImageUrl || '',
        };
        this.selectedPhotoName = '';
        this.syncView();
      }),
    );
  }

  ngOnDestroy() {
    this.subscriptions.unsubscribe();
  }

  routeTo(path = '') {
    return path || '/';
  }

  profileImage() {
    return this.form.profileImageUrl?.trim() || this.user?.profileImageUrl?.trim() || '/profile-icon.png';
  }

  isValid() {
    return this.form.name.trim().length > 1;
  }

  preparePhotoInput(input: HTMLInputElement) {
    input.value = '';
  }

  uploadPhoto(event: Event) {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) {
      return;
    }

    if (!file.type.startsWith('image/')) {
      this.feedback = { status: 'error', message: this.dictionary.profile.photoTypeError };
      input.value = '';
      return;
    }

    if (file.size > this.maxImageBytes) {
      this.feedback = { status: 'error', message: this.dictionary.profile.photoSizeError };
      input.value = '';
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const imageDataUrl = typeof reader.result === 'string' ? reader.result : '';
      if (!imageDataUrl) {
        this.feedback = { status: 'error', message: this.dictionary.common.submitError };
        return;
      }

      this.form.profileImageUrl = imageDataUrl;
      this.selectedPhotoName = file.name;
      this.feedback = null;
      this.isUploadingPhoto = true;

      this.auth.updateProfilePhoto(imageDataUrl).subscribe({
        next: ({ user }) => {
          this.form.profileImageUrl = user.profileImageUrl || '';
          this.feedback = null;
          this.isUploadingPhoto = false;
          this.syncView();
        },
        error: () => {
          this.form.profileImageUrl = this.user?.profileImageUrl || '';
          this.feedback = { status: 'error', message: this.dictionary.common.submitError };
          this.isUploadingPhoto = false;
          this.syncView();
        },
      });
    };
    reader.onerror = () => {
      this.feedback = { status: 'error', message: this.dictionary.common.submitError };
    };
    reader.readAsDataURL(file);
    input.value = '';
  }

  removePhoto() {
    this.form.profileImageUrl = '';
    this.selectedPhotoName = '';
    this.feedback = null;
    this.isUploadingPhoto = true;

    this.auth.updateProfilePhoto('').subscribe({
      next: ({ user }) => {
        this.form.profileImageUrl = user.profileImageUrl || '';
        this.isUploadingPhoto = false;
        this.syncView();
      },
      error: () => {
        this.form.profileImageUrl = this.user?.profileImageUrl || '';
        this.feedback = { status: 'error', message: this.dictionary.common.submitError };
        this.isUploadingPhoto = false;
        this.syncView();
      },
    });
  }

  save() {
    if (!this.user || !this.isValid()) {
      return;
    }

    this.isSaving = true;
    this.feedback = null;
    this.auth
      .updateProfile({
        name: this.form.name.trim(),
        profileImageUrl: this.form.profileImageUrl?.trim() || '',
      })
      .subscribe({
        next: () => {
          this.feedback = { status: 'success', message: this.dictionary.profile.success };
          this.isSaving = false;
          this.syncView();
        },
        error: () => {
          this.feedback = { status: 'error', message: this.dictionary.common.submitError };
          this.isSaving = false;
          this.syncView();
        },
      });
  }

  formatJoinedDate(value: string) {
    return new Intl.DateTimeFormat(this.locale === 'mn' ? 'mn-MN' : 'en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }).format(new Date(value));
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
