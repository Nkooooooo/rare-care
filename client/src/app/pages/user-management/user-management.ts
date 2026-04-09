import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Auth } from '../../core/auth';
import { I18n } from '../../core/i18n';
import { AdminCreateUserForm, AdminUpdateUserForm, AdminUser, Locale } from '../../models';

type ModalMode = '' | 'create' | 'detail';

@Component({
  selector: 'app-user-management',
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './user-management.html',
  styleUrl: './user-management.css',
})
export class UserManagement implements OnInit, OnDestroy {
  private readonly auth = inject(Auth);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  currentUser = this.auth.user;
  users: AdminUser[] = [];
  createForm: AdminCreateUserForm = this.defaultCreateForm();
  detailForm: AdminUpdateUserForm = this.defaultDetailForm();
  selectedUser: AdminUser | null = null;
  activeModal: ModalMode = '';
  isLoading = true;
  isSaving = false;
  dashboardFeedback: { status: 'success' | 'error'; message: string } | null = null;
  modalFeedback: { status: 'success' | 'error'; message: string } | null = null;

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
        this.currentUser = user;
        if (this.isAdmin()) {
          this.loadUsers();
        } else {
          this.users = [];
          this.isLoading = false;
          this.closeModal();
          this.syncView();
        }
      }),
    );
  }

  ngOnDestroy() {
    this.subscriptions.unsubscribe();
  }

  routeTo(path = '') {
    return path || '/';
  }

  isAdmin() {
    return this.currentUser?.role === 'admin';
  }

  openCreateModal() {
    this.activeModal = 'create';
    this.createForm = this.defaultCreateForm();
    this.modalFeedback = null;
    this.isSaving = false;
    this.syncView();
  }

  openUser(user: AdminUser) {
    this.selectedUser = user;
    this.activeModal = 'detail';
    this.detailForm = {
      username: user.username,
      role: user.role,
      password: '',
    };
    this.modalFeedback = null;
    this.isSaving = false;
    this.syncView();
  }

  closeModal() {
    this.activeModal = '';
    this.selectedUser = null;
    this.createForm = this.defaultCreateForm();
    this.detailForm = this.defaultDetailForm();
    this.modalFeedback = null;
    this.isSaving = false;
    this.syncView();
  }

  isCreateValid() {
    return (
      this.createForm.name.trim().length > 1 &&
      /^[a-zA-Z0-9._-]{3,32}$/.test(this.createForm.username.trim()) &&
      this.createForm.email.includes('@') &&
      this.createForm.password.length >= 8
    );
  }

  isDetailValid() {
    const password = this.detailForm.password || '';
    return (
      !!this.selectedUser &&
      /^[a-zA-Z0-9._-]{3,32}$/.test(this.detailForm.username.trim()) &&
      (password.length === 0 || password.length >= 8)
    );
  }

  createUser() {
    if (!this.isAdmin() || !this.isCreateValid()) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    this.auth
      .createAdminUser({
        name: this.createForm.name.trim(),
        username: this.createForm.username.trim().toLowerCase(),
        email: this.createForm.email.trim(),
        password: this.createForm.password,
      })
      .subscribe({
        next: ({ user }) => {
          this.users = this.sortUsers([user, ...this.users]);
          this.dashboardFeedback = { status: 'success', message: this.dictionary.admin.created };
          this.closeModal();
          this.syncView();
        },
        error: (error) => {
          this.modalFeedback = {
            status: 'error',
            message: error.error?.message || this.dictionary.common.generalError,
          };
          this.isSaving = false;
          this.syncView();
        },
      });
  }

  saveUser() {
    if (!this.isAdmin() || !this.selectedUser || !this.isDetailValid()) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    this.auth
      .updateAdminUser(this.selectedUser.id, {
        username: this.detailForm.username.trim().toLowerCase(),
        role: this.detailForm.role,
        password: this.detailForm.password?.trim() || '',
      })
      .subscribe({
        next: ({ user }) => {
          this.users = this.sortUsers(this.users.map((item) => (item.id === user.id ? user : item)));
          this.dashboardFeedback = { status: 'success', message: this.dictionary.admin.updated };
          this.closeModal();
          this.syncView();
        },
        error: (error) => {
          this.modalFeedback = {
            status: 'error',
            message: error.error?.message || this.dictionary.common.generalError,
          };
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

  private loadUsers() {
    this.isLoading = true;
    this.dashboardFeedback = null;
    this.auth.getAdminUsers().subscribe({
      next: ({ users }) => {
        this.users = this.sortUsers(users);
        this.isLoading = false;
        this.syncView();
      },
      error: (error) => {
        this.users = [];
        this.isLoading = false;
        this.dashboardFeedback = {
          status: 'error',
          message: error.error?.message || this.dictionary.common.generalError,
        };
        this.syncView();
      },
    });
  }

  private sortUsers(users: AdminUser[]) {
    return [...users].sort((left, right) => {
      if (left.role !== right.role) {
        return left.role === 'admin' ? -1 : 1;
      }

      return left.name.localeCompare(right.name, this.locale);
    });
  }

  private defaultCreateForm(): AdminCreateUserForm {
    return {
      name: '',
      username: '',
      email: '',
      password: '',
    };
  }

  private defaultDetailForm(): AdminUpdateUserForm {
    return {
      username: '',
      role: 'user',
      password: '',
    };
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
