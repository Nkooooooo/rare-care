import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';

import {
  AdminDailyCornerForm,
  AdminDiseaseForm,
  AdminCreateUserForm,
  AdminEventForm,
  AdminUpdateUserForm,
  AdminUser,
  AuthResponse,
  AuthUser,
  ContactForm,
  DailyCornerEntry,
  DiseaseBrowseResponse,
  Disease,
  DonationForm,
  EventItem,
  EventRegistrationForm,
  Locale,
  LoginForm,
  RegisterForm,
  UpdateProfileForm,
} from '../models';

@Injectable({ providedIn: 'root' })
export class Api {
  private readonly http = inject(HttpClient);

  getDiseases(
    locale: Locale,
    filters: { query?: string; category?: string; letter?: string; sort?: string; page?: number } = {},
  ) {
    let params = new HttpParams().set('locale', locale);
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        params = params.set(key, String(value));
      }
    });

    return this.http.get<DiseaseBrowseResponse>('/api/diseases', { params });
  }

  getDiseaseCategories(locale: Locale) {
    return this.http.get<{ categories: DiseaseBrowseResponse['categories'] }>('/api/diseases/categories', {
      params: { locale },
    });
  }

  getDisease(locale: Locale, slug: string) {
    return this.http.get<Disease>(`/api/diseases/${locale}/${slug}`);
  }

  getDailyCornerEntries(locale: Locale) {
    return this.http.get<DailyCornerEntry[]>('/api/daily-corner', { params: { locale } });
  }

  getEvents(locale: Locale) {
    return this.http.get<EventItem[]>('/api/events', { params: { locale } });
  }

  createEventRegistration(eventId: string, form: EventRegistrationForm) {
    return this.http.post<{ id: string; createdAt: string }>(
      `/api/events/${eventId}/registrations`,
      form,
    );
  }

  createDonation(form: DonationForm) {
    return this.http.post<{ id: string; status: string; createdAt: string }>(
      '/api/donations',
      form,
    );
  }

  createContactMessage(form: ContactForm) {
    return this.http.post<ContactForm & { id: string; createdAt: string }>('/api/contact', form);
  }

  register(form: RegisterForm) {
    return this.http.post<AuthResponse>('/api/auth/register', form);
  }

  login(form: LoginForm) {
    return this.http.post<AuthResponse>('/api/auth/login', form);
  }

  getAdminUsers(token: string) {
    return this.http.get<{ users: AdminUser[] }>('/api/admin/users', {
      headers: { 'x-auth-token': token },
    });
  }

  createAdminUser(token: string, form: AdminCreateUserForm) {
    return this.http.post<{ user: AdminUser }>('/api/admin/users', form, {
      headers: { 'x-auth-token': token },
    });
  }

  createAdminEvent(token: string, form: AdminEventForm) {
    return this.http.post<{ id: string; createdAt: string }>('/api/admin/events', form, {
      headers: { 'x-auth-token': token },
    });
  }

  getAdminEvents(token: string) {
    return this.http.get<EventItem[]>('/api/admin/events', {
      headers: { 'x-auth-token': token },
    });
  }

  updateAdminEvent(token: string, eventId: string, form: AdminEventForm) {
    return this.http.patch<{ event: EventItem }>(`/api/admin/events/${eventId}`, form, {
      headers: { 'x-auth-token': token },
    });
  }

  deleteAdminEvent(token: string, eventId: string) {
    return this.http.delete<{ id: string }>(`/api/admin/events/${eventId}`, {
      headers: { 'x-auth-token': token },
    });
  }

  createAdminDailyCornerEntry(token: string, form: AdminDailyCornerForm) {
    return this.http.post<{ id: string; createdAt: string }>('/api/admin/daily-corner', form, {
      headers: { 'x-auth-token': token },
    });
  }

  getAdminDailyCornerEntries(token: string) {
    return this.http.get<DailyCornerEntry[]>('/api/admin/daily-corner', {
      headers: { 'x-auth-token': token },
    });
  }

  updateAdminDailyCornerEntry(token: string, entryId: string, form: AdminDailyCornerForm) {
    return this.http.patch<{ entry: DailyCornerEntry }>(`/api/admin/daily-corner/${entryId}`, form, {
      headers: { 'x-auth-token': token },
    });
  }

  deleteAdminDailyCornerEntry(token: string, entryId: string) {
    return this.http.delete<{ id: string }>(`/api/admin/daily-corner/${entryId}`, {
      headers: { 'x-auth-token': token },
    });
  }

  createAdminDisease(token: string, form: AdminDiseaseForm) {
    return this.http.post<{ id: string; slug: string; updatedAt: string }>('/api/admin/diseases', form, {
      headers: { 'x-auth-token': token },
    });
  }

  getAdminDiseases(token: string) {
    return this.http.get<Disease[]>('/api/admin/diseases', {
      headers: { 'x-auth-token': token },
    });
  }

  updateAdminDisease(token: string, diseaseId: string, form: AdminDiseaseForm) {
    return this.http.patch<{ disease: Disease }>(`/api/admin/diseases/${diseaseId}`, form, {
      headers: { 'x-auth-token': token },
    });
  }

  deleteAdminDisease(token: string, diseaseId: string) {
    return this.http.delete<{ id: string }>(`/api/admin/diseases/${diseaseId}`, {
      headers: { 'x-auth-token': token },
    });
  }

  updateAdminUser(token: string, userId: string, form: AdminUpdateUserForm) {
    return this.http.patch<{ user: AdminUser }>(`/api/admin/users/${userId}`, form, {
      headers: { 'x-auth-token': token },
    });
  }

  promoteUserToAdmin(token: string, userId: string) {
    return this.http.patch<{ user: AdminUser }>(
      `/api/admin/users/${userId}/role`,
      { role: 'admin' },
      {
        headers: { 'x-auth-token': token },
      },
    );
  }

  updateProfile(token: string, form: UpdateProfileForm) {
    return this.http.patch<{ user: AuthUser }>('/api/auth/profile', form, {
      headers: { 'x-auth-token': token },
    });
  }

  updateProfilePhoto(token: string, profileImageUrl: string) {
    return this.http.patch<{ user: AuthUser }>(
      '/api/auth/profile/photo',
      { profileImageUrl },
      {
        headers: { 'x-auth-token': token },
      },
    );
  }

  getCurrentUser(token: string) {
    return this.http.get<{ user: AuthUser }>('/api/auth/me', {
      headers: { 'x-auth-token': token },
    });
  }

  logout(token: string) {
    return this.http.post<void>(
      '/api/auth/logout',
      {},
      {
        headers: { 'x-auth-token': token },
      },
    );
  }
}
