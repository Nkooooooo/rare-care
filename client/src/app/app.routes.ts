import { Routes } from '@angular/router';

import { Community } from './pages/community/community';
import { ContentManagement } from './pages/content-management/content-management';
import { Contact } from './pages/contact/contact';
import { DailyCorner } from './pages/daily-corner/daily-corner';
import { DiseaseDetail } from './pages/disease-detail/disease-detail';
import { DiseaseList } from './pages/disease-list/disease-list';
import { Donation } from './pages/donation/donation';
import { Events } from './pages/events/events';
import { Home } from './pages/home/home';
import { Legal } from './pages/legal/legal';
import { Profile } from './pages/profile/profile';
import { UserManagement } from './pages/user-management/user-management';

export const routes: Routes = [
  { path: '', component: Home },
  { path: 'disease-information', component: DiseaseList },
  { path: 'disease-information/:slug', component: DiseaseDetail },
  { path: 'daily-corner', component: DailyCorner },
  { path: 'events', component: Events },
  { path: 'donation', component: Donation },
  { path: 'community', component: Community },
  { path: 'contact', component: Contact },
  { path: 'profile', component: Profile },
  { path: 'user-management', component: UserManagement },
  { path: 'event-management', component: ContentManagement, data: { kind: 'events' } },
  { path: 'daily-corner-management', component: ContentManagement, data: { kind: 'daily-corner' } },
  { path: 'disease-management', component: ContentManagement, data: { kind: 'diseases' } },
  { path: 'content-management', redirectTo: 'event-management', pathMatch: 'full' },
  { path: 'privacy-policy', component: Legal, data: { kind: 'privacy' } },
  { path: 'disclaimer', component: Legal, data: { kind: 'disclaimer' } },
  { path: 'accessibility', redirectTo: '', pathMatch: 'full' },
  { path: 'mn', redirectTo: '', pathMatch: 'full' },
  { path: 'mn/disease-information', redirectTo: 'disease-information' },
  { path: 'mn/disease-information/:slug', redirectTo: 'disease-information/:slug' },
  { path: 'mn/daily-corner', redirectTo: 'daily-corner' },
  { path: 'mn/events', redirectTo: 'events' },
  { path: 'mn/donation', redirectTo: 'donation' },
  { path: 'mn/community', redirectTo: 'community' },
  { path: 'mn/contact', redirectTo: 'contact' },
  { path: 'mn/profile', redirectTo: 'profile' },
  { path: 'mn/user-management', redirectTo: 'user-management' },
  { path: 'mn/event-management', redirectTo: 'event-management' },
  { path: 'mn/daily-corner-management', redirectTo: 'daily-corner-management' },
  { path: 'mn/disease-management', redirectTo: 'disease-management' },
  { path: 'mn/content-management', redirectTo: 'event-management' },
  { path: 'mn/privacy-policy', redirectTo: 'privacy-policy' },
  { path: 'mn/disclaimer', redirectTo: 'disclaimer' },
  { path: 'mn/accessibility', redirectTo: '', pathMatch: 'full' },
  { path: 'en', redirectTo: '', pathMatch: 'full' },
  { path: 'en/disease-information', redirectTo: 'disease-information' },
  { path: 'en/disease-information/:slug', redirectTo: 'disease-information/:slug' },
  { path: 'en/daily-corner', redirectTo: 'daily-corner' },
  { path: 'en/events', redirectTo: 'events' },
  { path: 'en/donation', redirectTo: 'donation' },
  { path: 'en/community', redirectTo: 'community' },
  { path: 'en/contact', redirectTo: 'contact' },
  { path: 'en/profile', redirectTo: 'profile' },
  { path: 'en/user-management', redirectTo: 'user-management' },
  { path: 'en/event-management', redirectTo: 'event-management' },
  { path: 'en/daily-corner-management', redirectTo: 'daily-corner-management' },
  { path: 'en/disease-management', redirectTo: 'disease-management' },
  { path: 'en/content-management', redirectTo: 'event-management' },
  { path: 'en/privacy-policy', redirectTo: 'privacy-policy' },
  { path: 'en/disclaimer', redirectTo: 'disclaimer' },
  { path: 'en/accessibility', redirectTo: '', pathMatch: 'full' },
  { path: '**', redirectTo: '' },
];
