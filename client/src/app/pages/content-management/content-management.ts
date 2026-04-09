import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Auth } from '../../core/auth';
import { I18n } from '../../core/i18n';
import {
  AdminDailyCornerForm,
  AdminDiseaseForm,
  AdminEventForm,
  AuthUser,
  DailyCornerEntry,
  Disease,
  EventItem,
  Locale,
} from '../../models';

type ModalMode =
  | ''
  | 'create-event'
  | 'edit-event'
  | 'create-daily'
  | 'edit-daily'
  | 'create-disease'
  | 'edit-disease';

type DiseaseCauseDraft = {
  title: string;
  description: string;
  image: string;
};

type DiseaseSymptomDraft = {
  medicalTerm: string;
  description: string;
  synonymsText: string;
  frequency: string;
  bodySystem: string;
};

type DiseaseReferenceDraft = {
  title: string;
  url: string;
};

type DiseaseDraftForm = {
  locale: Locale;
  slug: string;
  name: string;
  aliasesText: string;
  category: string;
  shortDescription: string;
  summaryMedical: string;
  summarySimple: string;
  causes: DiseaseCauseDraft[];
  symptoms: DiseaseSymptomDraft[];
  references: DiseaseReferenceDraft[];
  published: boolean;
};

type ContentKind = 'events' | 'daily-corner' | 'diseases';

@Component({
  selector: 'app-content-management',
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './content-management.html',
  styleUrl: './content-management.css',
})
export class ContentManagement implements OnInit, OnDestroy {
  private readonly auth = inject(Auth);
  private readonly route = inject(ActivatedRoute);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  currentUser: AuthUser | null = this.auth.user;
  sectionKind: ContentKind = 'events';
  events: EventItem[] = [];
  dailyEntries: DailyCornerEntry[] = [];
  diseases: Disease[] = [];
  eventForm: AdminEventForm = this.defaultEventForm();
  dailyForm: AdminDailyCornerForm = this.defaultDailyForm();
  diseaseForm: DiseaseDraftForm = this.defaultDiseaseForm();
  activeModal: ModalMode = '';
  editingEventId = '';
  editingDailyId = '';
  editingDiseaseId = '';
  isLoading = true;
  isSaving = false;
  dashboardFeedback: { status: 'success' | 'error'; message: string } | null = null;
  modalFeedback: { status: 'success' | 'error'; message: string } | null = null;

  ngOnInit() {
    this.subscriptions.add(
      this.route.data.subscribe((data) => {
        this.sectionKind = this.resolveKind(data['kind']);
        if (this.isAdmin()) {
          this.loadDashboard();
        } else {
          this.syncView();
        }
      }),
    );

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
          this.loadDashboard();
        } else {
          this.resetDashboard();
          this.closeModal();
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

  pageTitle() {
    switch (this.sectionKind) {
      case 'daily-corner':
        return this.dictionary.admin.dailyDashboardTitle;
      case 'diseases':
        return this.dictionary.admin.diseasesDashboardTitle;
      default:
        return this.dictionary.admin.eventsDashboardTitle;
    }
  }

  pageBody() {
    switch (this.sectionKind) {
      case 'daily-corner':
        return this.dictionary.admin.dailyDashboardBody;
      case 'diseases':
        return this.dictionary.admin.diseasesDashboardBody;
      default:
        return this.dictionary.admin.eventsDashboardBody;
    }
  }

  statusLabel(published: boolean) {
    return published ? this.dictionary.admin.statusPublished : this.dictionary.admin.statusDraft;
  }

  countPublished(items: Array<{ published: boolean }>) {
    return items.filter((item) => item.published).length;
  }

  countDraft(items: Array<{ published: boolean }>) {
    return items.filter((item) => !item.published).length;
  }

  formatDate(value: string) {
    return new Intl.DateTimeFormat(this.locale === 'mn' ? 'mn-MN' : 'en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(new Date(value));
  }

  formatUpdatedDate(value: string) {
    return new Intl.DateTimeFormat(this.locale === 'mn' ? 'mn-MN' : 'en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(new Date(value));
  }

  openCreateEventModal() {
    this.activeModal = 'create-event';
    this.editingEventId = '';
    this.eventForm = this.defaultEventForm();
    this.resetModalState();
  }

  openEditEventModal(event: EventItem) {
    this.activeModal = 'edit-event';
    this.editingEventId = event.id;
    this.eventForm = {
      locale: event.locale,
      title: event.title,
      summary: event.summary,
      description: event.description || '',
      date: event.date,
      startTime: event.startTime || '',
      endTime: event.endTime || '',
      organizer: event.organizer || '',
      location: event.location || '',
      image: event.image || '',
      link: event.link || '',
      published: event.published,
    };
    this.resetModalState();
  }

  openCreateDailyModal() {
    this.activeModal = 'create-daily';
    this.editingDailyId = '';
    this.dailyForm = this.defaultDailyForm();
    this.resetModalState();
  }

  openEditDailyModal(entry: DailyCornerEntry) {
    this.activeModal = 'edit-daily';
    this.editingDailyId = entry.id;
    this.dailyForm = {
      locale: entry.locale,
      date: entry.date,
      title: entry.title,
      quote: entry.quote || '',
      body: entry.body,
      reminderTitle: entry.reminderTitle || '',
      reminderBody: entry.reminderBody || '',
      image: entry.image || '',
      audioUrl: entry.audioUrl || '',
      published: entry.published,
    };
    this.resetModalState();
  }

  openCreateDiseaseModal() {
    this.activeModal = 'create-disease';
    this.editingDiseaseId = '';
    this.diseaseForm = this.defaultDiseaseForm();
    this.resetModalState();
  }

  openEditDiseaseModal(disease: Disease) {
    this.activeModal = 'edit-disease';
    this.editingDiseaseId = disease.id;
    this.diseaseForm = {
      locale: disease.locale,
      slug: disease.slug,
      name: disease.name,
      aliasesText: (disease.aliases || []).join(', '),
      category: disease.category,
      shortDescription: disease.shortDescription,
      summaryMedical: disease.summaryMedical,
      summarySimple: disease.summarySimple,
      causes: (disease.causes || []).length
        ? disease.causes.map((cause) => ({
            title: cause.title,
            description: cause.description,
            image: cause.image || '',
          }))
        : [this.defaultCause()],
      symptoms: (disease.symptoms || []).length
        ? disease.symptoms.map((symptom) => ({
            medicalTerm: symptom.medicalTerm,
            description: symptom.description,
            synonymsText: (symptom.synonyms || []).join(', '),
            frequency: symptom.frequency || '',
            bodySystem: symptom.bodySystem || '',
          }))
        : [this.defaultSymptom()],
      references: (disease.references || []).length
        ? (disease.references || []).map((reference) => ({
            title: reference.title,
            url: reference.url,
          }))
        : [this.defaultReference()],
      published: disease.published,
    };
    this.resetModalState();
  }

  closeModal() {
    this.activeModal = '';
    this.editingEventId = '';
    this.editingDailyId = '';
    this.editingDiseaseId = '';
    this.eventForm = this.defaultEventForm();
    this.dailyForm = this.defaultDailyForm();
    this.diseaseForm = this.defaultDiseaseForm();
    this.modalFeedback = null;
    this.isSaving = false;
    this.syncView();
  }

  isEventValid() {
    return (
      this.eventForm.title.trim().length >= 3 &&
      this.eventForm.summary.trim().length >= 10 &&
      this.eventForm.date.trim().length >= 8
    );
  }

  isDailyValid() {
    return (
      this.dailyForm.title.trim().length >= 3 &&
      this.dailyForm.body.trim().length >= 20 &&
      this.dailyForm.date.trim().length >= 8
    );
  }

  isDiseaseValid() {
    return (
      this.diseaseForm.name.trim().length >= 3 &&
      this.diseaseForm.category.trim().length >= 2 &&
      this.diseaseForm.shortDescription.trim().length >= 10 &&
      this.diseaseForm.summaryMedical.trim().length >= 20 &&
      this.diseaseForm.summarySimple.trim().length >= 20
    );
  }

  saveEvent() {
    if (!this.isAdmin() || !this.isEventValid()) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    const payload: AdminEventForm = {
      locale: this.eventForm.locale,
      title: this.eventForm.title.trim(),
      summary: this.eventForm.summary.trim(),
      description: this.eventForm.description?.trim() || '',
      date: this.eventForm.date,
      startTime: this.eventForm.startTime?.trim() || '',
      endTime: this.eventForm.endTime?.trim() || '',
      organizer: this.eventForm.organizer?.trim() || '',
      location: this.eventForm.location?.trim() || '',
      image: this.eventForm.image?.trim() || '',
      link: this.eventForm.link?.trim() || '',
      published: this.eventForm.published,
    };

    if (this.editingEventId) {
      this.auth.updateAdminEvent(this.editingEventId, payload).subscribe({
        next: ({ event }) => {
          this.events = this.sortEvents(
            this.events.map((item) => (item.id === event.id ? event : item)),
          );
          this.dashboardFeedback = {
            status: 'success',
            message: this.dictionary.admin.eventUpdated,
          };
          this.closeModal();
        },
        error: (error: { error?: { message?: string } }) => this.handleModalError(error),
      });
      return;
    }

    this.auth.createAdminEvent(payload).subscribe({
      next: () => {
        this.loadDashboard();
        this.dashboardFeedback = {
          status: 'success',
          message: this.dictionary.admin.eventCreated,
        };
        this.closeModal();
      },
      error: (error: { error?: { message?: string } }) => this.handleModalError(error),
    });
  }

  deleteEvent() {
    if (!this.isAdmin() || !this.editingEventId) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    this.auth.deleteAdminEvent(this.editingEventId).subscribe({
      next: ({ id }) => {
        this.events = this.events.filter((item) => item.id !== id);
        this.dashboardFeedback = {
          status: 'success',
          message: this.dictionary.admin.eventDeleted,
        };
        this.closeModal();
      },
      error: (error) => this.handleModalError(error),
    });
  }

  saveDailyCorner() {
    if (!this.isAdmin() || !this.isDailyValid()) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    const payload: AdminDailyCornerForm = {
      locale: this.dailyForm.locale,
      date: this.dailyForm.date,
      title: this.dailyForm.title.trim(),
      quote: this.dailyForm.quote?.trim() || '',
      body: this.dailyForm.body.trim(),
      reminderTitle: this.dailyForm.reminderTitle?.trim() || '',
      reminderBody: this.dailyForm.reminderBody?.trim() || '',
      image: this.dailyForm.image?.trim() || '',
      audioUrl: this.dailyForm.audioUrl?.trim() || '',
      published: this.dailyForm.published,
    };

    if (this.editingDailyId) {
      this.auth.updateAdminDailyCornerEntry(this.editingDailyId, payload).subscribe({
        next: ({ entry }) => {
          this.dailyEntries = this.sortDailyEntries(
            this.dailyEntries.map((item) => (item.id === entry.id ? entry : item)),
          );
          this.dashboardFeedback = {
            status: 'success',
            message: this.dictionary.admin.dailyUpdated,
          };
          this.closeModal();
        },
        error: (error: { error?: { message?: string } }) => this.handleModalError(error),
      });
      return;
    }

    this.auth.createAdminDailyCornerEntry(payload).subscribe({
      next: () => {
        this.loadDashboard();
        this.dashboardFeedback = {
          status: 'success',
          message: this.dictionary.admin.dailyCreated,
        };
        this.closeModal();
      },
      error: (error: { error?: { message?: string } }) => this.handleModalError(error),
    });
  }

  deleteDailyCorner() {
    if (!this.isAdmin() || !this.editingDailyId) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    this.auth.deleteAdminDailyCornerEntry(this.editingDailyId).subscribe({
      next: ({ id }) => {
        this.dailyEntries = this.dailyEntries.filter((item) => item.id !== id);
        this.dashboardFeedback = {
          status: 'success',
          message: this.dictionary.admin.dailyDeleted,
        };
        this.closeModal();
      },
      error: (error) => this.handleModalError(error),
    });
  }

  saveDisease() {
    if (!this.isAdmin() || !this.isDiseaseValid()) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    const payload = this.buildDiseasePayload();
    if (this.editingDiseaseId) {
      this.auth.updateAdminDisease(this.editingDiseaseId, payload).subscribe({
        next: ({ disease }) => {
          this.diseases = this.sortDiseases(
            this.diseases.map((item) => (item.id === disease.id ? disease : item)),
          );
          this.dashboardFeedback = {
            status: 'success',
            message: this.dictionary.admin.diseaseUpdated,
          };
          this.closeModal();
        },
        error: (error: { error?: { message?: string } }) => this.handleModalError(error),
      });
      return;
    }

    this.auth.createAdminDisease(payload).subscribe({
      next: () => {
        this.loadDashboard();
        this.dashboardFeedback = {
          status: 'success',
          message: this.dictionary.admin.diseaseCreated,
        };
        this.closeModal();
      },
      error: (error: { error?: { message?: string } }) => this.handleModalError(error),
    });
  }

  deleteDisease() {
    if (!this.isAdmin() || !this.editingDiseaseId) {
      return;
    }

    this.isSaving = true;
    this.modalFeedback = null;
    this.auth.deleteAdminDisease(this.editingDiseaseId).subscribe({
      next: ({ id }) => {
        this.diseases = this.diseases.filter((item) => item.id !== id);
        this.dashboardFeedback = {
          status: 'success',
          message: this.dictionary.admin.diseaseDeleted,
        };
        this.closeModal();
      },
      error: (error) => this.handleModalError(error),
    });
  }

  addCause() {
    this.diseaseForm.causes = [...this.diseaseForm.causes, this.defaultCause()];
    this.syncView();
  }

  removeCause(index: number) {
    this.diseaseForm.causes = this.diseaseForm.causes.filter((_, itemIndex) => itemIndex !== index);
    if (!this.diseaseForm.causes.length) {
      this.diseaseForm.causes = [this.defaultCause()];
    }
    this.syncView();
  }

  addSymptom() {
    this.diseaseForm.symptoms = [...this.diseaseForm.symptoms, this.defaultSymptom()];
    this.syncView();
  }

  removeSymptom(index: number) {
    this.diseaseForm.symptoms = this.diseaseForm.symptoms.filter(
      (_, itemIndex) => itemIndex !== index,
    );
    if (!this.diseaseForm.symptoms.length) {
      this.diseaseForm.symptoms = [this.defaultSymptom()];
    }
    this.syncView();
  }

  addReference() {
    this.diseaseForm.references = [...this.diseaseForm.references, this.defaultReference()];
    this.syncView();
  }

  removeReference(index: number) {
    this.diseaseForm.references = this.diseaseForm.references.filter(
      (_, itemIndex) => itemIndex !== index,
    );
    if (!this.diseaseForm.references.length) {
      this.diseaseForm.references = [this.defaultReference()];
    }
    this.syncView();
  }

  private loadDashboard() {
    this.isLoading = true;
    this.dashboardFeedback = null;
    if (this.sectionKind === 'events') {
      this.auth.getAdminEvents().subscribe({
        next: (events) => {
          this.events = this.sortEvents(events);
          this.dailyEntries = [];
          this.diseases = [];
          this.isLoading = false;
          this.syncView();
        },
        error: (error) => this.handleDashboardError(error),
      });
      return;
    }

    if (this.sectionKind === 'daily-corner') {
      this.auth.getAdminDailyCornerEntries().subscribe({
        next: (dailyEntries) => {
          this.events = [];
          this.dailyEntries = this.sortDailyEntries(dailyEntries);
          this.diseases = [];
          this.isLoading = false;
          this.syncView();
        },
        error: (error) => this.handleDashboardError(error),
      });
      return;
    }

    this.auth.getAdminDiseases().subscribe({
      next: (diseases) => {
        this.events = [];
        this.dailyEntries = [];
        this.diseases = this.sortDiseases(diseases);
        this.isLoading = false;
        this.syncView();
      },
      error: (error) => this.handleDashboardError(error),
    });
  }

  private sortEvents(events: EventItem[]) {
    return [...events].sort((left, right) => left.date.localeCompare(right.date));
  }

  private sortDailyEntries(entries: DailyCornerEntry[]) {
    return [...entries].sort((left, right) => right.date.localeCompare(left.date));
  }

  private sortDiseases(diseases: Disease[]) {
    return [...diseases].sort(
      (left, right) =>
        right.updatedAt.localeCompare(left.updatedAt) || left.name.localeCompare(right.name, this.locale),
    );
  }

  private buildDiseasePayload(): AdminDiseaseForm {
    return {
      locale: this.diseaseForm.locale,
      slug: this.diseaseForm.slug.trim(),
      name: this.diseaseForm.name.trim(),
      aliases: this.splitCommaList(this.diseaseForm.aliasesText),
      category: this.diseaseForm.category.trim(),
      shortDescription: this.diseaseForm.shortDescription.trim(),
      summaryMedical: this.diseaseForm.summaryMedical.trim(),
      summarySimple: this.diseaseForm.summarySimple.trim(),
      causes: this.diseaseForm.causes
        .map((item) => ({
          title: item.title.trim(),
          description: item.description.trim(),
          image: item.image.trim(),
        }))
        .filter((item) => item.title && item.description),
      symptoms: this.diseaseForm.symptoms
        .map((item) => ({
          medicalTerm: item.medicalTerm.trim(),
          description: item.description.trim(),
          synonyms: this.splitCommaList(item.synonymsText),
          frequency: item.frequency.trim(),
          bodySystem: item.bodySystem.trim(),
        }))
        .filter((item) => item.medicalTerm && item.description),
      references: this.diseaseForm.references
        .map((item) => ({
          title: item.title.trim(),
          url: item.url.trim(),
        }))
        .filter((item) => item.title && item.url),
      published: this.diseaseForm.published,
    };
  }

  private splitCommaList(value: string) {
    return value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  }

  private handleModalError(error: { error?: { message?: string } }) {
    this.modalFeedback = {
      status: 'error',
      message: error.error?.message || this.dictionary.common.generalError,
    };
    this.isSaving = false;
    this.syncView();
  }

  private handleDashboardError(error: { error?: { message?: string } }) {
    this.resetDashboard();
    this.dashboardFeedback = {
      status: 'error',
      message: error.error?.message || this.dictionary.common.generalError,
    };
    this.syncView();
  }

  private resetModalState() {
    this.modalFeedback = null;
    this.isSaving = false;
    this.syncView();
  }

  private resetDashboard() {
    this.events = [];
    this.dailyEntries = [];
    this.diseases = [];
    this.isLoading = false;
  }

  private defaultEventForm(): AdminEventForm {
    return {
      locale: this.locale,
      title: '',
      summary: '',
      description: '',
      date: this.todayIsoDate(),
      startTime: '',
      endTime: '',
      organizer: '',
      location: '',
      image: '',
      link: '',
      published: true,
    };
  }

  private defaultDailyForm(): AdminDailyCornerForm {
    return {
      locale: this.locale,
      date: this.todayIsoDate(),
      title: '',
      quote: '',
      body: '',
      reminderTitle: '',
      reminderBody: '',
      image: '',
      audioUrl: '',
      published: true,
    };
  }

  private defaultDiseaseForm(): DiseaseDraftForm {
    return {
      locale: this.locale,
      slug: '',
      name: '',
      aliasesText: '',
      category: '',
      shortDescription: '',
      summaryMedical: '',
      summarySimple: '',
      causes: [this.defaultCause()],
      symptoms: [this.defaultSymptom()],
      references: [this.defaultReference()],
      published: true,
    };
  }

  private defaultCause(): DiseaseCauseDraft {
    return {
      title: '',
      description: '',
      image: '',
    };
  }

  private defaultSymptom(): DiseaseSymptomDraft {
    return {
      medicalTerm: '',
      description: '',
      synonymsText: '',
      frequency: '',
      bodySystem: '',
    };
  }

  private defaultReference(): DiseaseReferenceDraft {
    return {
      title: '',
      url: '',
    };
  }

  private todayIsoDate() {
    return new Date().toISOString().slice(0, 10);
  }

  private resolveKind(value: unknown): ContentKind {
    if (value === 'daily-corner' || value === 'diseases') {
      return value;
    }

    return 'events';
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
