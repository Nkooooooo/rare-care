import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { ContactForm, Locale } from '../../models';

@Component({
  selector: 'app-contact',
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './contact.html',
  styleUrl: './contact.css',
})
export class Contact implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  form: ContactForm = { name: '', email: '', subject: '', message: '' };
  isSubmitting = false;
  feedback = '';

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
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

  isValid() {
    return (
      this.form.name.length > 1 &&
      this.form.email.includes('@') &&
      this.form.subject.length > 2 &&
      this.form.message.length > 9
    );
  }

  submit() {
    if (!this.isValid()) {
      return;
    }

    this.isSubmitting = true;
    this.feedback = '';
    this.api.createContactMessage(this.form).subscribe({
      next: () => {
        this.feedback = this.dictionary.contact.success;
        this.form = { name: '', email: '', subject: '', message: '' };
        this.isSubmitting = false;
        this.syncView();
      },
      error: () => {
        this.feedback = this.dictionary.common.submitError;
        this.isSubmitting = false;
        this.syncView();
      },
    });
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
