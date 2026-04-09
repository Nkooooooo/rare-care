import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { DonationForm, Locale } from '../../models';

@Component({
  selector: 'app-donation',
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './donation.html',
  styleUrl: './donation.css',
})
export class Donation implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  presetAmounts = [50, 100, 250, 500, 1000];
  customAmount = '';
  isSubmitting = false;
  feedback: { status: 'success' | 'error'; message: string } | null = null;
  form: DonationForm = this.defaultForm();

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.form.country = this.locale === 'mn' ? 'Mongolia' : this.form.country;
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

  selectAmount(amount: number) {
    this.form.amount = amount;
    this.customAmount = '';
  }

  updateCustomAmount() {
    const parsed = Number(this.customAmount);
    this.form.amount = Number.isFinite(parsed) ? parsed : 0;
  }

  isValid() {
    return (
      this.form.amount > 0 &&
      this.form.firstName.length > 1 &&
      this.form.lastName.length > 1 &&
      this.form.address.length > 4 &&
      this.form.country.length > 1 &&
      this.form.stateProvince.length > 1 &&
      this.form.city.length > 1 &&
      this.form.postalCode.length > 1 &&
      this.form.email.includes('@') &&
      this.form.consentAccepted &&
      this.form.captchaPassed
    );
  }

  submit() {
    if (!this.isValid()) {
      return;
    }

    this.isSubmitting = true;
    this.feedback = null;
    this.api.createDonation(this.form).subscribe({
      next: () => {
        this.feedback = { status: 'success', message: this.dictionary.donation.successBody };
        this.form = this.defaultForm();
        this.isSubmitting = false;
        this.syncView();
      },
      error: () => {
        this.feedback = { status: 'error', message: this.dictionary.common.submitError };
        this.isSubmitting = false;
        this.syncView();
      },
    });
  }

  private defaultForm(): DonationForm {
    return {
      donationType: 'one_time',
      amount: 500,
      dedicateTo: '',
      note: '',
      firstName: '',
      lastName: '',
      address: '',
      country: 'Mongolia',
      stateProvince: '',
      city: '',
      postalCode: '',
      email: '',
      phone: '',
      paymentType: 'credit_card',
      consentAccepted: false,
      captchaPassed: false,
    };
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
