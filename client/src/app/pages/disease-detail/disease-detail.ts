import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary, formatDisplayDate } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { Disease, Locale } from '../../models';

@Component({
  selector: 'app-disease-detail',
  imports: [CommonModule, RouterLink],
  templateUrl: './disease-detail.html',
  styleUrl: './disease-detail.css',
})
export class DiseaseDetail implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly route = inject(ActivatedRoute);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  disease: Disease | null = null;
  notFound = false;
  private slug = '';

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.loadDisease();
        this.syncView();
      }),
    );

    this.subscriptions.add(
      this.route.paramMap.subscribe((params) => {
        this.slug = params.get('slug') || '';
        this.loadDisease();
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

  formatDate(value: string) {
    return formatDisplayDate(value, this.locale);
  }

  private loadDisease() {
    if (!this.slug) {
      return;
    }

    this.api.getDisease(this.locale, this.slug).subscribe({
      next: (disease) => {
        this.disease = disease;
        this.notFound = false;
        this.syncView();
      },
      error: () => {
        this.disease = null;
        this.notFound = true;
        this.syncView();
      },
    });
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
