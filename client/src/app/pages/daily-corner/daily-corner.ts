import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary, formatDisplayDate } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { DailyCornerEntry, Locale } from '../../models';

@Component({
  selector: 'app-daily-corner',
  imports: [CommonModule, RouterLink],
  templateUrl: './daily-corner.html',
  styleUrl: './daily-corner.css',
})
export class DailyCorner implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  entries: DailyCornerEntry[] = [];

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.api
          .getDailyCornerEntries(this.locale)
          .subscribe((entries) => {
            this.entries = entries;
            this.syncView();
          });
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

  reversed(index: number) {
    return index % 2 === 1;
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
