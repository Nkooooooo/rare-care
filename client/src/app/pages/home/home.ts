import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary, formatMonthDay } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { DailyCornerEntry, EventItem, Locale } from '../../models';

@Component({
  selector: 'app-home',
  imports: [CommonModule, RouterLink],
  templateUrl: './home.html',
  styleUrl: './home.css',
})
export class Home implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  events: EventItem[] = [];
  entries: DailyCornerEntry[] = [];

  readonly helpRoutes = ['/disease-information', '/community', '/donation', '/daily-corner'];
  readonly helpCtas = ['learnMore', 'joinGroup', 'applyNow', 'readNow'] as const;

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.loadContent();
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

  formatMonthDay(value: string) {
    return formatMonthDay(value, this.locale);
  }

  ctaLabel(index: number) {
    return this.dictionary.common[this.helpCtas[index]];
  }

  private loadContent() {
    this.api.getEvents(this.locale).subscribe((events) => {
      this.events = events.slice(0, 1);
      this.syncView();
    });
    this.api
      .getDailyCornerEntries(this.locale)
      .subscribe((entries) => {
        this.entries = entries.slice(0, 1);
        this.syncView();
      });
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
