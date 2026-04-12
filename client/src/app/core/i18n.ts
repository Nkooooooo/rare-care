import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

import { Dictionary, dictionaryFor, normalizeLocale } from '../content';
import { Locale } from '../models';

const storageKey = 'rare-care-locale';

@Injectable({ providedIn: 'root' })
export class I18n {
  private readonly localeSubject = new BehaviorSubject<Locale>(this.initialLocale());
  readonly locale$ = this.localeSubject.asObservable();

  get locale(): Locale {
    return this.localeSubject.value;
  }

  get dictionary(): Dictionary {
    return dictionaryFor(this.locale);
  }

  setLocale(locale: Locale) {
    this.localeSubject.next(locale);
    localStorage.setItem(storageKey, locale);
    this.syncDocument(locale);
  }

  toggleLocale() {
    this.setLocale(this.locale === 'mn' ? 'en' : 'mn');
  }

  private initialLocale(): Locale {
    const stored = localStorage.getItem(storageKey);
    if (stored === 'mn' || stored === 'en') {
      this.syncDocument(stored);
      return stored;
    }

    const browserLocale = normalizeLocale(navigator.language?.slice(0, 2));
    this.syncDocument(browserLocale);
    return browserLocale;
  }

  private syncDocument(locale: Locale) {
    document.documentElement.lang = locale;
    document.title = dictionaryFor(locale).siteName;
  }
}
