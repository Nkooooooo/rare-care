import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { Disease, Locale } from '../../models';

@Component({
  selector: 'app-disease-list',
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './disease-list.html',
  styleUrl: './disease-list.css',
})
export class DiseaseList implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly i18n = inject(I18n);
  private readonly subscriptions = new Subscription();

  locale: Locale = this.i18n.locale;
  dictionary: Dictionary = this.i18n.dictionary;
  diseases: Disease[] = [];
  categories: string[] = [];
  query = '';
  category = 'all';
  sort = 'name';

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.loadCategories();
        this.loadDiseases();
        this.syncView();
      }),
    );

    this.subscriptions.add(
      this.route.queryParamMap.subscribe((params) => {
        this.query = params.get('query') || '';
        this.category = params.get('category') || 'all';
        this.sort = params.get('sort') || 'name';
        this.loadDiseases();
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

  search() {
    this.router.navigate([this.routeTo('/disease-information')], {
      queryParams: {
        query: this.query || null,
        category: this.category !== 'all' ? this.category : null,
        sort: this.sort !== 'name' ? this.sort : null,
      },
    });
  }

  reset() {
    this.router.navigate([this.routeTo('/disease-information')]);
  }

  private loadCategories() {
    this.api
      .getDiseaseCategories(this.locale)
      .subscribe((categories) => {
        this.categories = categories;
        this.syncView();
      });
  }

  private loadDiseases() {
    this.api
      .getDiseases(this.locale, { query: this.query, category: this.category, sort: this.sort })
      .subscribe((diseases) => {
        this.diseases = diseases;
        this.syncView();
      });
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }
}
