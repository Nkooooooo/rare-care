import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { DiseaseFacet, DiseaseListItem, Locale } from '../../models';

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
  diseases: DiseaseListItem[] = [];
  categories: DiseaseFacet[] = [];
  letters: DiseaseFacet[] = [];
  query = '';
  category = 'all';
  letter = 'all';
  sort = 'name';
  page = 1;
  pageSize = 24;
  pageCount = 1;
  total = 0;
  private searchTimer: ReturnType<typeof setTimeout> | null = null;

  ngOnInit() {
    this.subscriptions.add(
      this.i18n.locale$.subscribe(() => {
        this.locale = this.i18n.locale;
        this.dictionary = this.i18n.dictionary;
        this.loadDiseases();
        this.syncView();
      }),
    );

    this.subscriptions.add(
      this.route.queryParamMap.subscribe((params) => {
        this.query = params.get('query') || '';
        this.category = params.get('category') || 'all';
        this.letter = params.get('letter') || 'all';
        this.sort = params.get('sort') || 'name';
        this.page = Math.max(Number(params.get('page') || '1') || 1, 1);
        this.loadDiseases();
        this.syncView();
      }),
    );
  }

  ngOnDestroy() {
    this.clearSearchTimer();
    this.subscriptions.unsubscribe();
  }

  routeTo(path = '') {
    return path || '/';
  }

  search() {
    this.clearSearchTimer();
    this.navigateWithFilters({ page: 1 });
  }

  reset() {
    this.clearSearchTimer();
    this.query = '';
    this.category = 'all';
    this.letter = 'all';
    this.sort = 'name';
    this.page = 1;
    this.navigateWithFilters();
  }

  selectCategory(category = 'all') {
    this.category = this.category === category ? 'all' : category;
    this.navigateWithFilters({ page: 1 });
  }

  selectLetter(letter = 'all') {
    this.letter = this.letter === letter ? 'all' : letter;
    this.navigateWithFilters({ page: 1 });
  }

  goToPage(page: number) {
    if (page < 1 || page > this.pageCount || page === this.page) {
      return;
    }

    this.page = page;
    this.navigateWithFilters();
  }

  isCategoryActive(category: string) {
    return this.category === category;
  }

  isLetterActive(letter: string) {
    return this.letter === letter;
  }

  hasActiveFilters() {
    return this.query.length > 0 || this.category !== 'all' || this.letter !== 'all' || this.sort !== 'name';
  }

  handleQueryChange(value: string) {
    this.query = value;
    this.clearSearchTimer();
    this.searchTimer = setTimeout(() => this.navigateWithFilters({ page: 1 }), 250);
  }

  resultsRangeSummary() {
    if (!this.total) {
      return this.dictionary.diseases.showingResults.replace('{count}', '0');
    }

    const start = (this.page - 1) * this.pageSize + 1;
    const end = Math.min(this.page * this.pageSize, this.total);

    return this.dictionary.diseases.showingRange
      .replace('{start}', start.toString())
      .replace('{end}', end.toString())
      .replace('{count}', this.total.toString());
  }

  primaryCategory(disease: DiseaseListItem) {
    const categories = disease.categories?.length ? disease.categories : [disease.category];
    return categories[0] || disease.category;
  }

  displayCategory(disease: DiseaseListItem) {
    const categories = disease.categories?.length ? disease.categories : [disease.category];
    if (this.category !== 'all' && categories.includes(this.category)) {
      return this.category;
    }

    return categories[0] || disease.category;
  }

  additionalCategoryCount(disease: DiseaseListItem) {
    const categories = disease.categories?.length ? disease.categories : [disease.category];
    const shownCategory = this.displayCategory(disease);
    return Math.max(categories.filter((item) => item !== shownCategory).length, 0);
  }

  additionalCategoryLabel(disease: DiseaseListItem) {
    return this.dictionary.diseases.relatedTypeCount.replace(
      '{count}',
      this.additionalCategoryCount(disease).toString(),
    );
  }

  pageWindow() {
    const pages: number[] = [];
    const start = Math.max(1, this.page - 2);
    const end = Math.min(this.pageCount, this.page + 2);

    for (let value = start; value <= end; value += 1) {
      pages.push(value);
    }

    return pages;
  }

  letterOptions() {
    const counts = new Map(this.letters.map((item) => [item.name, item.count]));
    return ['0-9', ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')].map((name) => ({
      name,
      count: counts.get(name) || 0,
    }));
  }

  private loadDiseases() {
    this.api
      .getDiseases(this.locale, {
        query: this.query,
        category: this.category,
        letter: this.letter,
        sort: this.sort,
        page: this.page,
      })
      .subscribe((response) => {
        this.diseases = response.items;
        this.categories = response.categories;
        this.letters = response.letters;
        this.total = response.total;
        this.page = response.page;
        this.pageSize = response.pageSize;
        this.pageCount = response.pageCount;
        this.syncView();
      });
  }

  private navigateWithFilters(overrides: Partial<Record<'page', number>> = {}) {
    const page = overrides.page ?? this.page;
    this.router.navigate([this.routeTo('/disease-information')], {
      queryParams: {
        query: this.query || null,
        category: this.category !== 'all' ? this.category : null,
        letter: this.letter !== 'all' ? this.letter : null,
        sort: this.sort !== 'name' ? this.sort : null,
        page: page > 1 ? page : null,
      },
    });
  }

  private syncView() {
    queueMicrotask(() => this.cdr.detectChanges());
  }

  private clearSearchTimer() {
    if (this.searchTimer) {
      clearTimeout(this.searchTimer);
      this.searchTimer = null;
    }
  }
}
