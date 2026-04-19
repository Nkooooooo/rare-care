import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, OnInit, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';

import { Dictionary, formatDisplayDate } from '../../content';
import { Api } from '../../core/api';
import { I18n } from '../../core/i18n';
import { Disease, Locale } from '../../models';

@Component({
  selector: 'app-disease-detail',
  imports: [CommonModule, FormsModule, RouterLink],
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
  symptomQuery = '';
  symptomSystem = 'all';
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

  private firstSentence(value = '') {
    const text = String(value || '').trim();
    if (!text) {
      return '';
    }

    const match = text.match(/^.*?[.!?](?:\s|$)/);
    return (match?.[0] || text).trim();
  }

  private splitSentences(value = '') {
    return String(value || '')
      .replace(/\s+/g, ' ')
      .split(/(?<=[.!?])\s+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  private escapePattern(value = '') {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  private conciseCauseMessage(value = '') {
    const text = String(value || '').trim();
    const lower = text.toLowerCase();

    if (!text) {
      return '';
    }

    if (/(missing genetic material|deletion|microdeletion|monosomy)/.test(lower)) {
      return this.locale === 'mn'
        ? 'Генетикийн материал дутуу байх эсвэл хромосомын устгалтай холбоотой байж болно.'
        : 'May involve missing genetic material or a chromosome deletion.';
    }

    if (/(extra genetic material|duplication|microduplication|trisomy|tetrasomy)/.test(lower)) {
      return this.locale === 'mn'
        ? 'Генетикийн материал илүүдэх эсвэл хромосомын олшролтой холбоотой байж болно.'
        : 'May involve extra genetic material or a chromosome duplication.';
    }

    if (/(gene|mutation|variant)/.test(lower)) {
      return this.locale === 'mn'
        ? 'Тодорхой генийн өөрчлөлттэй холбоотой байж болно.'
        : 'May involve a change in a specific gene.';
    }

    if (/(enzyme|metabolic|metabolism|transport|deficiency)/.test(lower)) {
      return this.locale === 'mn'
        ? 'Фермент эсвэл бодисын солилцооны өөрчлөлттэй холбоотой байж болно.'
        : 'May involve an enzyme or metabolic change.';
    }

    if (/(inherited|autosomal|x-linked|de novo|sporadic|randomly)/.test(lower)) {
      return this.locale === 'mn'
        ? 'Удамших эсвэл санамсаргүйгээр шинээр үүсэх боломжтой.'
        : 'Can be inherited or can happen for the first time by chance.';
    }

    return this.firstSentence(text);
  }

  private compactCauseSentence(value = '', diseaseName = '') {
    const source = String(value || '').replace(/\s+/g, ' ').trim();
    if (!source) {
      return '';
    }

    const diseaseLead = diseaseName ? new RegExp(`^${this.escapePattern(diseaseName)}\\s+(is|was)\\s+`, 'i') : null;
    let text = source;

    if (diseaseLead) {
      text = text.replace(diseaseLead, '');
    }

    text = text
      .replace(/^The syndrome is caused by /i, '')
      .replace(/^This disease is caused by /i, '')
      .replace(/^This condition is caused by /i, '')
      .replace(/^The disease is caused by /i, '')
      .replace(/^In most cases, /i, '')
      .replace(/^Only rarely is /i, '')
      .replace(/^It is inherited in /i, '')
      .trim();

    const lower = text.toLowerCase();
    const geneMatch = source.match(/\b([A-Z0-9-]{2,}) gene\b/);
    if (geneMatch) {
      return this.locale === 'mn'
        ? `${geneMatch[1]} генийн өөрчлөлттэй холбоотой байж болно.`
        : `May involve a change in the ${geneMatch[1]} gene.`;
    }

    const chromosomeLocation =
      source.match(/\bchromosome\s+([0-9]+(?:\s*[pq](?:\s*arm)?(?:\s*at\s*[pq]?[0-9.]+)?)?)/i)?.[1] ||
      source.match(/\b([0-9]+[pq][0-9.]+)\b/i)?.[1] ||
      '';

    if (/(deletion|microdeletion|monosomy|missing piece|loss of)/i.test(source)) {
      if (chromosomeLocation) {
        return this.locale === 'mn'
          ? `${chromosomeLocation}-тэй холбоотой генетикийн материал дутуу байх өөрчлөлттэй байж болно.`
          : `May involve missing genetic material affecting chromosome ${chromosomeLocation}.`;
      }
      return this.locale === 'mn'
        ? 'Генетикийн материал дутуу байх өөрчлөлттэй холбоотой байж болно.'
        : 'May involve missing genetic material.';
    }

    if (/(duplication|microduplication|trisomy|tetrasomy|extra piece|extra copy)/i.test(source)) {
      if (chromosomeLocation) {
        return this.locale === 'mn'
          ? `${chromosomeLocation}-тэй холбоотой генетикийн материал илүүдэх өөрчлөлттэй байж болно.`
          : `May involve extra genetic material affecting chromosome ${chromosomeLocation}.`;
      }
      return this.locale === 'mn'
        ? 'Генетикийн материал илүүдэх өөрчлөлттэй холбоотой байж болно.'
        : 'May involve extra genetic material.';
    }

    if (/(autosomal dominant)/i.test(source)) {
      return this.locale === 'mn' ? 'Аутосомын давамгай удамшлын хэлбэртэй байж болно.' : 'Can follow an autosomal dominant inheritance pattern.';
    }

    if (/(autosomal recessive)/i.test(source)) {
      return this.locale === 'mn' ? 'Аутосомын рецессив удамшлын хэлбэртэй байж болно.' : 'Can follow an autosomal recessive inheritance pattern.';
    }

    if (/(x-linked)/i.test(source)) {
      return this.locale === 'mn' ? 'X-холбоост удамшлын хэлбэртэй байж болно.' : 'Can follow an X-linked inheritance pattern.';
    }

    if (/(de novo|sporadic|randomly|for the first time|spontaneously)/i.test(source)) {
      return this.locale === 'mn'
        ? 'Зарим тохиолдолд удамшилгүйгээр шинээр үүсч болно.'
        : 'Can happen for the first time without being inherited.';
    }

    if (/(inherited|passed down from a parent)/i.test(source)) {
      return this.locale === 'mn' ? 'Зарим тохиолдолд эцэг эхээс удамшиж болно.' : 'Can sometimes be inherited from a parent.';
    }

    if (/(cell division)/i.test(source)) {
      return this.locale === 'mn' ? 'Эсийн хуваагдлын үеийн өөрчлөлттэй холбоотой байж болно.' : 'May be linked to a change during cell division.';
    }

    if (/(enzyme|metabolism|transport|deficiency)/i.test(source)) {
      return this.locale === 'mn'
        ? 'Фермент эсвэл бодисын солилцооны өөрчлөлттэй холбоотой байж болно.'
        : 'May involve an enzyme or metabolic change.';
    }

    return this.firstSentence(source);
  }

  private topBodySystems(disease: Disease) {
    const counts = new Map<string, number>();
    disease.symptoms.forEach((symptom) => {
      const key = String(symptom.bodySystem || '').trim();
      if (!key) {
        return;
      }

      counts.set(key, (counts.get(key) || 0) + 1);
    });

    return [...counts.entries()]
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0], this.locale))
      .slice(0, 3)
      .map(([name]) => name);
  }

  private hasInheritanceSignal(disease: Disease) {
    const source = [disease.summaryMedical, ...disease.causes.map((item) => item.description)].join(' ').toLowerCase();
    return /(inherited|hereditary|autosomal|x-linked|de novo|sporadic|randomly)/.test(source);
  }

  primaryCategory(disease: Disease) {
    const categories = disease.categories?.length ? disease.categories : [disease.category];
    return categories[0] || disease.category;
  }

  secondaryCategories(disease: Disease) {
    const categories = disease.categories?.length ? disease.categories : [disease.category];
    return categories.slice(1);
  }

  relatedCategorySummary(disease: Disease) {
    return this.secondaryCategories(disease).join(' · ');
  }

  private coreSymptoms(disease: Disease) {
    return disease.symptoms.filter((item) => !/when symptoms may appear|шинж тэмдэг илрэх үе/i.test(item.medicalTerm));
  }

  symptomPreview(disease: Disease) {
    const symptoms = this.coreSymptoms(disease);
    if (!symptoms.length) {
      return this.dictionary.diseases.noSymptomDetails;
    }

    const terms = symptoms.slice(0, 3).map((item) => item.medicalTerm);
    return symptoms.length > 3 ? `${terms.join(', ')}, ...` : terms.join(', ');
  }

  causeQuickPoints(disease: Disease) {
    const points: string[] = [];

    if (disease.causes.length) {
      points.push(this.conciseCauseMessage(disease.causes[0].description));
    } else {
      points.push(this.dictionary.diseases.noCauseDetails);
    }

    const inheritanceCause = disease.causes.find((item) =>
      /(inherited|autosomal|x-linked|de novo|sporadic|randomly)/i.test(item.description),
    );

    if (inheritanceCause) {
      points.push(this.conciseCauseMessage(inheritanceCause.description));
    } else if (this.hasInheritanceSignal(disease)) {
      points.push(
        this.locale === 'mn'
          ? 'Удамших эсвэл санамсаргүй үүсэх эсэхийг нягталж үзэх хэрэгтэй.'
          : 'Check whether it is inherited or happens sporadically.',
      );
    }

    return [...new Set(points.filter(Boolean))].slice(0, 2);
  }

  causeSectionPoints(disease: Disease) {
    const points = disease.causes
      .flatMap((cause) => this.splitSentences(cause.description).map((sentence) => this.compactCauseSentence(sentence, disease.name)))
      .filter(Boolean);

    const uniquePoints = [...new Set(points)];
    return uniquePoints.length ? uniquePoints.slice(0, 5) : [this.dictionary.diseases.noCauseDetails];
  }

  causeDetailPoints(cause: Disease['causes'][number], disease: Disease) {
    const points = this.splitSentences(cause.description)
      .map((sentence) => this.compactCauseSentence(sentence, disease.name))
      .filter(Boolean);

    return [...new Set(points)].slice(0, 2);
  }

  groupedVisibleSymptoms(disease: Disease) {
    const groups = new Map<string, Disease['symptoms']>();

    this.visibleSymptoms(disease).forEach((symptom) => {
      const groupName = String(symptom.bodySystem || '').trim() || this.dictionary.diseases.generalSymptomsGroup;
      const current = groups.get(groupName) || [];
      current.push(symptom);
      groups.set(groupName, current);
    });

    return [...groups.entries()]
      .map(([name, items]) => ({
        name,
        items: items.sort((left, right) => left.medicalTerm.localeCompare(right.medicalTerm, this.locale)),
      }))
      .sort((left, right) => {
        if (left.name === this.dictionary.diseases.generalSymptomsGroup) {
          return 1;
        }

        if (right.name === this.dictionary.diseases.generalSymptomsGroup) {
          return -1;
        }

        return left.name.localeCompare(right.name, this.locale);
      });
  }

  symptomLead(symptom: Disease['symptoms'][number]) {
    return this.firstSentence(symptom.description);
  }

  symptomExtraDetail(symptom: Disease['symptoms'][number]) {
    const lead = this.symptomLead(symptom);
    return String(symptom.description || '').trim() === lead ? '' : String(symptom.description || '').trim();
  }

  hasSymptomDetails(symptom: Disease['symptoms'][number]) {
    return Boolean(this.symptomExtraDetail(symptom) || symptom.synonyms?.length);
  }

  symptomQuickPoints(disease: Disease) {
    const mainSymptoms = this.coreSymptoms(disease).slice(0, 3).map((item) => item.medicalTerm);
    const points: string[] = [];
    const systems = this.topBodySystems(disease);

    if (mainSymptoms.length) {
      points.push(
        this.locale === 'mn'
          ? `${mainSymptoms.join(', ')} зэрэг шинж тэмдэг илэрч болно.`
          : `May include ${mainSymptoms.join(', ')}.`,
      );
    }

    points.push(this.dictionary.diseases.variableSymptomsLabel);

    if (this.coreSymptoms(disease).length === 1) {
      points.push(this.firstSentence(this.coreSymptoms(disease)[0].description));
    }

    if (systems.length) {
      points.push(`${this.dictionary.diseases.symptomSystemsLabel}: ${systems.join(' · ')}`);
    }

    return points.filter(Boolean).slice(0, 4);
  }

  diseaseTypeQuickPoints(disease: Disease) {
    const points: string[] = [];
    const related = this.secondaryCategories(disease);

    if (related.length) {
      points.push(related.join(' · '));
      points.push(this.dictionary.diseases.multipleCategoriesLabel);
    } else {
      points.push(
        this.locale === 'mn'
          ? 'Одоогоор энэ хуудсанд нэг үндсэн ангилал харагдаж байна.'
          : 'This page currently shows one main disease category.',
      );
    }

    points.push(`${this.dictionary.diseases.updated}: ${this.formatDate(disease.updatedAt)}`);
    return points.slice(0, 3);
  }

  symptomSystems(disease: Disease) {
    return [
      ...new Set(
        disease.symptoms
          .map((item) => String(item.bodySystem || '').trim())
          .filter(Boolean)
          .sort((left, right) => left.localeCompare(right, this.locale)),
      ),
    ];
  }

  visibleSymptoms(disease: Disease) {
    return disease.symptoms.filter((symptom) => {
      const searchable = [
        symptom.medicalTerm,
        symptom.description,
        symptom.frequency,
        symptom.bodySystem,
        ...(symptom.synonyms || []),
      ]
        .join(' ')
        .toLowerCase();

      const matchesQuery = !this.symptomQuery.trim() || searchable.includes(this.symptomQuery.trim().toLowerCase());
      const matchesSystem =
        this.symptomSystem === 'all' || (symptom.bodySystem || '').trim() === this.symptomSystem;

      return matchesQuery && matchesSystem;
    });
  }

  visibleSymptomCount(disease: Disease) {
    return this.dictionary.diseases.symptomVisibleCount.replace(
      '{count}',
      this.visibleSymptoms(disease).length.toString(),
    );
  }

  selectSymptomSystem(value = 'all') {
    this.symptomSystem = value;
  }

  private loadDisease() {
    if (!this.slug) {
      return;
    }

    this.api.getDisease(this.locale, this.slug).subscribe({
      next: (disease) => {
        this.disease = disease;
        this.notFound = false;
        this.symptomQuery = '';
        this.symptomSystem = 'all';
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
