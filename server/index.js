import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import cors from 'cors';
import express from 'express';
import morgan from 'morgan';

import { readAdminUsersSeed, readDatabase, readGardDiseaseIndex, writeDatabase } from './store.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const validLocales = new Set(['mn', 'en']);
const validRoles = new Set(['user', 'admin']);
const maxProfileImageBytes = 4 * 1024 * 1024;
const profileImageMountPath = '/media/profile-images';
const profileImagesDir = join(__dirname, 'data', 'profile-images');
const supportedProfileImageExtensions = {
  'image/gif': 'gif',
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp'
};

app.use(cors({ origin: true }));
app.use(express.json({ limit: '5mb' }));
app.use(morgan('dev'));

function resolveLocale(value) {
  return validLocales.has(value) ? value : 'mn';
}

function publicOnly(items, locale) {
  return items.filter((item) => item.locale === locale && item.published);
}

const gardCategoryLabels = {
  en: {
    'Birth defects': 'Birth defects',
    'Blood diseases': 'Blood diseases',
    Cancer: 'Cancer',
    'Endocrine diseases': 'Endocrine diseases',
    'Gastrointestinal diseases': 'Gastrointestinal diseases',
    'Genetic diseases': 'Genetic diseases',
    'Infectious diseases': 'Infectious diseases',
    'Kidney diseases': 'Kidney diseases',
    'Neurological diseases': 'Neurological diseases',
    'Respiratory diseases': 'Respiratory diseases',
    'Skin diseases': 'Skin diseases',
    'Urinary and reproductive diseases': 'Urinary and reproductive diseases',
  },
  mn: {
    'Birth defects': 'Төрөлхийн гажиг',
    'Blood diseases': 'Цусны өвчин',
    Cancer: 'Хавдар',
    'Endocrine diseases': 'Дотоод шүүрлийн өвчин',
    'Gastrointestinal diseases': 'Хоол боловсруулах тогтолцооны өвчин',
    'Genetic diseases': 'Генетикийн өвчин',
    'Infectious diseases': 'Халдварт өвчин',
    'Kidney diseases': 'Бөөрний өвчин',
    'Neurological diseases': 'Мэдрэлийн тогтолцооны өвчин',
    'Respiratory diseases': 'Амьсгалын замын өвчин',
    'Skin diseases': 'Арьсны өвчин',
    'Urinary and reproductive diseases': 'Шээс, нөхөн үржихүйн тогтолцооны өвчин',
  },
};

let gardDiseaseIndexPromise;

function uniqueStrings(values) {
  return [...new Set(values.filter(Boolean))];
}

function firstSentence(value) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }

  const match = text.match(/^.*?[.!?](?:\s|$)/);
  return (match?.[0] || text).trim();
}

function localizeGardCategory(category, locale) {
  return gardCategoryLabels[locale]?.[category] || category;
}

function localizeGardCategories(categories, locale) {
  return uniqueStrings((categories || []).map((category) => localizeGardCategory(category, locale)));
}

function joinLocalizedList(values, locale) {
  const items = uniqueStrings(values || []);
  if (!items.length) {
    return '';
  }

  if (items.length === 1) {
    return items[0];
  }

  if (items.length === 2) {
    return locale === 'mn' ? `${items[0]} болон ${items[1]}` : `${items[0]} and ${items[1]}`;
  }

  const last = items[items.length - 1];
  const head = items.slice(0, -1).join(', ');
  return locale === 'mn' ? `${head}, мөн ${last}` : `${head}, and ${last}`;
}

function trimSentence(value) {
  return String(value || '').trim().replace(/[.。\s]+$/g, '');
}

function lowerFirst(value) {
  return value ? value.charAt(0).toLowerCase() + value.slice(1) : value;
}

function replaceWithRules(text, rules) {
  return rules.reduce((output, [pattern, value]) => output.replace(pattern, value), text);
}

function splitSentences(text) {
  return String(text || '')
    .replace(/\s+/g, ' ')
    .split(/(?<=[.!?])\s+/)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
}

function cleanFeatureText(value) {
  return String(value || '')
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\b(such as|including|includes|include|may include|associated with|characterized by)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .replace(/^[,;:\s-]+|[,;:\s-]+$/g, '')
    .trim();
}

function extractGardFeaturePhrases(text) {
  const source = String(text || '').replace(/\s+/g, ' ').trim();
  if (!source) {
    return [];
  }

  const featureSegments = [];
  const patterns = [
    /\bmay include\b([^.!?]+)/i,
    /\bincluding\b([^.!?]+)/i,
    /\bcharacterized by\b([^.!?]+)/i,
    /\bassociated with\b([^.!?]+)/i,
    /\bfeatures of .*? include\b([^.!?]+)/i,
    /\bfeatures include\b([^.!?]+)/i,
    /\bsigns and symptoms may include:?\b([^.!?]+)/i,
    /\bsymptoms may include:?\b([^.!?]+)/i,
    /\bsymptoms also include\b([^.!?]+)/i,
    /\bother features may include\b([^.!?]+)/i,
    /\badditional features include\b([^.!?]+)/i,
  ];

  patterns.forEach((pattern) => {
    const match = source.match(pattern);
    if (match?.[1]) {
      featureSegments.push(match[1]);
    }
  });

  return uniqueStrings(
    featureSegments
      .flatMap((segment) => segment.split(/,|;|\band\/or\b|\band\b|\bor\b/gi))
      .map((item) => cleanFeatureText(item))
      .filter((item) => {
        if (!item) {
          return false;
        }

        const lower = item.toLowerCase();
        return ![
          'variable clinical features',
          'clinical features',
          'conditions',
          'problems',
          'abnormalities',
          'features',
          'symptoms',
        ].includes(lower);
      }),
  ).slice(0, 5);
}

function extractGardCauseSentences(text) {
  const keywords =
    /\b(caused by|result from|results from|due to|deletion|duplication|mutation|variant|gene|chromosome|missing piece|extra copy|loss of|inherited|sporadic|de novo|autosomal|x-linked)\b/i;

  return uniqueStrings(splitSentences(text).filter((sentence) => keywords.test(sentence))).slice(0, 3);
}

function inferSymptomBodySystem(feature) {
  const value = String(feature || '').toLowerCase();
  if (!value) {
    return '';
  }

  if (/(eye|vision|retina|optic|aniridia)/.test(value)) {
    return 'Eye';
  }

  if (/(brain|neurolog|intellectual|development|learning|autism|seizure|behavior)/.test(value)) {
    return 'Neurological';
  }

  if (/(kidney|renal|urinary|genitourinary|bladder|reproductive|testicle|ovary|hypospadias)/.test(value)) {
    return 'Urinary and reproductive';
  }

  if (/(heart|cardiac|blood|leukemia|tumor|cancer|malignan)/.test(value)) {
    return 'Blood and organs';
  }

  if (/(face|facial|skull|bone|growth|short stature|muscle)/.test(value)) {
    return 'Growth and skeletal';
  }

  if (/(skin|hair|nail)/.test(value)) {
    return 'Skin';
  }

  return '';
}

function localizeSymptomBodySystem(system, locale) {
  if (locale !== 'mn') {
    return system;
  }

  const labels = {
    Eye: 'Нүд',
    Neurological: 'Мэдрэлийн тогтолцоо',
    'Urinary and reproductive': 'Шээс, нөхөн үржихүйн тогтолцоо',
    'Blood and organs': 'Цус ба дотор эрхтэн',
    'Growth and skeletal': 'Өсөлт ба яс, булчин',
    Skin: 'Арьс',
  };

  return labels[system] || system;
}

function escapePattern(value = '') {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripDiseaseLead(text, diseaseName = '') {
  const source = String(text || '').trim();
  if (!source || !diseaseName) {
    return source;
  }

  const escaped = escapePattern(diseaseName);
  return source
    .replace(new RegExp(`^${escaped}\\s+(is|was|refers to)\\s+`, 'i'), '')
    .replace(new RegExp(`^${escaped}\\s*`, 'i'), '')
    .trim();
}

function localizeGardPhrase(text, locale) {
  const source = cleanFeatureText(text);
  if (!source) {
    return '';
  }

  if (locale !== 'mn') {
    return source.charAt(0).toUpperCase() + source.slice(1);
  }

  return replaceWithRules(source, [
    [/\bcertain malignancies\b/gi, 'зарим төрлийн хавдар'],
    [/\bdistinctive eye abnormalities\b/gi, 'нүдний онцлог өөрчлөлт'],
    [/\bglobal developmental delay\b/gi, 'ерөнхий хөгжлийн хоцрогдол'],
    [/\bintellectual disability\b/gi, 'оюуны хөгжлийн бэрхшээл'],
    [/\bdevelopmental delay\b/gi, 'хөгжлийн хоцрогдол'],
    [/\bdevelopmental delays\b/gi, 'хөгжлийн хоцрогдол'],
    [/\bgenitourinary problems\b/gi, 'шээс, бэлэг эрхтний тогтолцооны асуудал'],
    [/\bcongenital heart defects\b/gi, 'төрөлхийн зүрхний гажиг'],
    [/\bmild intellectual disability\b/gi, 'хөнгөн зэргийн оюуны хөгжлийн бэрхшээл'],
    [/\bdysmorphic facial features\b/gi, 'нүүрний хэлбэрийн онцлог өөрчлөлт'],
    [/\bmicrocephaly\b/gi, 'толгойн хэмжээ жижиг байх'],
    [/\bgrowth retardation\b/gi, 'өсөлтийн хоцрогдол'],
    [/\bgrowth delay\b/gi, 'өсөлтийн хоцрогдол'],
    [/\bshort stature\b/gi, 'намхан өсөлт'],
    [/\bhearing loss\b/gi, 'сонсгол буурах'],
    [/\bvision problems\b/gi, 'харааны асуудал'],
    [/\bvision\b/gi, 'хараа'],
    [/\bhearing\b/gi, 'сонсгол'],
    [/\bdevelopment\b/gi, 'хөгжил'],
    [/\bdelay\b/gi, 'хоцрогдол'],
    [/\beye abnormalities\b/gi, 'нүдний өөрчлөлт'],
    [/\bbehavioral problems\b/gi, 'зан үйлийн асуудал'],
    [/\bbehavioral abnormalities\b/gi, 'зан үйлийн өөрчлөлт'],
    [/\bautism-like behavior\b/gi, 'аутизмтай төстэй зан үйл'],
    [/\bother behavioral differences\b/gi, 'зан үйлийн бусад ялгаа'],
    [/\bcleft palate\b/gi, 'тагнайн сэтэрхий'],
    [/\brecurrent infections\b/gi, 'давтамжтай халдвар'],
    [/\bfeeding problems\b/gi, 'хооллолтын хүндрэл'],
    [/\bkidney abnormalities\b/gi, 'бөөрний өөрчлөлт'],
    [/\blearning disabilities\b/gi, 'суралцах хүндрэл'],
    [/\bunique facial characteristics\b/gi, 'нүүрний онцлог төрх'],
    [/\bhypoparathyroidism\b/gi, 'паратироид дааврын дутагдал'],
    [/\bthrombocytopenia\b/gi, 'ялтас эсийн тоо буурах'],
    [/\bscoliosis\b/gi, 'нуруу мурийх'],
    [/\bglobal developmental delay\b/gi, 'ерөнхий хөгжлийн хоцрогдол'],
    [/\blow muscle tone\b/gi, 'булчингийн сулрал'],
    [/\bhypotonia\b/gi, 'булчингийн сулрал'],
    [/\bpoor feeding\b/gi, 'муу хооллох'],
    [/\black of energy\b/gi, 'тамирдах'],
    [/\bvomiting\b/gi, 'бөөлжих'],
    [/\birritability\b/gi, 'цочромтгой болох'],
    [/\bdifficulty breathing\b/gi, 'амьсгалахад хүндрэлтэй болох'],
    [/\bseizures\b/gi, 'таталт'],
    [/\bcoma\b/gi, 'ком'],
    [/\bheart defects\b/gi, 'зүрхний гажиг'],
    [/\bhearing loss\b/gi, 'сонсгол буурах'],
    [/\bcognitive deficit\b/gi, 'танин мэдэхүйн хүндрэл'],
    [/\blanguage delay\b/gi, 'хэл ярианы хоцрогдол'],
    [/\bfacial features\b/gi, 'нүүрний онцлог'],
    [/\bwide-set eyes\b/gi, 'нүд хоорондын зай өргөн байх'],
    [/\bdroopy eyelids\b/gi, 'зовхи унжих'],
    [/\bsmall chin\b/gi, 'эрүү жижиг байх'],
    [/\bfriendly personality\b/gi, 'найрсаг зан араншин'],
    [/\bcleft lip\b/gi, 'урууны сэтэрхий'],
    [/\bautism spectrum disorder\b/gi, 'аутизмын хүрээний эмгэг'],
    [/\battention deficit hyperactivity disorder\b/gi, 'анхаарал дутмагшил, хэт хөдөлгөөнтөх эмгэг'],
    [/\bspeech delay\b/gi, 'хэл ярианы хоцрогдол'],
    [/\bgrowth delay\b/gi, 'өсөлтийн хоцрогдол'],
    [/\bfailure to thrive\b/gi, 'жин, өсөлт муу байх'],
    [/\bseizures\b/gi, 'таталт'],
    [/\bhypotonia\b/gi, 'булчингийн сулрал'],
    [/\bheart defects\b/gi, 'зүрхний гажиг'],
  ]);
}

function localizeGardSentence(text, locale, diseaseName = '') {
  const source = trimSentence(text);
  if (!source) {
    return '';
  }

  if (locale !== 'mn') {
    return `${source}.`;
  }

  const safeDiseaseName = escapePattern(diseaseName);
  const translated = replaceWithRules(source, [
    [new RegExp(`^${safeDiseaseName} is `, 'i'), `${diseaseName} нь `],
    [/^The syndrome is /i, 'Энэ хам шинж нь '],
    [/^The condition is /i, 'Энэ эмгэг нь '],
    [/^The disease is /i, 'Энэ өвчин нь '],
    [/^In most cases, /i, 'Ихэнх тохиолдолд, '],
    [/^In some cases, /i, 'Зарим тохиолдолд, '],
    [/^Only rarely /i, 'Ховор тохиолдолд '],
    [/^It is inherited in an autosomal dominant manner$/i, 'Энэ эмгэг аутосомын давамгай хэлбэрээр удамшиж болно'],
    [/^It is inherited in an autosomal recessive pattern$/i, 'Энэ эмгэг аутосомын рецессив хэлбэрээр удамшиж болно'],
    [/^It is important to ask whether the condition is inherited or happened sporadically$/i, 'Энэ эмгэг удамшсан эсэх, эсвэл санамсаргүй үүссэн эсэхийг тодруулах нь чухал'],
    [/\bis caused by\b/gi, 'шалтгаалдаг'],
    [/\bwas caused by\b/gi, 'шалтгаалсан'],
    [/\bresults from\b/gi, 'үүсдэг'],
    [/\bresult from\b/gi, 'үүсдэг'],
    [/\bdue to\b/gi, 'улмаас'],
    [/\bdeletion of genetic material\b/gi, 'генетикийн материалын устгал'],
    [/\bpartial deletion\b/gi, 'хэсэгчилсэн устгал'],
    [/\bpartial duplication\b/gi, 'хэсэгчилсэн олшрол'],
    [/\bextra piece of genetic material\b/gi, 'генетикийн материалын илүүдэл хэсэг'],
    [/\bextra copy\b/gi, 'илүүдэл хуулбар'],
    [/\bmissing piece of genetic material\b/gi, 'генетикийн материалын дутуу хэсэг'],
    [/\bmissing genetic information\b/gi, 'генетикийн мэдээллийн дутуу хэсэг'],
    [/\bshort \(p\) arm of chromosome 11\b/gi, '11-р хромосомын богино (p) мөр'],
    [/\bchromosome 11\b/gi, '11-р хромосом'],
    [/\bchromosome\b/gi, 'хромосом'],
    [/\bgene\b/gi, 'ген'],
    [/\bgenes\b/gi, 'генүүд'],
    [/\benzyme\b/gi, 'фермент'],
    [/\bprotein\b/gi, 'уураг'],
    [/\bmetabolism\b/gi, 'бодисын солилцоо'],
    [/\bcell division\b/gi, 'эсийн хуваагдал'],
    [/\bpassed down from a parent\b/gi, 'эцэг эхээс удамшсан'],
    [/\bmutation\b/gi, 'мутаци'],
    [/\bmutations\b/gi, 'мутациуд'],
    [/\bvariant\b/gi, 'хувилбар'],
    [/\bvariants\b/gi, 'хувилбарууд'],
    [/\bsporadic\b/gi, 'санамсаргүй үүссэн'],
    [/\bde novo\b/gi, 'шинээр үүссэн'],
    [/\binherited\b/gi, 'удамшсан'],
    [/\bautosomal dominant\b/gi, 'аутосомын давамгай'],
    [/\bautosomal recessive\b/gi, 'аутосомын рецессив'],
    [/\bx-linked\b/gi, 'X-холбоост'],
    [/\bearly embryonic development\b/gi, 'үр хөврөлийн эрт хөгжлийн үед'],
    [/\bfor unknown reasons\b/gi, 'шалтгаан нь тодорхойгүйгээр'],
    [/\bspontaneously\b/gi, 'санамсаргүйгээр'],
    [/\bonly rarely\b/gi, 'ховор тохиолдолд'],
    [/\bfor the first time\b/gi, 'анх удаа'],
    [/\babout 10% of cases are\b/gi, 'ойролцоогоор 10% нь'],
    [/\bnot inherited\b/gi, 'удамшдаггүй'],
    [/\boccurs randomly\b/gi, 'санамсаргүй үүсдэг'],
    [/\bdue to an error in cell division\b/gi, 'эсийн хуваагдлын алдаатай холбоотой'],
    [/\bbalanced translocation\b/gi, 'тэнцвэртэй транслокаци'],
    [/\bsmall part of chromosome 22\b/gi, '22-р хромосомын жижиг хэсэг'],
    [/\bnear the middle of the chromosome at a location known as q11\.2\b/gi, 'хромосомын дунд орчим дахь q11.2 байрлал'],
    [/\bmany different areas of the body\b/gi, 'биеийн олон тогтолцоо'],
    [/\bcan vary greatly in severity among people with the condition\b/gi, 'хүндийн зэрэг нь хүн бүрт ихээхэн ялгаатай байж болно'],
    [/\bcertain malignancies\b/gi, 'зарим төрлийн хавдар'],
    [/\bdistinctive eye abnormalities\b/gi, 'нүдний онцлог өөрчлөлт'],
    [/\bintellectual disability\b/gi, 'оюуны хөгжлийн бэрхшээл'],
    [/\bdevelopmental delays\b/gi, 'хөгжлийн хоцрогдол'],
    [/\bdevelopmental delay\b/gi, 'хөгжлийн хоцрогдол'],
    [/\bgenitourinary problems\b/gi, 'шээс, бэлэг эрхтний тогтолцооны асуудал'],
    [/\binvolves many different areas of the body\b/gi, 'биеийн олон тогтолцоонд нөлөөлж болох'],
    [/\borganic acid disorder\b/gi, 'органик хүчлийн солилцооны эмгэг'],
    [/\black adequate levels of an enzyme called ([A-Za-z0-9-]+)/gi, '$1 гэх фермент хангалтгүй байх'],
    [/\bprocessing of a particular amino acid called isoleucine\b/gi, 'изолейцин гэдэг амин хүчлийг боловсруулах үйл ажиллагаа'],
    [/\bthe buildup of the amino acid in the body\b/gi, 'уг бодис биед хуримтлагдах'],
  ])
    .replace(/\s+/g, ' ')
    .trim();

  return translated ? `${translated}.` : '';
}

function firstMatchingSentence(text, pattern) {
  return splitSentences(text).find((sentence) => pattern.test(sentence)) || '';
}

function isGenericGardCauseSnippet(snippet) {
  return /changes to the number or structure of a person’s chromosomes|change in the genetic material|more than one possible cause/i.test(
    snippet || '',
  );
}

function inferCauseInsight(entry, locale) {
  const source = `${entry.name} ${entry.summaryMedical} ${entry.causeSnippet}`.toLowerCase();

  if (/microdeletion|deletion|monosomy|missing piece|loss of|missing genetic information/.test(source)) {
    return {
      title: locale === 'mn' ? 'Үндсэн шалтгаан' : 'Main cause',
      description:
        locale === 'mn'
          ? 'Энэ өвчин нь генетикийн материалын дутуу хэсэг эсвэл хромосомын устгалтай холбоотой байж болно.'
          : 'This disease is commonly linked to missing genetic material or a chromosome deletion.',
    };
  }

  if (/microduplication|duplication|trisomy|tetrasomy|extra piece|extra copy/.test(source)) {
    return {
      title: locale === 'mn' ? 'Үндсэн шалтгаан' : 'Main cause',
      description:
        locale === 'mn'
          ? 'Энэ өвчин нь генетикийн материалын илүүдэл хэсэг эсвэл хромосомын олшролтой холбоотой байж болно.'
          : 'This disease is commonly linked to extra genetic material or a chromosome duplication.',
    };
  }

  if (/enzyme|metabolism|transport|lack adequate levels|deficiency/.test(source)) {
    return {
      title: locale === 'mn' ? 'Биологийн үндсэн өөрчлөлт' : 'Underlying biological change',
      description:
        locale === 'mn'
          ? 'Гол шалтгаан нь тодорхой ген, фермент, эсвэл бодисын солилцооны үйл ажиллагаа алдагдсантай холбоотой байж болно.'
          : 'The core cause may involve a gene, enzyme, or metabolic process not working as expected.',
    };
  }

  if (/gene|mutation|variant/.test(source)) {
    return {
      title: locale === 'mn' ? 'Генийн өөрчлөлт' : 'Gene change',
      description:
        locale === 'mn'
          ? 'Энэ өвчин нь тодорхой генийн өөрчлөлттэй холбоотой байж болно.'
          : 'This disease may be linked to a change in a specific gene.',
    };
  }

  if (/more than one possible cause/.test(source)) {
    return {
      title: locale === 'mn' ? 'Олон боломжит шалтгаан' : 'More than one possible cause',
      description:
        locale === 'mn'
          ? 'GARD-ийн мэдээллээр энэ өвчинд нэгээс олон боломжит шалтгаан байж болно.'
          : 'GARD notes that this disease may have more than one possible cause.',
    };
  }

  if (/chromosomal anomaly|chromosome|genetic material/.test(source)) {
    return {
      title: locale === 'mn' ? 'Хромосомын өөрчлөлт' : 'Chromosome change',
      description:
        locale === 'mn'
          ? 'Энэ өвчин нь хромосомын бүтэц эсвэл генетикийн материалын өөрчлөлттэй холбоотой байж болно.'
          : 'This disease may be linked to a change in chromosome structure or genetic material.',
    };
  }

  return null;
}

function buildGardCauseDetails(entry, locale) {
  if (locale === 'mn') {
    const causes = [];
    const causeLead = buildMnCauseLead(entry);
    const inheritanceLead = buildMnInheritanceLead(entry);
    const source = `${entry.summaryMedical} ${entry.summarySimple}`.toLowerCase();

    if (causeLead) {
      causes.push({
        title: 'Үндсэн шалтгаан',
        description: causeLead,
      });
    }

    if (inheritanceLead) {
      causes.push({
        title: 'Удамшлын хэлбэр',
        description: inheritanceLead,
      });
    }

    if (/cell division/.test(source)) {
      causes.push({
        title: 'Нэмэлт тайлбар',
        description: 'Зарим тохиолдолд эсийн хуваагдлын үеийн өөрчлөлттэй холбоотой байж болно.',
      });
    }

    if (!causes.length && entry.causeSnippet) {
      causes.push({
        title: 'Үндсэн шалтгаан',
        description: translateGardCauseSnippet(entry.causeSnippet, locale),
      });
    }

    return causes.slice(0, 3);
  }

  const causes = [];
  const primarySentence =
    firstMatchingSentence(
      entry.summaryMedical,
      /\b(caused by|due to|resulting from|results from|result from|deletion|duplication|mutation|variant|gene|enzyme|deficiency|missing piece|extra piece|loss of)\b/i,
    ) || '';
  const inheritanceSentence =
    firstMatchingSentence(entry.summaryMedical, /\b(inherited|de novo|sporadic|autosomal|x-linked|passed on|not inherited|occurs randomly)\b/i) ||
    '';
  const extraCauseSentence =
    firstMatchingSentence(
      entry.summaryMedical,
      /\b(cell division|genetic information|chromosomal anomaly|genetic material|hereditary)\b/i,
    ) || '';

  if (primarySentence) {
    const lower = primarySentence.toLowerCase();
    let title = locale === 'mn' ? 'Үндсэн шалтгаан' : 'Main cause';

    if (/(chromosome|deletion|duplication|monosomy|trisomy|tetrasomy)/.test(lower)) {
      title = locale === 'mn' ? 'Хромосомын өөрчлөлт' : 'Chromosome change';
    } else if (/(gene|mutation|variant|loss of)/.test(lower)) {
      title = locale === 'mn' ? 'Генийн өөрчлөлт' : 'Gene change';
    } else if (/(enzyme|metabolism|deficiency|transport)/.test(lower)) {
      title = locale === 'mn' ? 'Биологийн үндсэн өөрчлөлт' : 'Underlying biological change';
    }

    causes.push({
      title,
      description: localizeGardSentence(primarySentence, locale, entry.name),
    });
  } else {
    const inferred = inferCauseInsight(entry, locale);
    if (inferred) {
      causes.push(inferred);
    }
  }

  if (inheritanceSentence) {
    const localized = localizeGardSentence(inheritanceSentence, locale, entry.name);
    if (localized && !causes.some((item) => item.description === localized)) {
      causes.push({
        title: locale === 'mn' ? 'Удамшлын хэлбэр' : 'Inheritance pattern',
        description: localized,
      });
    }
  }

  if (extraCauseSentence) {
    const localized = localizeGardSentence(extraCauseSentence, locale, entry.name);
    if (localized && !causes.some((item) => item.description === localized)) {
      causes.push({
        title: locale === 'mn' ? 'Нэмэлт тайлбар' : 'Additional cause insight',
        description: localized,
      });
    }
  }

  if (entry.causeSnippet && (!causes.length || !isGenericGardCauseSnippet(entry.causeSnippet))) {
    const localizedSnippet = translateGardCauseSnippet(entry.causeSnippet, locale);
    if (localizedSnippet && !causes.some((item) => item.description === localizedSnippet)) {
      causes.push({
        title: locale === 'mn' ? 'GARD-ийн шалтгааны тэмдэглэл' : 'GARD cause note',
        description: localizedSnippet,
      });
    }
  }

  if (!causes.length) {
    const inferred = inferCauseInsight(entry, locale);
    if (inferred) {
      causes.push(inferred);
    }
  }

  return causes.slice(0, 3);
}

function buildGardSymptomDetails(entry, locale) {
  const features = extractGardFeaturePhrases(entry.summaryMedical);
  const symptoms = features.map((feature) => {
    const localizedFeature = localizeGardPhrase(feature, locale);
    return {
      medicalTerm: localizedFeature,
      description:
        locale === 'mn'
          ? `${localizedFeature} илэрч болох бөгөөд хүн бүрт ижил биш байж болно.`
          : `${localizedFeature} may be one of the main symptoms, but symptoms can differ from person to person.`,
      synonyms: [],
      frequency: '',
      bodySystem: localizeSymptomBodySystem(inferSymptomBodySystem(feature), locale),
    };
  });

  if (entry.symptomSnippet) {
    symptoms.push({
      medicalTerm: locale === 'mn' ? 'Шинж тэмдэг илрэх үе' : 'When symptoms may appear',
      description: translateGardSymptomSnippet(entry.symptomSnippet, locale),
      synonyms: [],
      frequency: '',
      bodySystem: '',
    });
  }

  return symptoms.slice(0, 6);
}

function translateGardCauseSnippet(snippet, locale) {
  const text = trimSentence(snippet);
  if (!text) {
    return '';
  }

  if (locale !== 'mn') {
    return `${text}.`;
  }

  const exactRules = [
    [
      /^This disease is caused by changes to the number or structure of a person’s chromosomes$/i,
      'Энэ өвчин нь хромосомын тоо эсвэл бүтцийн өөрчлөлтөөс шалтгаалдаг',
    ],
    [
      /^This disease is caused by a change in the genetic material \(DNA\)$/i,
      'Энэ өвчин нь генетикийн материал (DNA)-ын өөрчлөлтөөс шалтгаалдаг',
    ],
    [
      /^This disease is caused by a change in the genetic material$/i,
      'Энэ өвчин нь генетикийн материалын өөрчлөлтөөс шалтгаалдаг',
    ],
  ];

  for (const [pattern, value] of exactRules) {
    if (pattern.test(text)) {
      return `${value}.`;
    }
  }

  return `${replaceWithRules(text, [
    [/^This disease is caused by /i, 'Энэ өвчин нь '],
    [/^This condition is caused by /i, 'Энэ эмгэг нь '],
    [/\bchanges to the number or structure of a person’s chromosomes\b/gi, 'хромосомын тоо эсвэл бүтцийн өөрчлөлт'],
    [/\ba change in the genetic material \(DNA\)\b/gi, 'генетикийн материал (DNA)-ын өөрчлөлт'],
    [/\ba change in the genetic material\b/gi, 'генетикийн материалын өөрчлөлт'],
    [/\bchanges in the genetic material \(DNA\)\b/gi, 'генетикийн материал (DNA)-ын өөрчлөлт'],
  ])}.`;
}

function translateGardSymptomSnippet(snippet, locale) {
  const text = trimSentence(snippet);
  if (!text) {
    return '';
  }

  if (locale !== 'mn') {
    return `${text}.`;
  }

  const translated = replaceWithRules(text, [
    [/^May start to appear /i, 'Шинж тэмдэг нь '],
    [/\bduring Pregnancy\b/g, 'жирэмсний үед'],
    [/\bas a Newborn\b/g, 'нярай үед'],
    [/\bas an Infant\b/g, 'нярайгаас бага насанд'],
    [/\bas a Child\b/g, 'хүүхэд насанд'],
    [/\bas a Teenager\b/g, 'өсвөр насанд'],
    [/\bas an Adolescent\b/g, 'өсвөр насанд'],
    [/\bas an Adult\b/g, 'насанд хүрсэн үед'],
    [/\bas an Older Adult\b/g, 'ахимаг насанд'],
    [/\bat any time in life\b/g, 'амьдралын аль ч үед'],
    [/\band\b/g, 'эсвэл'],
  ]);

  return `${translated.replace(/\s+/g, ' ').trim()} илэрч эхэлж болно.`
    .replace('илэрч эхэлж болно илэрч эхэлж болно.', 'илэрч эхэлж болно.');
}

function translateGardLeadToMn(text, diseaseName) {
  const source = trimSentence(text);
  if (!source) {
    return '';
  }

  const translated = replaceWithRules(source, [
    [new RegExp(`^${diseaseName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} is `, 'i'), `${diseaseName} нь `],
    [/^A rare /i, 'Ховор '],
    [/^An inherited /i, 'Удамшлын '],
    [/\bis a rare\b/gi, 'нь ховор'],
    [/\bis a\b/gi, 'нь'],
    [/\bcharacterized by\b/gi, 'ихэвчлэн дараах онцлогоор илэрдэг:'],
    [/\bassociated with\b/gi, '-тай холбоотой'],
    [/\band\/or\b/gi, 'болон/эсвэл'],
    [/\bsyndrome\b/gi, 'хам шинж'],
    [/\bdisease\b/gi, 'өвчин'],
    [/\bdisorder\b/gi, 'эмгэг'],
    [/\bcondition\b/gi, 'эмгэг'],
    [/\bgenetic\b/gi, 'генетикийн'],
    [/\bchromosomal\b/gi, 'хромосомын'],
    [/\bdisorder that involves many different areas of the body and can vary greatly in severity among people with the condition\b/gi, 'биеийн олон тогтолцоонд нөлөөлж болох ба хүндийн зэрэг нь хүн бүрт ихээхэн ялгаатай байж болно'],
    [/\bcondition caused by an extra piece of genetic material on chromosome 2\b/gi, '2-р хромосом дээрх генетикийн материалын илүүдэл хэсгээс шалтгаалдаг эмгэг'],
    [/\bintellectual disability\b/gi, 'оюуны хөгжлийн бэрхшээл'],
    [/\bdevelopmental delay\b/gi, 'хөгжлийн хоцрогдол'],
    [/\bdevelopmental delays\b/gi, 'хөгжлийн хоцрогдол'],
    [/\bshort stature\b/gi, 'намхан өсөлт'],
    [/\bgrowth retardation\b/gi, 'өсөлтийн хоцрогдол'],
    [/\bmicrocephaly\b/gi, 'толгойн хэмжээ жижиг байх'],
    [/\bhypotonia\b/gi, 'булчингийн сулрал'],
    [/\bdysmorphic facial features\b/gi, 'нүүрний хэлбэрийн онцлог өөрчлөлт'],
    [/\bfacial dysmorphism\b/gi, 'нүүрний хэлбэрийн онцлог өөрчлөлт'],
    [/\bcongenital heart defects\b/gi, 'төрөлхийн зүрхний гажиг'],
    [/\bincreased risk of leukemia\b/gi, 'лейкозын эрсдэл нэмэгдэх'],
    [/\bcaused by\b/gi, 'шалтгаалдаг'],
  ])
    .replace(/\s+/g, ' ')
    .trim();

  return translated ? `${translated}.` : '';
}

function buildMnFeatureSentence(entry) {
  const features = extractGardFeaturePhrases(entry.summaryMedical)
    .map((item) => localizeGardPhrase(item, 'mn'))
    .filter(Boolean);

  if (!features.length) {
    return '';
  }

  const top = joinLocalizedList(features.slice(0, 4), 'mn');
  return `Илрэлд ${top} зэрэг шинж орж болно.`;
}

function findSummarySentence(text, diseaseName, pattern) {
  return (
    splitSentences(text).find((sentence) => pattern.test(stripDiseaseLead(sentence, diseaseName))) || ''
  );
}

function extractGeneSymbol(text) {
  return text.match(/\b([A-Z0-9-]{2,}) gene\b/)?.[1] || '';
}

function extractLocusLabel(entry) {
  const source = `${entry.name} ${entry.summaryMedical}`;
  return (
    source.match(/\b([0-9XY]+[pq](?:[0-9.]+)?(?:q[0-9.]+|p[0-9.]+)?)\b/i)?.[1] ||
    source.match(/\bchromosome\s+([0-9XY]+)\b/i)?.[1] ||
    ''
  );
}

function buildMnCauseLead(entry) {
  const source = `${entry.name} ${entry.summaryMedical} ${entry.causeSnippet}`.toLowerCase();
  const gene = extractGeneSymbol(entry.summaryMedical);
  const locus = extractLocusLabel(entry);

  if (gene) {
    return `${gene} генийн өөрчлөлттэй холбоотой байж болно.`;
  }

  if (/microdeletion|deletion|monosomy|missing piece|loss of|missing genetic information/.test(source)) {
    return locus
      ? `${locus} хэсгийн генетикийн материал дутуу байхтай холбоотой байж болно.`
      : 'Генетикийн материал дутуу байхтай холбоотой байж болно.';
  }

  if (/microduplication|duplication|trisomy|tetrasomy|extra piece|extra copy/.test(source)) {
    return locus
      ? `${locus} хэсгийн генетикийн материал илүүдэхтэй холбоотой байж болно.`
      : 'Генетикийн материал илүүдэхтэй холбоотой байж болно.';
  }

  if (/enzyme|metabolism|transport|deficiency|organic acid/.test(source)) {
    return 'Тодорхой фермент эсвэл бодисын солилцооны үйл ажиллагаа алдагдсантай холбоотой байж болно.';
  }

  if (/more than one possible cause/.test(source)) {
    return 'Нэгээс олон боломжит шалтгаантай байж болно.';
  }

  if (/changes to the number or structure of a person’s chromosomes|chromosomal anomaly|chromosome|genetic material/.test(source)) {
    return 'Хромосомын тоо эсвэл бүтцийн өөрчлөлттэй холбоотой байж болно.';
  }

  return '';
}

function buildMnInheritanceLead(entry) {
  const source = `${entry.summaryMedical} ${entry.summarySimple}`.toLowerCase();

  if (/autosomal dominant/.test(source)) {
    return 'Аутосомын давамгай хэлбэрээр удамшиж болно.';
  }

  if (/autosomal recessive/.test(source)) {
    return 'Аутосомын рецессив хэлбэрээр удамшиж болно.';
  }

  if (/x-linked/.test(source)) {
    return 'X-холбоост хэлбэрээр удамшиж болно.';
  }

  if (/not inherited|de novo|sporadic|occurs randomly|for the first time|spontaneously/.test(source)) {
    return 'Ихэнх тохиолдолд удамшилгүйгээр шинээр үүсч болно.';
  }

  if (/inherited from a parent|passed on in a dominant pattern|inherits the deletion from an unaffected parent|inherited/.test(source)) {
    return 'Зарим тохиолдолд эцэг эхээс удамшиж болно.';
  }

  return '';
}

function buildMnMedicalSummary(entry, categories) {
  const translatedLead = `${entry.name} нь ${categories[0] || 'ховор өвчин'} ангилалд багтах ховор эмгэг юм.`;
  const featureSentence = buildMnFeatureSentence(entry);
  const causeSentence = buildMnCauseLead(entry);
  const inheritanceSentence = buildMnInheritanceLead(entry);

  const parts = [
    translatedLead,
    featureSentence,
    causeSentence ? `Гол шалтгаан нь ${trimSentence(causeSentence)}.` : '',
    inheritanceSentence,
  ].filter(Boolean);

  return uniqueStrings(parts).join(' ');
}

function buildMnSimpleSummary(entry, categories) {
  const features = extractGardFeaturePhrases(entry.summaryMedical)
    .map((item) => localizeGardPhrase(item, 'mn'))
    .filter(Boolean);
  const lead = features.length
    ? `${entry.name} нь ${categories[0] || 'ховор өвчин'} ангилалд багтах ховор өвчин бөгөөд ${joinLocalizedList(features.slice(0, 3), 'mn')} зэрэг өөрчлөлт илэрч болно.`
    : `${entry.name} нь ${categories[0] || 'ховор өвчин'} ангилалд багтах ховор өвчин юм.`;
  const causeSentence = buildMnCauseLead(entry);
  const inheritanceSentence = buildMnInheritanceLead(entry);

  const causePart = causeSentence
    ? `Гол шалтгаан нь ${trimSentence(causeSentence)}.`.replace(/\.\./g, '.')
    : '';
  const variabilityPart = 'Шинж тэмдэг болон хүндийн зэрэг нь хүн бүрт өөр байж болно.';
  const inheritancePart = inheritanceSentence || '';

  return [lead, causePart, variabilityPart, inheritancePart].filter(Boolean).join(' ');
}

function buildGardMedicalSummary(entry, locale, categories) {
  const categoryText = joinLocalizedList(categories, locale);

  if (locale !== 'mn') {
    return (
      String(entry.summaryMedical || '').trim() ||
      `This Rare Care page is an index entry based on the NIH Genetic and Rare Diseases Information Center (GARD) disease catalog. GARD classifies ${entry.name} under ${categoryText}. Use the GARD source below for condition-specific information about causes, symptoms, and treatment, and confirm care decisions with a clinician.`
    );
  }

  return buildMnMedicalSummary(entry, categories);
}

function buildGardSimpleSummary(entry, locale, categories) {
  const mainType = categories[0] || (locale === 'mn' ? 'ховор өвчин' : 'rare disease');

  if (locale !== 'mn') {
    return (
      String(entry.summarySimple || '').trim() ||
      'Rare Care added this disease so families can browse by name, letter, and official GARD category more easily. For a fuller explanation, open the GARD reference below and use it to prepare questions for your care team.'
    );
  }

  return buildMnSimpleSummary(entry, categories.length ? categories : [mainType]);
}

function diseaseCategories(disease) {
  return uniqueStrings(Array.isArray(disease.categories) ? disease.categories : [disease.category]);
}

function alphabetBucket(name) {
  const initial = String(name || '').trim().charAt(0).toUpperCase();
  if (!initial) {
    return '';
  }

  if (/[0-9]/.test(initial)) {
    return '0-9';
  }

  if (/[A-Z]/.test(initial)) {
    return initial;
  }

  return '';
}

function sortFacetLetters(left, right) {
  if (left.name === right.name) {
    return 0;
  }

  if (left.name === '0-9') {
    return -1;
  }

  if (right.name === '0-9') {
    return 1;
  }

  return left.name.localeCompare(right.name, 'en');
}

function buildFacetCounts(values, locale, sorter) {
  const counts = new Map();
  values.forEach((value) => {
    counts.set(value, (counts.get(value) || 0) + 1);
  });

  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort(sorter || ((left, right) => left.name.localeCompare(right.name, locale)));
}

async function readCachedGardDiseaseIndex() {
  gardDiseaseIndexPromise ??= readGardDiseaseIndex();
  return gardDiseaseIndexPromise;
}

function buildLocalDiseaseListItem(disease, locale) {
  const categories = diseaseCategories(disease);
  return {
    id: disease.id,
    slug: disease.slug,
    name: disease.name,
    aliases: disease.aliases || [],
    category: categories[0] || disease.category,
    categories,
    shortDescription: disease.shortDescription,
    source: 'rare-care',
    locale,
    updatedAt: disease.updatedAt,
  };
}

function buildGardDiseaseListItem(entry, locale, generatedAt) {
  const categories = localizeGardCategories(entry.categories, locale);
  const categoryText = categories.join(', ');
  const summaryLead = firstSentence(buildGardMedicalSummary(entry, locale, categories) || buildGardSimpleSummary(entry, locale, categories));

  return {
    id: entry.id,
    slug: entry.slug,
    name: entry.name,
    aliases: entry.aliases || [],
    category: categories[0] || '',
    categories,
    shortDescription:
      summaryLead ||
      (locale === 'mn'
        ? `${entry.name} нь NIH-ийн GARD жагсаалтад ${categoryText} ангиллаар бүртгэгдсэн ховор өвчин юм.`
        : `${entry.name} is listed in the NIH GARD rare disease catalog under ${categoryText}.`),
    source: 'gard',
    locale,
    updatedAt: generatedAt,
  };
}

function buildGardDiseaseDetail(entry, locale, generatedAt) {
  const categories = localizeGardCategories(entry.categories, locale);
  const categoryText = categories.join(', ');
  const summaryMedical = buildGardMedicalSummary(entry, locale, categories);
  const summarySimple = buildGardSimpleSummary(entry, locale, categories);
  const causes = buildGardCauseDetails(entry, locale);
  const symptoms = buildGardSymptomDetails(entry, locale);

  return {
    id: entry.id,
    slug: entry.slug,
    name: entry.name,
    aliases: entry.aliases || [],
    category: categories[0] || '',
    categories,
    shortDescription:
      firstSentence(summaryMedical) ||
      (locale === 'mn'
        ? `${entry.name} нь NIH-ийн GARD өвчний жагсаалтад ${categoryText} ангиллаар бүртгэгдсэн ховор эмгэг юм.`
        : `${entry.name} is indexed in the NIH GARD disease list under ${categoryText}.`),
    summaryMedical,
    summarySimple,
    causes,
    symptoms,
    references: [
      {
        title: locale === 'mn' ? 'NIH GARD лавлагаа' : 'NIH GARD reference',
        url: entry.url,
      },
    ],
    source: 'gard',
    locale,
    published: true,
    updatedAt: generatedAt,
  };
}

function resolveDiseaseCatalog(db, gardIndex, locale) {
  const catalog = [];
  const usedSlugs = new Set();

  publicOnly(db.diseases, locale).forEach((disease) => {
    catalog.push(buildLocalDiseaseListItem(disease, locale));
    usedSlugs.add(disease.slug);
  });

  gardIndex.diseases.forEach((entry) => {
    if (usedSlugs.has(entry.slug)) {
      return;
    }

    catalog.push(buildGardDiseaseListItem(entry, locale, gardIndex.generatedAt));
  });

  return catalog;
}

function requiredString(body, field, minLength = 1) {
  return typeof body[field] === 'string' && body[field].trim().length >= minLength;
}

function normalizedEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail(value));
}

function normalizeUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
}

function normalizeRole(value) {
  return validRoles.has(value) ? value : 'user';
}

function normalizeSlug(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function emailLocalPart(value) {
  return String(value || '').split('@')[0] || '';
}

function usernameExists(users, username, excludedUserId = '') {
  return users.some(
    (user) => user.id !== excludedUserId && normalizeUsername(user.username) === username,
  );
}

function uniqueUsername(users, desiredValue, fallbackValue = 'user', excludedUserId = '') {
  const base = normalizeUsername(desiredValue) || normalizeUsername(fallbackValue) || 'user';
  let candidate = base;
  let suffix = 2;

  while (usernameExists(users, candidate, excludedUserId)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }

  return candidate;
}

function ensureUserState(users) {
  let changed = false;

  users.forEach((user) => {
    const nextUsername = uniqueUsername(
      users,
      user.username || emailLocalPart(user.email) || user.name || user.id,
      user.name || user.id,
      user.id,
    );
    const nextRole = normalizeRole(user.role);

    if (user.username !== nextUsername) {
      user.username = nextUsername;
      changed = true;
    }

    if (user.role !== nextRole) {
      user.role = nextRole;
      changed = true;
    }

    if (typeof user.profileImageUrl !== 'string') {
      user.profileImageUrl = '';
      changed = true;
    }
  });

  return changed;
}

function ensureAuthCollections(db) {
  db.users ??= [];
  db.authSessions ??= [];
  ensureUserState(db.users);
  return db;
}

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    name: user.name,
    email: user.email,
    role: normalizeRole(user.role),
    profileImageUrl: user.profileImageUrl || '',
    createdAt: user.createdAt
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

function verifyPassword(password, storedHash) {
  const [salt, originalHash] = String(storedHash || '').split(':');
  if (!salt || !originalHash) {
    return false;
  }

  try {
    const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(originalHash, 'hex'), Buffer.from(derivedKey, 'hex'));
  } catch {
    return false;
  }
}

function readAuthToken(request) {
  const directToken = request.get('x-auth-token');
  if (directToken) {
    return directToken;
  }

  const authorization = request.get('authorization');
  if (authorization?.startsWith('Bearer ')) {
    return authorization.slice(7);
  }

  return '';
}

function findAuthenticatedUser(db, token) {
  const session = db.authSessions.find((item) => item.token === token);
  return session ? db.users.find((item) => item.id === session.userId) || null : null;
}

function requireAdminUser(db, token, response) {
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return null;
  }

  const user = findAuthenticatedUser(db, token);
  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return null;
  }

  if (normalizeRole(user.role) !== 'admin') {
    response.status(403).json({ message: 'Administrator access required.' });
    return null;
  }

  return user;
}

function defaultSeedEmail(username) {
  return `${username}@rarecare.local`;
}

async function ensureSeededAdminUsers() {
  const db = ensureAuthCollections(await readDatabase());
  let changed = false;
  const seedData = await readAdminUsersSeed();
  const admins = Array.isArray(seedData?.admins) ? seedData.admins : [];

  changed = ensureUserState(db.users) || changed;

  admins.forEach((seed) => {
    const username = normalizeUsername(seed.username);
    const password = String(seed.password || '');
    if (!username || password.trim().length < 8) {
      return;
    }

    const email = validEmail(seed.email) ? normalizedEmail(seed.email) : defaultSeedEmail(username);
    const name = String(seed.name || username).trim() || username;
    const existingUser =
      db.users.find((user) => normalizeUsername(user.username) === username) ||
      db.users.find((user) => user.email === email);

    if (existingUser) {
      const nextUsername = uniqueUsername(db.users, username, name, existingUser.id);
      if (existingUser.username !== nextUsername) {
        existingUser.username = nextUsername;
        changed = true;
      }

      if (existingUser.role !== 'admin') {
        existingUser.role = 'admin';
        changed = true;
      }

      if (!existingUser.email && validEmail(email)) {
        existingUser.email = email;
        changed = true;
      }

      if (typeof existingUser.profileImageUrl !== 'string') {
        existingUser.profileImageUrl = '';
        changed = true;
      }

      return;
    }

    db.users.push({
      id: `user-${crypto.randomUUID()}`,
      username: uniqueUsername(db.users, username, name),
      name,
      email,
      role: 'admin',
      profileImageUrl: '',
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString()
    });
    changed = true;
  });

  if (changed) {
    await writeDatabase(db);
  }
}

function isStoredProfileImage(value) {
  return String(value || '').startsWith(`${profileImageMountPath}/`);
}

async function deleteStoredProfileImage(imageUrl) {
  if (!isStoredProfileImage(imageUrl)) {
    return;
  }

  const fileName = basename(String(imageUrl || '').slice(profileImageMountPath.length));
  if (!fileName) {
    return;
  }

  try {
    await unlink(join(profileImagesDir, fileName));
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      throw error;
    }
  }
}

async function saveProfileImage(dataUrl, userId) {
  const match = String(dataUrl || '').match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,([a-zA-Z0-9+/=]+)$/);
  if (!match) {
    return null;
  }

  const [, mimeType, base64Data] = match;
  const extension = supportedProfileImageExtensions[mimeType.toLowerCase()];
  if (!extension) {
    return null;
  }

  const buffer = Buffer.from(base64Data, 'base64');
  if (!buffer.length || buffer.length > maxProfileImageBytes) {
    return null;
  }

  await mkdir(profileImagesDir, { recursive: true });

  const fileName = `${userId}-${crypto.randomUUID()}.${extension}`;
  await writeFile(join(profileImagesDir, fileName), buffer);
  return `${profileImageMountPath}/${fileName}`;
}

async function persistUserProfileImage(user, profileImageUrl) {
  const previousProfileImageUrl = user.profileImageUrl || '';
  const nextProfileImageValue = String(profileImageUrl || '').trim();

  if (!nextProfileImageValue) {
    user.profileImageUrl = '';
    await deleteStoredProfileImage(previousProfileImageUrl);
    return user.profileImageUrl;
  }

  if (nextProfileImageValue.startsWith('data:')) {
    const storedProfileImageUrl = await saveProfileImage(nextProfileImageValue, user.id);
    if (!storedProfileImageUrl) {
      throw new Error('INVALID_PROFILE_IMAGE');
    }

    user.profileImageUrl = storedProfileImageUrl;
    if (storedProfileImageUrl !== previousProfileImageUrl) {
      await deleteStoredProfileImage(previousProfileImageUrl);
    }
    return user.profileImageUrl;
  }

  user.profileImageUrl = nextProfileImageValue;
  return user.profileImageUrl;
}

app.get('/api/health', (_request, response) => {
  response.json({ ok: true, app: 'rare-care', database: 'json-file' });
});

app.get('/api/diseases', async (request, response) => {
  const [db, gardIndex] = await Promise.all([readDatabase(), readCachedGardDiseaseIndex()]);
  const locale = resolveLocale(String(request.query.locale || 'mn'));
  const query = String(request.query.query || '').trim().toLowerCase();
  const category = String(request.query.category || 'all');
  const letter = String(request.query.letter || 'all').toUpperCase();
  const sort = String(request.query.sort || 'name');
  const page = Math.max(Number(request.query.page || 1) || 1, 1);
  const pageSize = 24;

  const catalog = resolveDiseaseCatalog(db, gardIndex, locale);
  let filteredDiseases = catalog;

  if (query) {
    filteredDiseases = filteredDiseases.filter((disease) => {
      const searchable = [
        disease.name,
        disease.shortDescription,
        disease.category,
        ...(disease.categories || []),
        ...(disease.aliases || [])
      ]
        .join(' ')
        .toLowerCase();

      return searchable.includes(query);
    });
  }

  const categoryFacetSource =
    letter && letter !== 'ALL'
      ? filteredDiseases.filter((disease) => alphabetBucket(disease.name) === letter)
      : filteredDiseases;
  const letterFacetSource =
    category && category !== 'all'
      ? filteredDiseases.filter((disease) => (disease.categories || [disease.category]).includes(category))
      : filteredDiseases;

  const categories = buildFacetCounts(
    categoryFacetSource.flatMap((disease) => disease.categories || [disease.category]),
    locale,
  );
  const letters = buildFacetCounts(
    letterFacetSource.map((disease) => alphabetBucket(disease.name)).filter(Boolean),
    locale,
    sortFacetLetters,
  );

  if (category && category !== 'all') {
    filteredDiseases = filteredDiseases.filter((disease) =>
      (disease.categories || [disease.category]).includes(category),
    );
  }

  if (letter && letter !== 'ALL') {
    filteredDiseases = filteredDiseases.filter((disease) => alphabetBucket(disease.name) === letter);
  }

  filteredDiseases.sort((left, right) => {
    if (sort === 'updated') {
      return new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime();
    }

    return left.name.localeCompare(right.name, locale);
  });

  const total = filteredDiseases.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, pageCount);
  const start = (currentPage - 1) * pageSize;

  response.json({
    items: filteredDiseases.slice(start, start + pageSize),
    total,
    page: currentPage,
    pageSize,
    pageCount,
    categories,
    letters,
  });
});

app.get('/api/diseases/categories', async (request, response) => {
  const [db, gardIndex] = await Promise.all([readDatabase(), readCachedGardDiseaseIndex()]);
  const locale = resolveLocale(String(request.query.locale || 'mn'));
  const categories = buildFacetCounts(
    resolveDiseaseCatalog(db, gardIndex, locale).flatMap((disease) => disease.categories || [disease.category]),
    locale,
  );

  response.json({ categories });
});

app.get('/api/diseases/:locale/:slug', async (request, response) => {
  const [db, gardIndex] = await Promise.all([readDatabase(), readCachedGardDiseaseIndex()]);
  const locale = resolveLocale(request.params.locale);
  const disease = publicOnly(db.diseases, locale).find((item) => item.slug === request.params.slug);

  if (disease) {
    response.json({
      ...disease,
      categories: diseaseCategories(disease),
      source: 'rare-care',
    });
    return;
  }

  const gardDisease = gardIndex.diseases.find((item) => item.slug === request.params.slug);
  if (!gardDisease) {
    response.status(404).json({ message: 'Disease not found.' });
    return;
  }

  response.json(buildGardDiseaseDetail(gardDisease, locale, gardIndex.generatedAt));
});

app.get('/api/daily-corner', async (request, response) => {
  const db = await readDatabase();
  const locale = resolveLocale(String(request.query.locale || 'mn'));
  const entries = publicOnly(db.dailyCornerEntries, locale).sort((left, right) => right.date.localeCompare(left.date));

  response.json(entries);
});

app.get('/api/events', async (request, response) => {
  const db = await readDatabase();
  const locale = resolveLocale(String(request.query.locale || 'mn'));
  const events = publicOnly(db.events, locale).sort((left, right) => left.date.localeCompare(right.date));

  response.json(events);
});

app.post('/api/events/:id/registrations', async (request, response) => {
  const body = request.body || {};
  const attendees = Number(body.attendees);
  const db = await readDatabase();
  db.eventRegistrations ??= [];

  const event = db.events.find((item) => item.id === request.params.id && item.published);
  if (!event) {
    response.status(404).json({ message: 'Event not found.' });
    return;
  }

  if (
    !requiredString(body, 'name', 2) ||
    !requiredString(body, 'email', 5) ||
    !validEmail(body.email) ||
    !Number.isFinite(attendees) ||
    attendees < 1
  ) {
    response.status(400).json({ message: 'Please complete the required event registration fields.' });
    return;
  }

  const registration = {
    id: `event-registration-${crypto.randomUUID()}`,
    eventId: event.id,
    eventTitle: event.title,
    locale: event.locale,
    name: body.name.trim(),
    email: normalizedEmail(body.email),
    phone: String(body.phone || '').trim(),
    attendees,
    note: String(body.note || '').trim(),
    createdAt: new Date().toISOString()
  };

  db.eventRegistrations.push(registration);
  await writeDatabase(db);

  response.status(201).json({ id: registration.id, createdAt: registration.createdAt });
});

app.post('/api/auth/register', async (request, response) => {
  const body = request.body || {};
  const email = normalizedEmail(body.email);

  if (!requiredString(body, 'name', 2) || !validEmail(email) || !requiredString(body, 'password', 8)) {
    response.status(400).json({ message: 'Please complete the required registration fields.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const existingUser = db.users.find((user) => user.email === email);

  if (existingUser) {
    response.status(409).json({ message: 'An account with this email already exists.' });
    return;
  }

  const username = uniqueUsername(
    db.users,
    body.username || emailLocalPart(email) || body.name,
    body.name || 'user',
  );
  const user = {
    id: `user-${crypto.randomUUID()}`,
    username,
    name: body.name.trim(),
    email,
    role: 'user',
    profileImageUrl: '',
    passwordHash: hashPassword(body.password),
    createdAt: new Date().toISOString()
  };
  const session = {
    id: `session-${crypto.randomUUID()}`,
    userId: user.id,
    token: crypto.randomBytes(32).toString('hex'),
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  db.authSessions = db.authSessions.filter((item) => item.userId !== user.id);
  db.authSessions.push(session);
  await writeDatabase(db);

  response.status(201).json({ token: session.token, user: sanitizeUser(user) });
});

app.post('/api/auth/login', async (request, response) => {
  const body = request.body || {};
  const identifier = String(body.identifier || body.email || '').trim();
  const email = normalizedEmail(identifier);
  const username = normalizeUsername(identifier);

  if (!identifier || !requiredString(body, 'password', 8)) {
    response.status(400).json({ message: 'Please enter a valid username or email and password.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = db.users.find(
    (item) => item.email === email || normalizeUsername(item.username) === username,
  );

  if (!user || !verifyPassword(body.password, user.passwordHash)) {
    response.status(401).json({ message: 'Incorrect username, email, or password.' });
    return;
  }

  const session = {
    id: `session-${crypto.randomUUID()}`,
    userId: user.id,
    token: crypto.randomBytes(32).toString('hex'),
    createdAt: new Date().toISOString()
  };

  db.authSessions = db.authSessions.filter((item) => item.userId !== user.id);
  db.authSessions.push(session);
  await writeDatabase(db);

  response.json({ token: session.token, user: sanitizeUser(user) });
});

app.get('/api/auth/me', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);

  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  response.json({ user: sanitizeUser(user) });
});

app.patch('/api/auth/profile', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const body = request.body || {};
  if (!requiredString(body, 'name', 2)) {
    response.status(400).json({ message: 'Please complete the required profile fields.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);

  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  user.name = body.name.trim();
  if (typeof body.profileImageUrl === 'string') {
    try {
      await persistUserProfileImage(user, body.profileImageUrl);
    } catch (error) {
      if (error instanceof Error && error.message === 'INVALID_PROFILE_IMAGE') {
        response.status(400).json({ message: 'Please upload a valid profile image.' });
        return;
      }

      throw error;
    }
  }

  await writeDatabase(db);
  response.json({ user: sanitizeUser(user) });
});

app.patch('/api/auth/profile/photo', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const body = request.body || {};
  if (typeof body.profileImageUrl !== 'string') {
    response.status(400).json({ message: 'Please upload a valid profile image.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);

  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  try {
    await persistUserProfileImage(user, body.profileImageUrl);
  } catch (error) {
    if (error instanceof Error && error.message === 'INVALID_PROFILE_IMAGE') {
      response.status(400).json({ message: 'Please upload a valid profile image.' });
      return;
    }

    throw error;
  }

  await writeDatabase(db);
  response.json({ user: sanitizeUser(user) });
});

app.get('/api/admin/users', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);
  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  if (normalizeRole(user.role) !== 'admin') {
    response.status(403).json({ message: 'Administrator access required.' });
    return;
  }

  const users = [...db.users]
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt))
    .map((item) => sanitizeUser(item));

  response.json({ users });
});

app.post('/api/admin/users', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const body = request.body || {};
  const email = normalizedEmail(body.email);
  const requestedUsername = normalizeUsername(body.username);

  if (
    !requiredString(body, 'name', 2) ||
    !requestedUsername ||
    requestedUsername.length < 3 ||
    !validEmail(email) ||
    !requiredString(body, 'password', 8)
  ) {
    response.status(400).json({ message: 'Please complete the required user fields.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);
  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  if (normalizeRole(user.role) !== 'admin') {
    response.status(403).json({ message: 'Administrator access required.' });
    return;
  }

  if (db.users.some((item) => item.email === email)) {
    response.status(409).json({ message: 'An account with this email already exists.' });
    return;
  }

  if (usernameExists(db.users, requestedUsername)) {
    response.status(409).json({ message: 'That username is already in use.' });
    return;
  }

  const createdUser = {
    id: `user-${crypto.randomUUID()}`,
    username: requestedUsername,
    name: body.name.trim(),
    email,
    role: 'user',
    profileImageUrl: '',
    passwordHash: hashPassword(body.password),
    createdAt: new Date().toISOString()
  };

  db.users.push(createdUser);
  await writeDatabase(db);

  response.status(201).json({ user: sanitizeUser(createdUser) });
});

app.patch('/api/admin/users/:id', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const body = request.body || {};
  const username = normalizeUsername(body.username);
  const role = normalizeRole(body.role);
  const password = String(body.password || '');

  if (!username || username.length < 3) {
    response.status(400).json({ message: 'Please provide a valid username.' });
    return;
  }

  if (body.password && password.trim().length < 8) {
    response.status(400).json({ message: 'Password must be at least 8 characters long.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);
  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  if (normalizeRole(user.role) !== 'admin') {
    response.status(403).json({ message: 'Administrator access required.' });
    return;
  }

  const targetUser = db.users.find((item) => item.id === request.params.id);
  if (!targetUser) {
    response.status(404).json({ message: 'User not found.' });
    return;
  }

  if (usernameExists(db.users, username, targetUser.id)) {
    response.status(409).json({ message: 'That username is already in use.' });
    return;
  }

  if (targetUser.id === user.id && role !== 'admin') {
    response.status(400).json({ message: 'You cannot remove your own admin access.' });
    return;
  }

  targetUser.username = username;
  targetUser.role = role;

  if (password.trim()) {
    targetUser.passwordHash = hashPassword(password);
  }

  await writeDatabase(db);
  response.json({ user: sanitizeUser(targetUser) });
});

app.patch('/api/admin/users/:id/role', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(401).json({ message: 'Authentication required.' });
    return;
  }

  const body = request.body || {};
  if (normalizeRole(body.role) !== 'admin') {
    response.status(400).json({ message: 'Only admin promotion is supported right now.' });
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  const user = findAuthenticatedUser(db, token);
  if (!user) {
    response.status(401).json({ message: 'Session not found.' });
    return;
  }

  if (normalizeRole(user.role) !== 'admin') {
    response.status(403).json({ message: 'Administrator access required.' });
    return;
  }

  const targetUser = db.users.find((item) => item.id === request.params.id);
  if (!targetUser) {
    response.status(404).json({ message: 'User not found.' });
    return;
  }

  targetUser.role = 'admin';
  await writeDatabase(db);

  response.json({ user: sanitizeUser(targetUser) });
});

app.get('/api/admin/events', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.events ??= [];
  response.json(
    [...db.events].sort((left, right) => left.date.localeCompare(right.date) || left.title.localeCompare(right.title)),
  );
});

app.post('/api/admin/events', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  const body = request.body || {};
  const locale = resolveLocale(body.locale);

  if (
    !requiredString(body, 'title', 3) ||
    !requiredString(body, 'summary', 10) ||
    !requiredString(body, 'date', 8)
  ) {
    response.status(400).json({ message: 'Please complete the required event fields.' });
    return;
  }

  db.events ??= [];
  const id = `event-${normalizeSlug(body.title)}-${locale}-${crypto.randomUUID().slice(0, 8)}`;
  const createdAt = new Date().toISOString();

  db.events.push({
    id,
    title: body.title.trim(),
    summary: body.summary.trim(),
    description: String(body.description || '').trim(),
    date: String(body.date || '').trim(),
    startTime: String(body.startTime || '').trim(),
    endTime: String(body.endTime || '').trim(),
    organizer: String(body.organizer || '').trim(),
    location: String(body.location || '').trim(),
    image: String(body.image || '').trim(),
    link: String(body.link || '').trim(),
    locale,
    published: body.published !== false
  });

  await writeDatabase(db);
  response.status(201).json({ id, createdAt });
});

app.patch('/api/admin/events/:id', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.events ??= [];
  const event = db.events.find((item) => item.id === request.params.id);
  if (!event) {
    response.status(404).json({ message: 'Event not found.' });
    return;
  }

  const body = request.body || {};
  const locale = resolveLocale(body.locale);

  if (
    !requiredString(body, 'title', 3) ||
    !requiredString(body, 'summary', 10) ||
    !requiredString(body, 'date', 8)
  ) {
    response.status(400).json({ message: 'Please complete the required event fields.' });
    return;
  }

  event.title = body.title.trim();
  event.summary = body.summary.trim();
  event.description = String(body.description || '').trim();
  event.date = String(body.date || '').trim();
  event.startTime = String(body.startTime || '').trim();
  event.endTime = String(body.endTime || '').trim();
  event.organizer = String(body.organizer || '').trim();
  event.location = String(body.location || '').trim();
  event.image = String(body.image || '').trim();
  event.link = String(body.link || '').trim();
  event.locale = locale;
  event.published = body.published !== false;

  await writeDatabase(db);
  response.json({ event });
});

app.delete('/api/admin/events/:id', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.events ??= [];
  const index = db.events.findIndex((item) => item.id === request.params.id);
  if (index === -1) {
    response.status(404).json({ message: 'Event not found.' });
    return;
  }

  const [removed] = db.events.splice(index, 1);
  await writeDatabase(db);
  response.json({ id: removed.id });
});

app.get('/api/admin/daily-corner', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.dailyCornerEntries ??= [];
  response.json([...db.dailyCornerEntries].sort((left, right) => right.date.localeCompare(left.date)));
});

app.post('/api/admin/daily-corner', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  const body = request.body || {};
  const locale = resolveLocale(body.locale);

  if (
    !requiredString(body, 'title', 3) ||
    !requiredString(body, 'body', 20) ||
    !requiredString(body, 'date', 8)
  ) {
    response.status(400).json({ message: 'Please complete the required Daily Corner fields.' });
    return;
  }

  db.dailyCornerEntries ??= [];
  const id = `daily-${body.date}-${locale}-${crypto.randomUUID().slice(0, 8)}`;
  const createdAt = new Date().toISOString();

  db.dailyCornerEntries.push({
    id,
    date: String(body.date || '').trim(),
    title: body.title.trim(),
    quote: String(body.quote || '').trim(),
    body: body.body.trim(),
    reminderTitle: String(body.reminderTitle || '').trim(),
    reminderBody: String(body.reminderBody || '').trim(),
    image: String(body.image || '').trim(),
    audioUrl: String(body.audioUrl || '').trim(),
    locale,
    published: body.published !== false
  });

  await writeDatabase(db);
  response.status(201).json({ id, createdAt });
});

app.patch('/api/admin/daily-corner/:id', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.dailyCornerEntries ??= [];
  const entry = db.dailyCornerEntries.find((item) => item.id === request.params.id);
  if (!entry) {
    response.status(404).json({ message: 'Daily Corner entry not found.' });
    return;
  }

  const body = request.body || {};
  const locale = resolveLocale(body.locale);

  if (
    !requiredString(body, 'title', 3) ||
    !requiredString(body, 'body', 20) ||
    !requiredString(body, 'date', 8)
  ) {
    response.status(400).json({ message: 'Please complete the required Daily Corner fields.' });
    return;
  }

  entry.date = String(body.date || '').trim();
  entry.title = body.title.trim();
  entry.quote = String(body.quote || '').trim();
  entry.body = body.body.trim();
  entry.reminderTitle = String(body.reminderTitle || '').trim();
  entry.reminderBody = String(body.reminderBody || '').trim();
  entry.image = String(body.image || '').trim();
  entry.audioUrl = String(body.audioUrl || '').trim();
  entry.locale = locale;
  entry.published = body.published !== false;

  await writeDatabase(db);
  response.json({ entry });
});

app.delete('/api/admin/daily-corner/:id', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.dailyCornerEntries ??= [];
  const index = db.dailyCornerEntries.findIndex((item) => item.id === request.params.id);
  if (index === -1) {
    response.status(404).json({ message: 'Daily Corner entry not found.' });
    return;
  }

  const [removed] = db.dailyCornerEntries.splice(index, 1);
  await writeDatabase(db);
  response.json({ id: removed.id });
});

app.get('/api/admin/diseases', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.diseases ??= [];
  response.json(
    [...db.diseases].sort(
      (left, right) =>
        left.name.localeCompare(right.name, left.locale) || right.updatedAt.localeCompare(left.updatedAt),
    ),
  );
});

app.post('/api/admin/diseases', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  const body = request.body || {};
  const locale = resolveLocale(body.locale);
  const slug = normalizeSlug(body.slug || body.name);

  if (
    !slug ||
    !requiredString(body, 'name', 3) ||
    !requiredString(body, 'category', 2) ||
    !requiredString(body, 'shortDescription', 10) ||
    !requiredString(body, 'summaryMedical', 20) ||
    !requiredString(body, 'summarySimple', 20)
  ) {
    response.status(400).json({ message: 'Please complete the required disease fields.' });
    return;
  }

  db.diseases ??= [];
  if (db.diseases.some((item) => item.locale === locale && item.slug === slug)) {
    response.status(409).json({ message: 'A disease entry with this slug already exists for that language.' });
    return;
  }

  const aliases = Array.isArray(body.aliases)
    ? body.aliases.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  const causes = Array.isArray(body.causes)
    ? body.causes
        .map((item) => ({
          title: String(item?.title || '').trim(),
          description: String(item?.description || '').trim(),
          image: String(item?.image || '').trim(),
        }))
        .filter((item) => item.title && item.description)
    : [];
  const symptoms = Array.isArray(body.symptoms)
    ? body.symptoms
        .map((item) => ({
          medicalTerm: String(item?.medicalTerm || '').trim(),
          description: String(item?.description || '').trim(),
          synonyms: Array.isArray(item?.synonyms)
            ? item.synonyms.map((synonym) => String(synonym || '').trim()).filter(Boolean)
            : [],
          frequency: String(item?.frequency || '').trim(),
          bodySystem: String(item?.bodySystem || '').trim(),
        }))
        .filter((item) => item.medicalTerm && item.description)
    : [];
  const references = Array.isArray(body.references)
    ? body.references
        .map((item) => ({
          title: String(item?.title || '').trim(),
          url: String(item?.url || '').trim(),
        }))
        .filter((item) => item.title && item.url)
    : [];
  const updatedAt = new Date().toISOString();
  const id = `disease-${slug}-${locale}-${crypto.randomUUID().slice(0, 8)}`;

  db.diseases.push({
    id,
    slug,
    name: body.name.trim(),
    aliases,
    category: body.category.trim(),
    shortDescription: body.shortDescription.trim(),
    summaryMedical: body.summaryMedical.trim(),
    summarySimple: body.summarySimple.trim(),
    causes,
    symptoms,
    references,
    locale,
    published: body.published !== false,
    updatedAt
  });

  await writeDatabase(db);
  response.status(201).json({ id, slug, updatedAt });
});

app.patch('/api/admin/diseases/:id', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.diseases ??= [];
  const disease = db.diseases.find((item) => item.id === request.params.id);
  if (!disease) {
    response.status(404).json({ message: 'Disease not found.' });
    return;
  }

  const body = request.body || {};
  const locale = resolveLocale(body.locale);
  const slug = normalizeSlug(body.slug || body.name);

  if (
    !slug ||
    !requiredString(body, 'name', 3) ||
    !requiredString(body, 'category', 2) ||
    !requiredString(body, 'shortDescription', 10) ||
    !requiredString(body, 'summaryMedical', 20) ||
    !requiredString(body, 'summarySimple', 20)
  ) {
    response.status(400).json({ message: 'Please complete the required disease fields.' });
    return;
  }

  if (
    db.diseases.some(
      (item) => item.id !== disease.id && item.locale === locale && item.slug === slug,
    )
  ) {
    response.status(409).json({ message: 'A disease entry with this slug already exists for that language.' });
    return;
  }

  const aliases = Array.isArray(body.aliases)
    ? body.aliases.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  const causes = Array.isArray(body.causes)
    ? body.causes
        .map((item) => ({
          title: String(item?.title || '').trim(),
          description: String(item?.description || '').trim(),
          image: String(item?.image || '').trim(),
        }))
        .filter((item) => item.title && item.description)
    : [];
  const symptoms = Array.isArray(body.symptoms)
    ? body.symptoms
        .map((item) => ({
          medicalTerm: String(item?.medicalTerm || '').trim(),
          description: String(item?.description || '').trim(),
          synonyms: Array.isArray(item?.synonyms)
            ? item.synonyms.map((synonym) => String(synonym || '').trim()).filter(Boolean)
            : [],
          frequency: String(item?.frequency || '').trim(),
          bodySystem: String(item?.bodySystem || '').trim(),
        }))
        .filter((item) => item.medicalTerm && item.description)
    : [];
  const references = Array.isArray(body.references)
    ? body.references
        .map((item) => ({
          title: String(item?.title || '').trim(),
          url: String(item?.url || '').trim(),
        }))
        .filter((item) => item.title && item.url)
    : [];

  disease.slug = slug;
  disease.name = body.name.trim();
  disease.aliases = aliases;
  disease.category = body.category.trim();
  disease.shortDescription = body.shortDescription.trim();
  disease.summaryMedical = body.summaryMedical.trim();
  disease.summarySimple = body.summarySimple.trim();
  disease.causes = causes;
  disease.symptoms = symptoms;
  disease.references = references;
  disease.locale = locale;
  disease.published = body.published !== false;
  disease.updatedAt = new Date().toISOString();

  await writeDatabase(db);
  response.json({ disease });
});

app.delete('/api/admin/diseases/:id', async (request, response) => {
  const db = ensureAuthCollections(await readDatabase());
  const adminUser = requireAdminUser(db, readAuthToken(request), response);
  if (!adminUser) {
    return;
  }

  db.diseases ??= [];
  const index = db.diseases.findIndex((item) => item.id === request.params.id);
  if (index === -1) {
    response.status(404).json({ message: 'Disease not found.' });
    return;
  }

  const [removed] = db.diseases.splice(index, 1);
  await writeDatabase(db);
  response.json({ id: removed.id });
});

app.post('/api/auth/logout', async (request, response) => {
  const token = readAuthToken(request);
  if (!token) {
    response.status(204).end();
    return;
  }

  const db = ensureAuthCollections(await readDatabase());
  db.authSessions = db.authSessions.filter((item) => item.token !== token);
  await writeDatabase(db);

  response.status(204).end();
});

app.post('/api/donations', async (request, response) => {
  const body = request.body || {};
  const amount = Number(body.amount);
  const validDonationType = ['one_time', 'monthly'].includes(body.donationType);
  const validPaymentType = ['credit_card', 'qpay'].includes(body.paymentType);

  if (
    !validDonationType ||
    !Number.isFinite(amount) ||
    amount < 1 ||
    !validPaymentType ||
    !body.consentAccepted ||
    !body.captchaPassed ||
    !requiredString(body, 'firstName', 2) ||
    !requiredString(body, 'lastName', 2) ||
    !requiredString(body, 'address', 5) ||
    !requiredString(body, 'country', 2) ||
    !requiredString(body, 'stateProvince', 2) ||
    !requiredString(body, 'city', 2) ||
    !requiredString(body, 'postalCode', 2) ||
    !requiredString(body, 'email', 5)
  ) {
    response.status(400).json({ message: 'Please complete the required donation fields.' });
    return;
  }

  const db = await readDatabase();
  const donation = {
    id: `donation-${crypto.randomUUID()}`,
    donationType: body.donationType,
    amount,
    dedicateTo: body.dedicateTo || '',
    note: body.note || '',
    firstName: body.firstName.trim(),
    lastName: body.lastName.trim(),
    address: body.address.trim(),
    country: body.country.trim(),
    stateProvince: body.stateProvince.trim(),
    city: body.city.trim(),
    postalCode: body.postalCode.trim(),
    email: body.email.trim(),
    phone: body.phone || '',
    paymentType: body.paymentType,
    consentAccepted: true,
    status: process.env.NODE_ENV === 'production' ? 'pending' : 'paid',
    createdAt: new Date().toISOString()
  };

  db.donationSubmissions.push(donation);
  await writeDatabase(db);

  response.status(201).json({ id: donation.id, status: donation.status, createdAt: donation.createdAt });
});

app.post('/api/contact', async (request, response) => {
  const body = request.body || {};

  if (
    !requiredString(body, 'name', 2) ||
    !requiredString(body, 'email', 5) ||
    !requiredString(body, 'subject', 3) ||
    !requiredString(body, 'message', 10)
  ) {
    response.status(400).json({ message: 'Please complete the required contact fields.' });
    return;
  }

  const db = await readDatabase();
  const contact = {
    id: `contact-${crypto.randomUUID()}`,
    name: body.name.trim(),
    email: body.email.trim(),
    subject: body.subject.trim(),
    message: body.message.trim(),
    createdAt: new Date().toISOString()
  };

  db.contactMessages.push(contact);
  await writeDatabase(db);

  response.status(201).json(contact);
});

const angularDist = join(__dirname, 'public', 'browser');

app.use(profileImageMountPath, express.static(profileImagesDir));

if (existsSync(angularDist)) {
  app.use(express.static(angularDist));
  app.get(/^(?!\/api).*/, (_request, response) => {
    response.sendFile(join(angularDist, 'index.html'));
  });
}

async function start() {
  await ensureSeededAdminUsers();

  app.listen(port, () => {
    console.log(`Rare Care Express API listening on http://localhost:${port}`);
  });
}

start().catch((error) => {
  console.error('Rare Care failed to start.', error);
  process.exit(1);
});
