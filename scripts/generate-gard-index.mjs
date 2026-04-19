import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const outputPath = join(rootDir, 'server', 'data', 'gard-disease-index.json');

const diseasesUrl = 'https://rarediseases.info.nih.gov/assets/diseases.trimmed.json';
const categoriesUrl = 'https://rarediseases.info.nih.gov/assets/diseases.categories.json';
const referencePageUrl = 'https://rarediseases.info.nih.gov/diseases/categories';
const userAgent = 'Rare Care GARD sync/1.0 (+https://rarediseases.info.nih.gov)';
const concurrency = Math.max(Number(process.env.GARD_CONCURRENCY || 6) || 6, 1);
const limit = Math.max(Number(process.env.GARD_LIMIT || 0) || 0, 0);
const forceRefresh = process.env.GARD_FORCE_REFRESH === '1';

function unique(values) {
  return [...new Set(values)];
}

function slugify(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function cleanAliases(values) {
  return unique(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean),
  );
}

function cleanText(value = '') {
  return String(value)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_match, digits) => String.fromCharCode(Number(digits)))
    .replace(/&#x([0-9a-f]+);/gi, (_match, digits) => String.fromCharCode(parseInt(digits, 16)))
    .replace(/\s+/g, ' ')
    .trim();
}

function readSummary(html) {
  const match = html.match(
    /<h5[^>]*>\s*Summary\s*<\/h5>[\s\S]*?<span[^>]*class="host[^"]*"[^>]*>([\s\S]*?)<\/span>/i,
  );

  return cleanText(match?.[1] || '');
}

function readSnippetValue(html, label) {
  const pattern = new RegExp(
    `<strong[^>]*>\\s*${label}\\s*:<\\/strong><span[^>]*>([\\s\\S]*?)<\\/span>`,
    'i',
  );
  return cleanText(html.match(pattern)?.[1] || '');
}

function stripLeadIn(text, diseaseName) {
  const escapedName = diseaseName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`^${escapedName}\\s+(is|was|refers to)\\s+`, 'i'),
    new RegExp(`^${escapedName}\\s*`, 'i'),
    /^[A-Z0-9][A-Za-z0-9(),\-/'\s]{0,90}\s+(is|was|refers to)\s+/i,
  ];

  for (const pattern of patterns) {
    if (pattern.test(text)) {
      return text.replace(pattern, '').trim();
    }
  }

  return text.trim();
}

function simplifySentence(sentence, diseaseName) {
  let simplified = sentence
    .replace(/\bin which there is a predisposition to several conditions, including\b/gi, 'that can affect')
    .replace(/\bcharacterized by\b/gi, 'that can cause')
    .replace(/\bcongenital heart defects\b/gi, 'heart differences present from birth')
    .replace(/\bdysmorphic facial features\b/gi, 'facial differences')
    .replace(/\bfacial dysmorphism\b/gi, 'facial differences')
    .replace(/\bglobal developmental delay\b/gi, 'slower overall development')
    .replace(/\bdevelopmental delay\b/gi, 'slower development')
    .replace(/\bgrowth retardation\b/gi, 'slow growth')
    .replace(/\bmicrocephaly\b/gi, 'a smaller-than-expected head size')
    .replace(/\bhypotonia\b/gi, 'low muscle tone')
    .replace(/\bcognitive impairment\b/gi, 'learning or thinking difficulties')
    .replace(/\bautosomal\b/gi, 'inherited')
    .replace(/\btrisomy\/tetrasomy\b/gi, 'extra chromosome material')
    .replace(/\bpredisposition to\b/gi, 'higher chance of')
    .replace(/\bmalignancies\b/gi, 'cancers')
    .replace(/\bgenitourinary\b/gi, 'urinary or genital')
    .replace(/\bintellectual disability\b/gi, 'learning or development problems')
    .replace(/\bdevelopmental delays\b/gi, 'slower development')
    .replace(/\bcongenital\b/gi, 'present from birth')
    .replace(/\bdeletion of genetic material\b/gi, 'a missing piece of genetic material')
    .replace(/\bshort \(p\) arm of chromosome 11\b/gi, 'short arm of chromosome 11')
    .replace(/\bspontaneously\b/gi, 'by chance')
    .replace(/\bde novo\b/gi, 'new and not inherited')
    .replace(/\bsporadic\b/gi, 'by chance')
    .replace(/\bindividuals\b/gi, 'people')
    .replace(/\bsyndrome\b/gi, 'condition')
    .replace(/\banomalies\b/gi, 'differences')
    .replace(/\bmultisystem\b/gi, 'whole-body')
    .replace(/\bmanifestations\b/gi, 'signs')
    .replace(/\bphenotype\b/gi, 'set of features')
    .replace(/\bneoplasms\b/gi, 'tumors')
    .replace(/\betiology\b/gi, 'cause')
    .replace(/\bassociated with\b/gi, 'linked to')
    .replace(/\bmay be present\b/gi, 'can happen')
    .replace(/\bmay occur\b/gi, 'can happen')
    .replace(/\bcan include\b/gi, 'may include')
    .replace(/\ba a\b/gi, 'a')
    .replace(/\s+/g, ' ')
    .trim();

  const withoutLead = stripLeadIn(simplified, diseaseName);
  if (withoutLead && withoutLead !== simplified) {
    simplified = `${diseaseName} is ${withoutLead}`;
  }

  return simplified;
}

function splitSentences(text) {
  return cleanText(text)
    .split(/(?<=[.!?])\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function lowerFirst(value) {
  return value ? value.charAt(0).toLowerCase() + value.slice(1) : value;
}

function polishPlainLanguage(value) {
  return String(value || '')
    .replace(/\brare,\s+/gi, 'rare ')
    .replace(/\ba a\b/gi, 'a')
    .replace(/\bcondition condition\b/gi, 'condition')
    .replace(/\s+\./g, '.')
    .replace(/\s+/g, ' ')
    .trim();
}

function buildPlainLanguageSummary(summary, diseaseName, causeSnippet, symptomSnippet) {
  const sentences = splitSentences(summary);
  const featureSentence = sentences.find((sentence) => !/acronym/i.test(sentence)) || sentences[0] || '';
  const causeSentence =
    sentences.find(
      (sentence) =>
        sentence !== featureSentence && /\bcaused by\b|\bdeletion\b|\binherited\b|\bgenetic\b/i.test(sentence),
    ) || '';
  const extraSentence =
    sentences.find(
      (sentence) =>
        sentence !== featureSentence &&
        sentence !== causeSentence &&
        !/acronym/i.test(sentence) &&
        /\binclude\b|\bfeatures\b|\bsymptoms\b|\bdevelopment\b/i.test(sentence),
    ) || '';
  const chosen = [featureSentence, extraSentence, causeSentence]
    .filter(Boolean)
    .slice(0, 3)
    .map((sentence, index) => {
      const simplified = simplifySentence(sentence, diseaseName);
      if (index === 0) {
        const withoutLead = stripLeadIn(simplified, diseaseName);
        return withoutLead ? `${diseaseName} is ${lowerFirst(withoutLead)}` : simplified;
      }
      return simplified;
    })
    .filter((sentence, index, array) => array.indexOf(sentence) === index);

  if (!chosen.length) {
    const fallback = [];

    if (causeSnippet) {
      fallback.push(`${diseaseName} is linked to ${stripLeadIn(causeSnippet, 'This disease').toLowerCase()}.`);
    }

    if (symptomSnippet) {
      fallback.push(`Symptoms ${symptomSnippet.charAt(0).toLowerCase()}${symptomSnippet.slice(1)}`);
    }

    return fallback.join(' ').trim();
  }

  return polishPlainLanguage(chosen.join(' '));
}

function buildFallbackMedicalSummary(entry) {
  const categoryText = (entry.categories || []).join(', ');
  return `${entry.name} is listed by NIH GARD under ${categoryText}. Open the GARD reference for the condition-specific clinical summary, causes, symptoms, and care considerations.`;
}

function buildFallbackSimpleSummary(entry, causeSnippet, symptomSnippet) {
  const parts = [
    `${entry.name} is included in the GARD rare disease library so people can find it more easily.`,
  ];

  if (causeSnippet) {
    parts.push(causeSnippet);
  }

  if (symptomSnippet) {
    parts.push(`Symptoms ${symptomSnippet.charAt(0).toLowerCase()}${symptomSnippet.slice(1)}`);
  }

  return parts.join(' ').replace(/\s+/g, ' ').trim();
}

async function readJson(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': userAgent },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.status}`);
  }

  return response.json();
}

async function readText(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': userAgent },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.status}`);
  }

  return response.text();
}

async function readExistingIndex() {
  try {
    const raw = await readFile(outputPath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function mapWithConcurrency(items, mapper) {
  const results = new Array(items.length);
  let cursor = 0;

  async function worker() {
    while (cursor < items.length) {
      const current = cursor;
      cursor += 1;
      results[current] = await mapper(items[current], current);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
  return results;
}

async function enrichDiseaseEntry(entry, existingEntry, index, total) {
  if (
    !forceRefresh &&
    existingEntry?.summaryMedical &&
    existingEntry?.summarySimple &&
    existingEntry?.summarySource === 'gard-page'
  ) {
    return {
      ...entry,
      summaryMedical: existingEntry.summaryMedical,
      summarySimple: existingEntry.summarySimple,
      symptomSnippet: existingEntry.symptomSnippet || '',
      causeSnippet: existingEntry.causeSnippet || '',
      summarySource: existingEntry.summarySource,
    };
  }

  try {
    const html = await readText(entry.url);
    const summaryMedical = readSummary(html);
    const symptomSnippet = readSnippetValue(html, 'Symptoms');
    const causeSnippet = readSnippetValue(html, 'Cause');
    const summarySimple = buildPlainLanguageSummary(
      summaryMedical,
      entry.name,
      causeSnippet,
      symptomSnippet,
    );

    if ((index + 1) % 100 === 0 || index + 1 === total) {
      console.log(`Enriched ${index + 1}/${total} GARD diseases`);
    }

    return {
      ...entry,
      summaryMedical: summaryMedical || buildFallbackMedicalSummary(entry),
      summarySimple: summarySimple || buildFallbackSimpleSummary(entry, causeSnippet, symptomSnippet),
      symptomSnippet,
      causeSnippet,
      summarySource: summaryMedical ? 'gard-page' : 'gard-fallback',
    };
  } catch (error) {
    console.warn(`Falling back for ${entry.name}: ${error.message}`);
    return {
      ...entry,
      summaryMedical: existingEntry?.summaryMedical || buildFallbackMedicalSummary(entry),
      summarySimple:
        existingEntry?.summarySimple || buildFallbackSimpleSummary(entry, existingEntry?.causeSnippet || '', existingEntry?.symptomSnippet || ''),
      symptomSnippet: existingEntry?.symptomSnippet || '',
      causeSnippet: existingEntry?.causeSnippet || '',
      summarySource: existingEntry?.summarySource || 'gard-fallback',
    };
  }
}

async function main() {
  const [categories, diseases, existingIndex] = await Promise.all([
    readJson(categoriesUrl),
    readJson(diseasesUrl),
    readExistingIndex(),
  ]);
  const categoryMap = new Map(categories.map((category) => [category.name, category.nameCurated]));
  const existingById = new Map((existingIndex?.diseases || []).map((entry) => [entry.id, entry]));
  const usedSlugs = new Set();

  const transformedDiseases = diseases
    .map((disease) => {
      const mappedCategories = unique(
        (Array.isArray(disease.tagsDiseaseCategory) ? disease.tagsDiseaseCategory : [])
          .map((tag) => categoryMap.get(tag))
          .filter(Boolean),
      );

      if (!mappedCategories.length) {
        return null;
      }

      const baseSlug = slugify(disease.encodedName || disease.name);
      let slug = baseSlug || `gard-${disease.id}`;
      if (usedSlugs.has(slug)) {
        slug = `${slug}-gard-${disease.id}`;
      }
      usedSlugs.add(slug);

      return {
        id: `gard-${disease.id}`,
        gardId: disease.id,
        slug,
        name: String(disease.name || '').trim(),
        aliases: cleanAliases(disease.synonyms),
        categories: mappedCategories,
        url: `https://rarediseases.info.nih.gov/diseases/${disease.id}/${disease.encodedName || slug}`,
      };
    })
    .filter(Boolean)
    .sort((left, right) => left.name.localeCompare(right.name, 'en'));

  const scopedDiseases = limit ? transformedDiseases.slice(0, limit) : transformedDiseases;
  const enrichedDiseases = await mapWithConcurrency(scopedDiseases, (entry, index) =>
    enrichDiseaseEntry(entry, existingById.get(entry.id), index, scopedDiseases.length),
  );

  const payload = {
    generatedAt: new Date().toISOString(),
    source: {
      diseasesUrl,
      categoriesUrl,
      referencePageUrl,
    },
    categories: categories.map((category) => ({
      key: category.name,
      name: category.nameCurated,
      description: category.textSnippet,
    })),
    diseases: enrichedDiseases,
  };

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  console.log(
    `Saved ${payload.diseases.length} GARD-indexed diseases across ${payload.categories.length} official categories to ${outputPath}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
