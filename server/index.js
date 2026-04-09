import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import cors from 'cors';
import express from 'express';
import morgan from 'morgan';

import { readAdminUsersSeed, readDatabase, writeDatabase } from './store.js';

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
  const db = await readDatabase();
  const locale = resolveLocale(String(request.query.locale || 'mn'));
  const query = String(request.query.query || '').trim().toLowerCase();
  const category = String(request.query.category || 'all');
  const sort = String(request.query.sort || 'name');

  let diseases = publicOnly(db.diseases, locale);

  if (query) {
    diseases = diseases.filter((disease) => {
      const searchable = [
        disease.name,
        disease.shortDescription,
        disease.category,
        ...(disease.aliases || [])
      ]
        .join(' ')
        .toLowerCase();

      return searchable.includes(query);
    });
  }

  if (category && category !== 'all') {
    diseases = diseases.filter((disease) => disease.category === category);
  }

  diseases.sort((left, right) => {
    if (sort === 'updated') {
      return new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime();
    }

    return left.name.localeCompare(right.name, locale);
  });

  response.json(diseases);
});

app.get('/api/diseases/categories', async (request, response) => {
  const db = await readDatabase();
  const locale = resolveLocale(String(request.query.locale || 'mn'));
  const categories = [...new Set(publicOnly(db.diseases, locale).map((disease) => disease.category))]
    .sort((left, right) => left.localeCompare(right, locale));

  response.json(categories);
});

app.get('/api/diseases/:locale/:slug', async (request, response) => {
  const db = await readDatabase();
  const locale = resolveLocale(request.params.locale);
  const disease = publicOnly(db.diseases, locale).find((item) => item.slug === request.params.slug);

  if (!disease) {
    response.status(404).json({ message: 'Disease not found.' });
    return;
  }

  response.json(disease);
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
