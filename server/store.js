import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dataDir = dirname(fileURLToPath(import.meta.url));
const dbPath = join(dataDir, 'data', 'db.json');
const adminUsersPath = join(dataDir, 'data', 'admin-users.json');

export async function readDatabase() {
  const raw = await readFile(dbPath, 'utf8');
  return JSON.parse(raw);
}

export async function writeDatabase(database) {
  await writeFile(dbPath, `${JSON.stringify(database, null, 2)}\n`, 'utf8');
}

export async function readAdminUsersSeed() {
  const raw = await readFile(adminUsersPath, 'utf8');
  return JSON.parse(raw);
}
