import { copyFile, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceDirectory = join(projectRoot, 'src');
const clashDirectory = join(projectRoot, 'dist', 'ch');
const surgeDirectory = join(projectRoot, 'dist', 'sg');

const listFiles = await findListFiles(sourceDirectory);

if (listFiles.length === 0) {
  throw new Error(`No .list files found in ${sourceDirectory}`);
}

await Promise.all([
  rm(clashDirectory, { recursive: true, force: true }),
  rm(surgeDirectory, { recursive: true, force: true }),
]);

const skippedRules = [];

for (const sourceFile of listFiles) {
  const relativeFile = relative(sourceDirectory, sourceFile);
  const surgeFile = join(
    surgeDirectory,
    relativeFile.replace(/\.list$/i, '.txt'),
  );
  const clashFile = join(
    clashDirectory,
    relativeFile.replace(/\.list$/i, '.yaml'),
  );

  await mkdir(dirname(surgeFile), { recursive: true });
  await mkdir(dirname(clashFile), { recursive: true });

  // Keep the Surge distribution byte-for-byte identical to its source file.
  await copyFile(sourceFile, surgeFile);

  const source = await readFile(sourceFile, 'utf8');
  const payload = [];

  for (const [index, rawLine] of source.split(/\r?\n/).entries()) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) {
      continue;
    }

    const value = toClashPayloadValue(line, sourceFile, index + 1, skippedRules);

    if (value !== null) {
      payload.push(`  - ${quoteYaml(value)}`);
    }
  }

  await writeFile(clashFile, `payload:\n${payload.join('\n')}\n`);
}

if (skippedRules.length > 0) {
  process.stderr.write(
    `Skipped ${skippedRules.length} unsupported Clash rule(s):\n${skippedRules
      .map(({ file, line, type }) => `  - ${relative(projectRoot, file)}:${line} (${type})`)
      .join('\n')}\n`,
  );
}

process.stdout.write(
  `Built ${listFiles.length} rule set(s) in dist/ch and dist/sg.\n`,
);

async function findListFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const entryPath = join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await findListFiles(entryPath)));
    } else if (entry.isFile() && entry.name.endsWith('.list')) {
      files.push(entryPath);
    }
  }

  return files;
}

function toClashPayloadValue(rule, sourceFile, lineNumber, skippedRules) {
  const [type, rawValue] = rule.split(',', 2);

  if (!rawValue) {
    throw new Error(`Invalid rule at ${sourceFile}:${lineNumber}: ${rule}`);
  }

  switch (type) {
    case 'DOMAIN':
      return rawValue;
    case 'DOMAIN-SUFFIX':
      return `+.${rawValue.replace(/^\.+/, '')}`;
    case 'IP-CIDR':
    case 'IP-CIDR6':
      return rawValue;
    default:
      skippedRules.push({ file: sourceFile, line: lineNumber, type });
      return null;
  }
}

function quoteYaml(value) {
  return `'${value.replaceAll("'", "''")}'`;
}
