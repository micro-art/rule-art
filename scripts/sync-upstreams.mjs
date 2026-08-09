import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const configPath = join(projectRoot, 'config', 'upstreams.json');
const lockPath = join(projectRoot, 'state', 'upstreams.lock.json');
const sourceDirectory = join(projectRoot, 'src');
const apply = process.argv.includes('--apply');
const unsupportedArguments = process.argv.slice(2).filter((argument) => argument !== '--apply' && argument !== '--check');

if (unsupportedArguments.length > 0) {
  throw new Error(`Unsupported argument(s): ${unsupportedArguments.join(', ')}`);
}

async function main() {
const config = JSON.parse(await readFile(configPath, 'utf8'));
const previousLock = await readJsonIfPresent(lockPath);
const documents = new Map();
const summaries = [];
const removalReports = config.removalReports ?? [];
const managedBlocksByOwner = new Map(
  config.upstreams.flatMap((upstream) => upstream.targets.map((target) => [target.destination, target.managedBlock])),
);

for (const owner of config.ownerOrder) {
  documents.set(owner, await readRuleDocument(owner, managedBlocksByOwner.get(owner)));
}

const upstreamRules = new Map();
const nextLock = {
  schemaVersion: 1,
  upstreams: {},
};

for (const upstream of config.upstreams) {
  const revision = await resolveBranchRevision(upstream.repository, upstream.branch);
  const sourceLock = {
    repository: upstream.repository,
    branch: upstream.branch,
    revision,
    targets: {},
  };

  const fetchedTargets = await Promise.all(
    upstream.targets.map(async (target) => {
      const [content, verifier] = await Promise.all([
        fetchRepositoryFile(upstream.repository, revision, target.remoteFile),
        target.verifyWith ? fetchRepositoryFile(upstream.repository, revision, target.verifyWith) : null,
      ]);
      return { target, content, verifier };
    }),
  );

  for (const { target, content, verifier } of fetchedTargets) {
    const parsed = parseDomainList(content, `${upstream.id}/${target.remoteFile}`);

    if (verifier) {
      verifyGfwList(verifier, parsed, `${upstream.id}/${target.verifyWith}`);
    }

    const regexFingerprint = fingerprint(parsed.regex);
    const previousTargetLock = previousLock?.upstreams?.[upstream.id]?.targets?.[target.id];

    if (previousTargetLock?.regexFingerprint && previousTargetLock.regexFingerprint !== regexFingerprint) {
      throw new Error(
        `${upstream.id}/${target.remoteFile} changed its quarantined regex rules; manual review is required.`,
      );
    }

    upstreamRules.set(target.destination, {
      ...target,
      upstream: upstream.id,
      rules: parsed.rules.map((rule) => ({ rule, origin: 'managed' })),
    });
    sourceLock.targets[target.id] = {
      remoteFile: target.remoteFile,
      contentFingerprint: fingerprint([content]),
      regexCount: parsed.regex.length,
      regexFingerprint,
      ruleCount: parsed.rules.length,
    };
  }

  nextLock.upstreams[upstream.id] = sourceLock;
}

const ownerIndex = new RuleIndex();
const rulesByOwner = new Map();
const renderedDocuments = new Map();
const renderedReports = new Map();

for (const owner of config.ownerOrder) {
  const document = documents.get(owner);
  const managed = upstreamRules.get(owner);
  const candidateRules = parseDocumentEntries(document.manualLines, 'manual').map(({ rule }) => rule);

  for (const report of removalReports.filter(({ removedOwner }) => removedOwner === owner)) {
    const content = renderRemovalReport(report, candidateRules, rulesByOwner);
    if (content) renderedReports.set(report.report, content);
  }

  const result = normalizeDocument(
    document,
    managed,
    ownerIndex,
    config.strictIsolation,
  );

  renderedDocuments.set(owner, result.content);
  rulesByOwner.set(owner, result.rules);
  ownerIndex.addAll(result.rules);
  summaries.push({ owner, ...result.summary });
}

const pendingWrites = [];

for (const [owner, content] of renderedDocuments) {
  const document = documents.get(owner);
  if (content !== document.original) {
    pendingWrites.push({ path: document.path, content });
  }
}

for (const [report, content] of renderedReports) {
  const path = join(projectRoot, report);
  if (content !== (await readTextIfPresent(path))) {
    pendingWrites.push({ path, content });
  }
}

const nextLockContent = `${JSON.stringify(nextLock, null, 2)}\n`;
const lockChanged = nextLockContent !== (await readTextIfPresent(lockPath));

for (const summary of summaries) {
  process.stdout.write(
    `${summary.owner}: kept=${summary.kept}, imported=${summary.imported}, removed=${summary.removed}, protected=${summary.protected}, strict=${summary.strict}\n`,
  );
}

if (pendingWrites.length === 0 && !lockChanged) {
  process.stdout.write('Upstream rules are already synchronized.\n');
  process.exit(0);
}

process.stdout.write(
  `Synchronization ${apply ? 'will update' : 'would update'} ${pendingWrites.length} source file(s)${lockChanged ? ' and the lock file' : ''}.\n`,
);

if (!apply) {
  process.stdout.write('Run with --apply to write the synchronized rules.\n');
  process.exit(0);
}

for (const pendingWrite of pendingWrites) {
  await mkdir(dirname(pendingWrite.path), { recursive: true });
  await writeFile(pendingWrite.path, pendingWrite.content);
}

if (lockChanged) {
  await mkdir(dirname(lockPath), { recursive: true });
  await writeFile(lockPath, nextLockContent);
}
}

function normalizeDocument(document, managed, ownerIndex, strictIsolation) {
  const manualEntries = parseDocumentEntries(document.manualLines, 'manual');
  const managedEntries = managed ? managed.rules : [];
  const entries = deduplicateExact([...manualEntries, ...managedEntries]);
  const filtered = [];
  let protectedCount = 0;
  let strictCount = 0;

  for (const entry of entries) {
    if (!isDomainRule(entry.rule)) {
      filtered.push(entry);
      continue;
    }

    if (ownerIndex.covers(entry.rule)) {
      protectedCount += 1;
      continue;
    }

    if (strictIsolation && ownerIndex.hasBroaderOverlap(entry.rule)) {
      strictCount += 1;
      continue;
    }

    filtered.push(entry);
  }

  const rules = removeCoveredRules(filtered);
  const manualRuleIndexes = new Set(
    rules
      .filter(({ origin }) => origin === 'manual')
      .map(({ sourceIndex }) => sourceIndex),
  );
  const managedRules = rules
    .filter(({ origin }) => origin === 'managed')
    .map(({ rule }) => rule)
    .sort(compareRules);
  const manualLines = document.manualLines.filter((line, index) => {
    const rule = parseSurgeRule(line);
    if (!rule) return true;
    return manualRuleIndexes.has(index);
  });
  const content = renderDocument(manualLines, managed?.managedBlock, managedRules);

  return {
    content,
    rules: rules.map(({ rule }) => rule),
    summary: {
      kept: rules.length,
      imported: managedRules.length,
      removed: entries.length - rules.length,
      protected: protectedCount,
      strict: strictCount,
    },
  };
}

function renderRemovalReport(report, candidateRules, rulesByOwner) {
  const matches = report.priorityOwners.flatMap((priorityOwner) => {
    const priorityRules = rulesByOwner.get(priorityOwner);
    if (!priorityRules) {
      throw new Error(`Removal report requires an earlier owner: ${priorityOwner}`);
    }
    return findRuleOverlaps(candidateRules, priorityRules).map((match) => ({ ...match, priorityOwner }));
  });

  if (matches.length === 0) return null;

  const lines = [
    `# ${report.removedOwner}.list automatic overlap removals`,
    '',
    `These rules were removed from ${report.removedOwner}.list because a higher-priority rule already covers them.`,
    `Total semantic overlaps: ${matches.length}.`,
  ];

  const groups = new Map();
  for (const match of matches) {
    const group = groups.get(match.relationship) ?? [];
    group.push(match);
    groups.set(match.relationship, group);
  }

  for (const relationship of [...groups.keys()].sort()) {
    lines.push('', `## ${relationship}`);
    for (const match of groups.get(relationship).sort(compareOverlapMatches)) {
      lines.push(
        `- \`${formatRule(match.left)}\` → \`${formatRule(match.right)}\` (${match.priorityOwner}.list)`,
      );
    }
  }

  return `${lines.join('\n')}\n`;
}

function findRuleOverlaps(leftRules, rightRules) {
  const index = new OverlapIndex(rightRules);
  const matches = new Map();

  for (const left of leftRules) {
    if (!isDomainRule(left)) continue;
    for (const right of index.findOverlaps(left)) {
      const relationship = describeOverlap(left, right);
      matches.set(`${ruleKey(left)}\u0000${ruleKey(right)}`, { left, right, relationship });
    }
  }

  return [...matches.values()];
}

class OverlapIndex {
  constructor(rules) {
    this.root = createNode();
    for (const rule of rules) this.add(rule);
  }

  add(rule) {
    if (!isDomainRule(rule)) return;
    const node = this.nodeFor(rule.value, true);
    node.rules.push(rule);
  }

  findOverlaps(rule) {
    const matches = new Map();
    const labels = rule.value.split('.').reverse();
    let node = this.root;

    for (let index = 0; index < labels.length; index += 1) {
      node = node.children.get(labels[index]);
      if (!node) return [...matches.values()];

      for (const candidate of node.rules) {
        if (candidate.type === 'DOMAIN-SUFFIX' || index === labels.length - 1) {
          matches.set(ruleKey(candidate), candidate);
        }
      }
    }

    if (rule.type === 'DOMAIN-SUFFIX') this.collectDescendants(node, matches);
    return [...matches.values()];
  }

  collectDescendants(node, matches) {
    for (const candidate of node.rules) matches.set(ruleKey(candidate), candidate);
    for (const child of node.children.values()) this.collectDescendants(child, matches);
  }

  nodeFor(value, create) {
    let node = this.root;

    for (const label of value.split('.').reverse()) {
      let child = node.children.get(label);
      if (!child) {
        if (!create) return null;
        child = createNode();
        node.children.set(label, child);
      }
      node = child;
    }

    return node;
  }
}

function describeOverlap(left, right) {
  if (left.value === right.value) {
    return left.type === right.type ? 'Identical rule' : 'Same host / suffix boundary';
  }
  if (left.type === 'DOMAIN-SUFFIX' && right.value.endsWith(`.${left.value}`)) {
    return 'Removed suffix contains higher-priority rule';
  }
  if (right.type === 'DOMAIN-SUFFIX' && left.value.endsWith(`.${right.value}`)) {
    return 'Higher-priority suffix contains removed rule';
  }
  throw new Error(`Unexpected overlap: ${ruleKey(left)} / ${ruleKey(right)}`);
}

function compareOverlapMatches(left, right) {
  return `${left.priorityOwner}\u0000${ruleKey(left.left)}\u0000${ruleKey(left.right)}`.localeCompare(
    `${right.priorityOwner}\u0000${ruleKey(right.left)}\u0000${ruleKey(right.right)}`,
  );
}

function deduplicateExact(entries) {
  const byKey = new Map();

  for (const entry of entries) {
    const key = ruleKey(entry.rule);
    const existing = byKey.get(key);

    if (!existing || (entry.origin === 'managed' && existing.origin !== 'managed')) {
      byKey.set(key, entry);
    }
  }

  return [...byKey.values()];
}

function removeCoveredRules(entries) {
  const index = new RuleIndex();
  index.addAll(entries.map(({ rule }) => rule));

  return entries.filter((entry) => !isDomainRule(entry.rule) || !index.isCoveredByAnother(entry.rule));
}

function renderDocument(manualLines, managedBlock, managedRules) {
  const trimmedManual = [...manualLines];
  while (trimmedManual.at(-1) === '') trimmedManual.pop();

  if (!managedBlock) {
    return `${trimmedManual.join('\n')}\n`;
  }

  const block = [
    `# BEGIN rule-art:managed ${managedBlock}`,
    ...managedRules.map(formatRule),
    `# END rule-art:managed ${managedBlock}`,
  ];
  const prefix = trimmedManual.length > 0 ? `${trimmedManual.join('\n')}\n\n` : '';
  return `${prefix}${block.join('\n')}\n`;
}

async function readRuleDocument(owner, managedBlock) {
  const path = join(sourceDirectory, `${owner}.list`);
  const original = await readFile(path, 'utf8');
  const block = findManagedBlock(original, managedBlock);

  return {
    path,
    original,
    manualLines: block ? [...block.before, ...block.after] : original.split(/\r?\n/),
  };
}

function findManagedBlock(content, blockId) {
  if (!blockId) return null;

  const lines = content.split(/\r?\n/);
  const begin = `# BEGIN rule-art:managed ${blockId}`;
  const end = `# END rule-art:managed ${blockId}`;
  const beginIndex = lines.indexOf(begin);

  if (beginIndex === -1) return null;

  const endIndex = lines.indexOf(end, beginIndex + 1);
  if (endIndex === -1) {
    throw new Error(`Missing managed-block end marker for ${blockId}`);
  }

  return {
    before: lines.slice(0, beginIndex),
    after: lines.slice(endIndex + 1),
  };
}

function parseDocumentEntries(lines, origin) {
  return lines.flatMap((line, sourceIndex) => {
    const rule = parseSurgeRule(line);
    return rule ? [{ rule, origin, sourceIndex }] : [];
  });
}

function parseSurgeRule(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  const separator = trimmed.indexOf(',');
  if (separator === -1) return null;

  const type = trimmed.slice(0, separator);
  const value = trimmed.slice(separator + 1);
  if (!type || !value) return null;

  return {
    type,
    value: isDomainRule({ type }) ? normalizeDomainValue(type, value) : value,
  };
}

function parseDomainList(content, sourceName) {
  const rules = [];
  const regex = [];

  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    if (!rawLine) continue;

    const separator = rawLine.indexOf(':');
    if (separator === -1) {
      throw new Error(`${sourceName}:${index + 1} has an invalid rule.`);
    }

    const type = rawLine.slice(0, separator);
    const value = rawLine.slice(separator + 1).split(':@', 1)[0].trim();

    if (type === 'regexp') {
      regex.push(value);
    } else if (type === 'full') {
      rules.push({ type: 'DOMAIN', value: normalizeDomainValue('DOMAIN', value) });
    } else if (type === 'domain') {
      rules.push({ type: 'DOMAIN-SUFFIX', value: normalizeDomainValue('DOMAIN-SUFFIX', value) });
    } else {
      throw new Error(`${sourceName}:${index + 1} has unsupported type ${type}.`);
    }
  }

  return { rules: deduplicateExact(rules.map((rule) => ({ rule, origin: 'managed' }))).map(({ rule }) => rule), regex };
}

function verifyGfwList(content, expected, sourceName) {
  const decoded = Buffer.from(content.trim(), 'base64').toString('utf8');
  const rules = [];
  const regex = [];

  for (const rawLine of decoded.split(/\r?\n/)) {
    if (!rawLine || rawLine.startsWith('!') || rawLine === '[AutoProxy 0.2.9]') continue;

    if (rawLine.startsWith('||')) {
      rules.push({ type: 'DOMAIN-SUFFIX', value: normalizeDomainValue('DOMAIN-SUFFIX', rawLine.slice(2)) });
    } else if (rawLine.startsWith('|http://') || rawLine.startsWith('|https://')) {
      const url = new URL(rawLine.slice(1));
      if (url.pathname !== '/' || url.search || url.hash || url.port) {
        throw new Error(`${sourceName} contains a URL rule that cannot be normalized safely.`);
      }
      rules.push({ type: 'DOMAIN', value: normalizeDomainValue('DOMAIN', url.hostname) });
    } else if (rawLine.startsWith('/') && rawLine.endsWith('/')) {
      regex.push(rawLine.slice(1, -1));
    } else {
      throw new Error(`${sourceName} contains an unsupported AutoProxy rule.`);
    }
  }

  const expectedRules = new Set(expected.rules.map(ruleKey));
  const actualRules = new Set(rules.map(ruleKey));

  if (!sameSet(expectedRules, actualRules) || !sameSet(new Set(expected.regex), new Set(regex))) {
    throw new Error(`${sourceName} does not match geolocation-!cn.txt.`);
  }
}

function normalizeDomainValue(type, value) {
  const normalized = value.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!normalized || /[\s,/#]/.test(normalized)) {
    throw new Error(`Invalid ${type} value: ${value}`);
  }
  return normalized;
}

class RuleIndex {
  constructor() {
    this.root = createNode();
    this.exactRules = new Set();
  }

  addAll(rules) {
    for (const rule of rules) this.add(rule);
  }

  add(rule) {
    if (!isDomainRule(rule)) return;

    if (rule.type === 'DOMAIN') {
      this.exactRules.add(rule.value);
    }

    const labels = rule.value.split('.').reverse();
    let node = this.root;

    for (const label of labels) {
      let child = node.children.get(label);
      if (!child) {
        child = createNode();
        node.children.set(label, child);
      }
      node.descendantCount += 1;
      node = child;
    }

    if (rule.type === 'DOMAIN') {
      node.exactCount += 1;
    } else {
      node.suffixCount += 1;
    }
  }

  covers(rule) {
    if (!isDomainRule(rule)) return false;
    if (rule.type === 'DOMAIN' && this.exactRules.has(rule.value)) return true;
    return this.hasAncestorSuffix(rule.value, true);
  }

  hasBroaderOverlap(rule) {
    if (!isDomainRule(rule) || rule.type === 'DOMAIN') return false;
    if (this.hasAncestorSuffix(rule.value, true)) return false;
    const node = this.nodeFor(rule.value, false);
    return Boolean(node && (node.exactCount > 0 || node.suffixCount > 0 || node.descendantCount > 0));
  }

  isCoveredByAnother(rule) {
    if (!isDomainRule(rule)) return false;
    if (rule.type === 'DOMAIN') return this.hasAncestorSuffix(rule.value, true);
    return this.hasAncestorSuffix(rule.value, false);
  }

  hasAncestorSuffix(value, includeSelf) {
    const labels = value.split('.').reverse();
    let node = this.root;

    for (let index = 0; index < labels.length; index += 1) {
      node = node.children.get(labels[index]);
      if (!node) return false;
      if ((includeSelf || index < labels.length - 1) && node.suffixCount > 0) return true;
    }

    return false;
  }

  nodeFor(value, create) {
    let node = this.root;

    for (const label of value.split('.').reverse()) {
      let child = node.children.get(label);
      if (!child) {
        if (!create) return null;
        child = createNode();
        node.children.set(label, child);
      }
      node = child;
    }

    return node;
  }
}

function createNode() {
  return {
    children: new Map(),
    rules: [],
    exactCount: 0,
    suffixCount: 0,
    descendantCount: 0,
  };
}

function isDomainRule(rule) {
  return rule.type === 'DOMAIN' || rule.type === 'DOMAIN-SUFFIX';
}

function ruleKey(rule) {
  return `${rule.type},${rule.value}`;
}

function formatRule(rule) {
  return `${rule.type},${rule.value}`;
}

function compareRules(left, right) {
  return ruleKey(left).localeCompare(ruleKey(right));
}

function fingerprint(values) {
  return createHash('sha256').update(values.join('\n')).digest('hex');
}

async function resolveBranchRevision(repository, branch) {
  const data = await fetchJson(`https://api.github.com/repos/${repository}/git/ref/heads/${branch}`);
  return data.object.sha;
}

async function fetchRepositoryFile(repository, revision, file) {
  const encodedPath = file.split('/').map(encodeURIComponent).join('/');
  const data = await fetchJson(
    `https://api.github.com/repos/${repository}/contents/${encodedPath}?ref=${encodeURIComponent(revision)}`,
  );
  if (data.encoding !== 'base64' || typeof data.content !== 'string') {
    throw new Error(`Unable to decode ${repository}/${file} at ${revision}.`);
  }
  return Buffer.from(data.content, 'base64').toString('utf8');
}

async function fetchJson(url) {
  const response = await fetchWithRetry(url);
  return response.json();
}

async function fetchWithRetry(url) {
  let lastError;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    let response;
    try {
      response = await fetch(url, { headers: githubHeaders() });
    } catch (error) {
      lastError = error;
    }

    if (response?.ok) return response;
    if (response && response.status < 500 && response.status !== 408 && response.status !== 429) {
      throw new Error(`Unable to fetch ${url}: HTTP ${response.status}`);
    }
    if (response) lastError = new Error(`Unable to fetch ${url}: HTTP ${response.status}`);
    if (attempt < 3) await delay(attempt * 500);
  }

  throw lastError;
}

function githubHeaders() {
  return process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {};
}

async function readJsonIfPresent(path) {
  const text = await readTextIfPresent(path);
  return text ? JSON.parse(text) : null;
}

async function readTextIfPresent(path) {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function sameSet(left, right) {
  return left.size === right.size && [...left].every((item) => right.has(item));
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

await main();
