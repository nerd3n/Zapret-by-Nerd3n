'use strict';

// Run with: node tests/test_frontend_standard.js
// The actual frontend runs in a VM with a minimal DOM and fixture-only fetch.
// No HTTP request, Windows service, subprocess or bypass engine is started.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'web', 'index.html'), 'utf8');
const source = fs.readFileSync(path.join(root, 'web', 'app.js'), 'utf8');
const suite = {id: 'flowseal-standard-v1', name: 'Flowseal Standard', endpointCount: 17,
  httpChecksPerRepeat: 36, pingChecksPerRepeat: 17, error: null};

class Element {
  constructor(id = '') {
    Object.assign(this, {id, value: '', textContent: '', innerHTML: '', hidden: false,
      style: {}, dataset: {}, attributes: {}, children: {}, listeners: {},
      firstChild: {textContent: ''}});
    this.classList = {toggle: (name, enabled) => { this.attributes[`class:${name}`] = !!enabled; }};
  }
  get disabled() { return !!this._disabled; }
  set disabled(value) { this._disabled = !!value; }
  querySelector(selector) { return this.children[selector] ||= new Element(); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() {}
}

function baseState(overrides = {}) {
  return {admin: true, provider: '', city: '', testSuite: {...suite},
    strategies: [{id: 'stock-general', name: 'GENERAL', family: 'Stock', experimental: false}],
    externalProcessIds: [], process: {running: false}, serviceBusy: false,
    service: {supported: true, installed: false, owned: false, state: 'not_installed'},
    network: {status: 'unknown'}, job: {running: false, results: []}, autoSetup: {status: 'pending'},
    ...overrides};
}

function harness(initial = baseState()) {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(ids).size, ids.length, 'HTML ids are unique');
  for (const match of source.matchAll(/(?<!\$)\$\('([^']+)'\)/g)) {
    assert(ids.includes(match[1]), `Missing HTML element ${match[1]}`);
  }
  const elements = new Map(ids.map(id => [id, new Element(id)]));
  const baseline = new Element('baseline');
  let apiState = initial;
  let candidateInputs = [];
  const requests = [];
  const context = {console, AbortController, setTimeout, clearTimeout,
    location: {hash: ''}, localStorage: {getItem() {}, setItem() {}},
    window: {addEventListener() {}},
    document: {documentElement: new Element(), getElementById(id) {
      assert(elements.has(id), `Unexpected element ${id}`);
      return elements.get(id);
    }, querySelectorAll(selector) {
      if (selector === '[data-action="baseline"]') return [baseline];
      if (selector === '[data-candidate]') return candidateInputs;
      return [];
    }, addEventListener() {}},
    async fetch(url, options) {
      const body = options.body ? JSON.parse(options.body) : null;
      requests.push({url, method: options.method || 'GET', body});
      if (url === '/api/session') return {ok: true, json: async () => ({token: 'fixture-token'})};
      if (url === '/api/state') return {ok: true, json: async () => apiState};
      if (url === '/api/test' && options.method === 'POST') return {ok: true, json: async () => ({ok: true})};
      throw new Error(`No fixture for ${options.method || 'GET'} ${url}; network is forbidden`);
    }};
  const instrumented = source.replace(/  changeView\(\);\s+poll\(\);\s+timer = setInterval\(poll, 1800\);/,
    `  globalThis.fixtureUI = {
      set(next, options = {}) { state = next; online = options.online !== false; token = 'fixture-token';
        busy = !!options.busy; selectedId = next.strategies?.[0]?.id || ''; detailId = selectedId;
        candidates = new Set(options.candidates || [selectedId]); },
      candidateIds: () => [...candidates],
      buttonStates, render, renderResults, renderAutomatic, renderJob, renderTestSuite,
      resultMetrics, resultRows, resultDetails, serviceSummary, checkCell
    };`);
  assert.notEqual(instrumented, source, 'Fixture replaces polling startup');
  vm.runInNewContext(instrumented, context, {filename: 'web/app.js'});
  const ui = context.fixtureUI;
  function set(next, options) {
    apiState = next;
    candidateInputs = (next.strategies || []).map(strategy => {
      const input = new Element(); input.dataset.candidate = strategy.id; return input;
    });
    ui.set(next, options);
  }
  set(initial);
  return {ui, requests, baseline, set, element: id => elements.get(id),
    click: id => elements.get(id).listeners.click()};
}

function fullResult(repeats = 1) {
  const checks = [];
  for (let attempt = 1; attempt <= repeats; attempt++) {
    for (let target = 0; target < 12; target++) {
      for (const mode of ['HTTP', 'TLS1.2', 'TLS1.3', 'PING']) checks.push({
        target: `Endpoint ${target}`, service: target < 4 ? 'YouTube' : target < 8 ? 'Discord' : 'Control',
        url: `https://fixture-${target}.invalid/`, mode, attempt, ok: true, status: 'OK',
        error: null, httpStatus: mode === 'PING' ? null : 200, timeMs: 12});
    }
    for (let target = 0; target < 5; target++) checks.push({target: `Ping ${target}`, service: 'DNS',
      url: null, mode: 'PING', attempt, ok: true, status: 'OK', error: null, httpStatus: null, timeMs: 8});
  }
  return {suiteId: suite.id, strategyId: 'stock-general', name: 'GENERAL', checks, repeats,
    passed: 36 * repeats, total: 36 * repeats, pingPassed: 17 * repeats, pingTotal: 17 * repeats,
    expectedHttp: 36 * repeats, expectedPing: 17 * repeats, expectedChecks: 53 * repeats,
    unsupported: 0, complete: true, score: 100, medianMs: 12};
}

function oldResult() {
  return {strategyId: 'stock-general', name: 'Old 5/5', passed: 5, total: 5, score: 100,
    checks: Array.from({length: 5}, (_, index) => ({service: index < 3 ? 'YouTube' : 'Discord',
      target: `Old ${index}`, ok: true, httpStatus: 200, timeMs: 10}))};
}

test('legacy 5/5 and records without mode never show green success', () => {
  const {ui} = harness();
  for (const result of [oldResult(), {...oldResult(), suiteId: suite.id, complete: true},
    {...fullResult(), suiteId: 'another-suite'}]) {
    assert.equal(ui.resultMetrics(result).legacy, true);
    assert.match(ui.resultRows([result]), /Старая проверка · повторите Standard/);
    assert.doesNotMatch(ui.resultRows([result]), /pill success|5 \/ 5|100%/);
    assert.doesNotMatch(ui.serviceSummary('YouTube', [result]), /pill success/);
    assert.match(ui.serviceSummary('YouTube', [result]), /Повторите Standard/);
    assert.doesNotMatch(ui.resultDetails(result), /pill success/);
  }
});

test('full Standard counts 36 HTTP/TLS and 17 Ping independently per repeat', () => {
  const {ui} = harness();
  for (const repeats of [1, 2, 3]) {
    const result = fullResult(repeats), metrics = ui.resultMetrics(result);
    assert.equal(metrics.complete, true);
    assert.equal(metrics.passed, 36 * repeats);
    assert.equal(metrics.httpTotal, 36 * repeats);
    assert.equal(metrics.pingPassed, 17 * repeats);
    assert.equal(metrics.pingTotal, 17 * repeats);
    assert.equal(metrics.success, true);
    assert.match(ui.serviceSummary('YouTube', [result]), new RegExp(`HTTP/TLS: ${12 * repeats} / ${12 * repeats}`));
    assert.match(ui.serviceSummary('Discord', [result]), /Адреса отвечают/);
    assert.doesNotMatch(ui.serviceSummary('Discord', [result]), /сервис работает/i);
  }
});

test('a claimed Standard 5/5 cannot be promoted to a complete result', () => {
  const {ui} = harness();
  const result = {...fullResult(), checks: fullResult().checks.slice(0, 5), total: 5, passed: 5};
  delete result.expectedChecks; delete result.expectedHttp; delete result.expectedPing;
  const metrics = ui.resultMetrics(result);
  assert.equal(metrics.httpTotal, 36);
  assert.equal(metrics.complete, false);
  assert.equal(metrics.success, false);
  assert.doesNotMatch(ui.resultRows([result]) + ui.serviceSummary('YouTube', [result]), /pill success/);
});

test('UNSUP and SSL never count as OK even with a contradictory ok flag', () => {
  const {ui} = harness();
  const result = fullResult();
  result.checks[1].status = 'UNSUP'; result.checks[2].status = 'SSL';
  const metrics = ui.resultMetrics(result);
  assert.equal(metrics.passed, 34);
  assert.equal(metrics.unsupported, 1);
  assert.equal(metrics.success, false);
  const unsupported = ui.checkCell(result.checks[1], true);
  assert.match(unsupported, /pill neutral/);
  assert.match(unsupported, /UNSUP/);
  assert.doesNotMatch(unsupported, />OK<|pill success/);
  assert.doesNotMatch(ui.serviceSummary('YouTube', [result]), /pill success/);
  assert.match(ui.resultDetails(result), /TLS1\.2|TLS1\.3|PING/);
});

test('cancelled, errored and incomplete runs cannot have green result cells', () => {
  const {ui} = harness();
  const cancelled = fullResult(); cancelled.checks.at(-1).status = 'CANCELLED';
  for (const result of [{...fullResult(), complete: false}, {...fullResult(), error: 'Engine exited'},
    {...fullResult(), cancelled: true}, cancelled]) {
    assert.equal(ui.resultMetrics(result).success, false);
    assert.doesNotMatch(ui.resultRows([result]) + ui.resultDetails(result)
      + ui.serviceSummary('YouTube', [result]), /pill success/);
  }
});

test('duplicate records do not make up a full Standard run', () => {
  const {ui} = harness(), result = fullResult();
  result.checks[1] = {...result.checks[0]};
  assert.equal(ui.resultMetrics(result).complete, false);
  assert.doesNotMatch(ui.resultRows([result]), /pill success/);
});

test('Ping successes never inflate HTTP, and failed Ping does not erase HTTP responses', () => {
  const {ui} = harness(), httpFailed = fullResult(), pingFailed = fullResult();
  httpFailed.checks.filter(check => check.mode !== 'PING').forEach(check => { check.ok = false; check.status = 'ERROR'; });
  pingFailed.checks.filter(check => check.mode === 'PING').forEach(check => { check.ok = false; check.status = 'ERROR'; });
  assert.equal(ui.resultMetrics(httpFailed).passed, 0);
  assert.equal(ui.resultMetrics(httpFailed).pingPassed, 17);
  assert.equal(ui.resultMetrics(httpFailed).success, false);
  assert.equal(ui.resultMetrics(pingFailed).passed, 36);
  assert.equal(ui.resultMetrics(pingFailed).pingPassed, 0);
  assert.equal(ui.resultMetrics(pingFailed).success, true);
  assert.match(ui.resultRows([pingFailed]), /pill neutral">0 \/ 17/);
});

test('custom target metadata and result expectations override default cardinality', () => {
  const customSuite = {...suite, endpointCount: 2, httpChecksPerRepeat: 3, pingChecksPerRepeat: 2};
  const {ui} = harness(baseState({testSuite: customSuite}));
  const result = {...fullResult(), checks: [...fullResult().checks.slice(0, 4), fullResult().checks.at(-1)],
    passed: 3, total: 3, pingPassed: 2, pingTotal: 2, expectedChecks: 5, expectedHttp: 3, expectedPing: 2};
  assert.equal(ui.resultMetrics(result).success, true);
  assert.match(ui.serviceSummary('YouTube', [result]), /HTTP\/TLS: 3 \/ 3/);
  delete result.expectedChecks; delete result.expectedHttp; delete result.expectedPing;
  assert.equal(ui.resultMetrics(result).success, true);
  const previousResult = fullResult();
  assert.equal(ui.resultMetrics(previousResult).httpTotal, 36, 'Report retains its own expectations');
  assert.equal(ui.resultMetrics(previousResult).success, true);
});

test('unsupported Ping remains separate from HTTP/TLS success and unsupported counts', () => {
  const result = fullResult();
  result.checks.filter(check => check.mode === 'PING').forEach(check => { check.ok = false; check.status = 'UNSUP'; });
  result.pingUnsupported = 17;
  const h = harness(baseState({job: {results: [result]}}));
  const metrics = h.ui.resultMetrics(result);
  assert.equal(metrics.unsupported, 0);
  assert.equal(metrics.pingUnsupported, 17);
  assert.equal(metrics.success, true);
  assert.equal(metrics.pingPassed, 0);
  assert.match(h.ui.resultRows([result]), /Есть UNSUP/);
  h.ui.renderResults();
  assert.equal(h.element('standard-http-total').textContent, '36 / 36');
  assert.equal(h.element('standard-ping-total').textContent, '0 / 17');
  assert.equal(h.element('standard-unsupported-total').textContent, '0 / 17');
});

test('per-address details keep all modes, repeats, HTTP codes and escaped errors', () => {
  const {ui} = harness(), result = fullResult(2);
  result.checks[0].httpStatus = 404;
  result.checks[1].target = '<img src=x onerror=alert(1)>';
  result.checks[1].error = '<script>bad()</script>'; result.checks[1].status = 'SSL';
  const detail = ui.resultDetails(result);
  for (const mode of ['HTTP', 'TLS1.2', 'TLS1.3', 'PING']) assert(detail.includes(`<th scope="col">${mode}</th>`));
  assert.match(detail, /HTTP 404/);
  assert.match(detail, /<th scope="row">2<\/th>/);
  assert.match(detail, /&lt;script&gt;bad\(\)&lt;\/script&gt;/);
  assert.doesNotMatch(detail, /<img|<script/);
  assert.match(detail, /<span class="check-missing">—<\/span>/, 'Ping-only endpoints have no HTTP tests');
});

test('aggregate counters exclude legacy results and never mix Ping with HTTP', () => {
  const h = harness(baseState({job: {results: [oldResult(), fullResult(), fullResult(2)]}}));
  h.ui.renderResults();
  assert.equal(h.element('standard-http-total').textContent, '108 / 108');
  assert.equal(h.element('standard-ping-total').textContent, '51 / 51');
  assert.equal(h.element('standard-unsupported-total').textContent, '0 / 0');
  h.set(baseState({job: {results: [oldResult()]}})); h.ui.renderResults();
  assert.equal(h.element('standard-result-totals').hidden, true);
});

test('Standard All posts exactly the 22 upstream BAT ids including EXP, at one repeat', async () => {
  const strategies = [...Array.from({length: 22}, (_, index) => ({id: `stock-${index}`, name: `Stock ${index}`,
    family: 'Flowseal', experimental: index === 21})), ...Array.from({length: 6}, (_, index) => ({
    id: `experiment-${index}`, name: `Additional ${index}`, family: 'Extra', experimental: true}))];
  const h = harness(baseState({strategies}));
  h.set(baseState({strategies}), {candidates: ['experiment-0']});
  h.element('repeats').value = '3'; h.ui.buttonStates();
  assert.equal(h.element('standard-all-button').disabled, false);
  await h.click('standard-all-button');
  const request = h.requests.find(item => item.url === '/api/test');
  assert.deepEqual(request.body, {strategyIds: strategies.slice(0, 22).map(item => item.id), repeats: 1});
  assert.equal(h.element('repeats').value, '1');
  assert.equal(h.ui.candidateIds().length, 22);
  assert(h.ui.candidateIds().includes('stock-21'));
  assert(!h.ui.candidateIds().some(id => id.startsWith('experiment-')));
});

test('manual choice preserves additional strategies and selected repeats', async () => {
  const h = harness();
  h.set(baseState(), {candidates: ['stock-general', 'experiment-extra']});
  h.element('repeats').value = '3'; h.ui.buttonStates();
  await h.click('test-button');
  const request = h.requests.find(item => item.url === '/api/test');
  assert.deepEqual(request.body, {strategyIds: ['stock-general', 'experiment-extra'], repeats: 3});
});

test('suite errors disable test, baseline and auto controls, but not session start', () => {
  for (const testSuite of [{...suite, error: 'targets.txt is invalid'}, undefined]) {
    const h = harness(baseState({testSuite})); h.ui.buttonStates(); h.ui.renderTestSuite(); h.ui.renderAutomatic();
    for (const id of ['test-button', 'standard-all-button', 'auto-start-button']) assert.equal(h.element(id).disabled, true);
    assert.equal(h.baseline.disabled, true);
    assert.equal(h.element('start-button').disabled, false);
    assert.equal(h.element('standard-suite-error').hidden, false);
    assert(h.element('standard-suite-error').textContent);
    assert.equal(h.element('auto-title').textContent, 'Набор Standard недоступен');
  }
});

test('Standard All remains disabled for service, admin, operation and offline restrictions', async () => {
  const states = [{admin: false}, {service: {supported: true, installed: true, owned: true, state: 'stopped'}},
    {job: {running: true}}, {serviceBusy: true}, {externalProcessIds: [123]}, {autoSetup: {status: 'testing'}}];
  for (const changes of states) {
    const h = harness(baseState(changes)); h.ui.buttonStates();
    assert.equal(h.element('standard-all-button').disabled, true);
    await h.click('standard-all-button'); assert.equal(h.requests.length, 0);
  }
  for (const options of [{busy: true}, {online: false}]) {
    const h = harness(); h.set(baseState(), options); h.ui.buttonStates();
    assert.equal(h.element('standard-all-button').disabled, true);
  }
});

test('current strategy checks do not replace the overall run counter', () => {
  const h = harness(baseState({job: {running: true, current: 1, total: 23, currentCheck: 27, checksTotal: 53}}));
  h.ui.renderJob();
  assert.equal(h.element('job-progress').max, 23);
  assert.equal(h.element('job-progress').value, 1);
  assert.equal(h.element('job-counter').textContent, 'Прогоны: 1 из 23');
  assert.match(h.element('job-check-counter').textContent, /27 из 53/);
  h.set(baseState({job: {current: 0, total: 0}})); h.ui.renderJob();
  assert.equal(h.element('job-check-counter').hidden, true);
});

test('reachable baseline never tells the user that bypass is unnecessary', () => {
  for (const autoSetup of [{status: 'baseline_reachable', recommendation: {bypassNotNeeded: false}},
    {status: 'complete', recommendation: {status: 'baseline_reachable', bypassNotNeeded: false}},
    {status: 'complete', recommendation: {bypassNotNeeded: true, reason: 'Обход не требуется'}}]) {
    const h = harness(baseState({autoSetup, job: {results: [fullResult()]}})); h.ui.renderAutomatic();
    assert.match(h.element('auto-title').textContent, /Standard отвечают без обхода/);
    assert.doesNotMatch(h.element('auto-reason').textContent + h.element('auto-recommendation-name').textContent
      + h.element('auto-recommendation-reason').textContent, /обход не требуется/i);
    assert.equal(h.element('auto-status').className, 'pill neutral');
    assert.equal(h.element('auto-recommendation').attributes['class:baseline-reachable'], true);
  }
});

test('legacy recommendations are neutral until a full Standard validates them', () => {
  const h = harness(baseState({autoSetup: {status: 'complete', recommendation: {strategyId: 'stock-general'}},
    job: {results: [oldResult()]}})); h.ui.renderAutomatic();
  assert.equal(h.element('auto-status').className, 'pill neutral');
  assert.match(h.element('auto-recommendation-reason').textContent, /не подтверждён полным Standard/);
});
