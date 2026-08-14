// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Browser demonstration of the Sealway verifier.
//
// Everything of consequence happens inside the WebAssembly module: this file
// loads it, hands it the proof and the trust material, and renders the report it
// returns. It takes no verification decision of its own, which is the same rule
// the command line interface follows.

const el = (id) => document.getElementById(id);

const panels = {
  loading: el('loading'),
  input: el('input'),
  running: el('running'),
  error: el('error'),
  result: el('result'),
};

function show(...names) {
  for (const [name, node] of Object.entries(panels)) {
    node.hidden = !names.includes(name);
  }
}

// Trust material for the qualified eIDAS determination.
//
// The official European endpoints send no cross-origin headers, so a browser
// cannot read them directly. The documents are served from this page's own
// origin instead, unchanged and still signed: the module verifies the European
// signatures itself, so serving them here carries the bytes without making this
// server something anyone has to trust.
async function loadTrustMaterial() {
  const read = async (path) => {
    const response = await fetch(path);
    if (!response.ok) {
      throw new Error(`${path}: HTTP ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  };

  try {
    const [lotl, es] = await Promise.all([
      read('trust/lotl.xml'),
      read('trust/lists/es.xml'),
    ]);

    el('trust-state').innerHTML =
      '<span class="ok">✓</span> European Trusted Lists loaded — qualified eIDAS ' +
      'status will be established.';

    return { lotl, lists: { ES: es } };
  } catch (err) {
    el('trust-state').innerHTML =
      '<span class="warn">!</span> No Trusted List material was found next to this ' +
      `page (${err.message}). Everything else is still verified; the qualified ` +
      'eIDAS status will be reported as indeterminate rather than assumed.';

    return null;
  }
}

let trustMaterial = null;

async function boot() {
  const go = new Go();

  try {
    const result = await WebAssembly.instantiateStreaming(
      fetch('sealway.wasm'),
      go.importObject,
    );

    go.run(result.instance);
  } catch (err) {
    el('loading-status').textContent = `The verifier could not be loaded: ${err.message}`;
    return;
  }

  trustMaterial = await loadTrustMaterial();

  show('input');
}

async function verify(file) {
  show('running');

  try {
    const bytes = new Uint8Array(await file.arrayBuffer());

    const json = await globalThis.sealwayVerifier.verify(bytes, {
      verifyAnchors: el('anchors').checked,
      timeoutSeconds: 20,
      trust: trustMaterial,
    });

    render(JSON.parse(json));
    show('result');
  } catch (err) {
    el('error-message').textContent = err.message ?? String(err);
    show('error');
  }
}

const RESULT_LABELS = {
  complete_valid: 'Complete — everything was verified',
  partial_valid: 'Partial — nothing failed, something was not established',
  invalid: 'Invalid — the proof does not hold',
};

function render(report) {
  const verdict = el('verdict');
  verdict.className = `verdict r-${report.result}`;
  el('verdict-label').textContent = RESULT_LABELS[report.result] ?? report.result;

  const certificate = report.certificate ?? {};
  el('verdict-id').textContent = [certificate.public_id, certificate.title]
    .filter(Boolean)
    .join(' · ');

  el('explanation').textContent = report.summary?.explanation ?? '';

  const container = el('sections');
  container.replaceChildren();

  for (const section of report.sections ?? []) {
    container.append(renderSection(section));
  }

  el('raw').textContent = JSON.stringify(report, null, 2);
}

function renderSection(section) {
  const node = document.createElement('section');
  node.className = 'stage';

  const heading = document.createElement('h2');
  heading.textContent = section.title;
  node.append(heading);

  for (const check of section.checks ?? []) {
    node.append(renderCheck(check));
  }

  return node;
}

function renderCheck(check) {
  const row = document.createElement('div');
  row.className = `check s-${check.status}`;

  const status = document.createElement('span');
  status.className = 'badge';
  status.textContent = check.status;
  row.append(status);

  const body = document.createElement('div');
  body.className = 'check-body';

  const title = document.createElement('p');
  title.className = 'check-title';
  title.textContent = check.title;
  body.append(title);

  // A step that did not simply succeed always says why, and shows the values a
  // reader would need to redo the comparison.
  if (check.status !== 'valid') {
    const message = document.createElement('p');
    message.className = 'check-message';
    message.textContent = check.message;
    body.append(message);

    const details = Object.entries(check.details ?? {});
    if (details.length > 0) {
      body.append(renderDetails(details));
    }
  } else if (check.details) {
    const notable = Object.entries(check.details).filter(([key]) =>
      ['service_status', 'service_type', 'trust_list', 'provider', 'match'].includes(key),
    );

    if (notable.length > 0) {
      body.append(renderDetails(notable));
    }
  }

  row.append(body);

  return row;
}

function renderDetails(entries) {
  const list = document.createElement('dl');
  list.className = 'details';

  for (const [key, value] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    const term = document.createElement('dt');
    term.textContent = key;

    const definition = document.createElement('dd');
    definition.textContent = value;

    list.append(term, definition);
  }

  return list;
}

el('file').addEventListener('change', (event) => {
  const [file] = event.target.files;
  if (file) {
    verify(file);
  }
});

const drop = el('drop');

for (const name of ['dragenter', 'dragover', 'dragleave', 'drop']) {
  drop.addEventListener(name, (event) => {
    event.preventDefault();
    drop.classList.toggle('over', name === 'dragenter' || name === 'dragover');
  });
}

drop.addEventListener('drop', (event) => {
  const [file] = event.dataTransfer.files;
  if (file) {
    verify(file);
  }
});

el('again').addEventListener('click', () => {
  el('file').value = '';
  show('input');
});

boot();
