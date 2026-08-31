/**
 * analyzer.js
 *
 * Talks to /api/analyze, which calls the SAME core Python analyzer
 * used by the CLI (src/password_checker/checker.py). No scoring
 * logic is duplicated here -- this file only renders whatever the
 * server computes.
 *
 * The password is sent only to this local Flask server (never a
 * third party) and only while you are actively typing; nothing is
 * cached, stored, or written to disk on either side.
 */

(() => {
  const pwInput = document.getElementById('pw');
  const toggleBtn = document.getElementById('toggle-visibility');
  const charCount = document.getElementById('char-count');

  const readoutEmpty = document.getElementById('readout-empty');
  const readoutContent = document.getElementById('readout-content');

  const meter = document.getElementById('meter');
  const strengthTag = document.getElementById('strength-tag');
  const scoreValue = document.getElementById('score-value');
  const gridChecks = document.getElementById('grid-checks');
  const entropyValue = document.getElementById('entropy-value');
  const crackValue = document.getElementById('crack-value');

  const issuesBlock = document.getElementById('issues-block');
  const issuesList = document.getElementById('issues-list');
  const recsBlock = document.getElementById('recs-block');
  const recsList = document.getElementById('recs-list');

  const STRENGTH_COLORS = {
    'WEAK': 'var(--danger)',
    'MEDIUM': 'var(--warn)',
    'STRONG': 'var(--safe)',
    'VERY STRONG': 'var(--safe)',
  };

  const STRENGTH_BARS = {
    'WEAK': 2,
    'MEDIUM': 5,
    'STRONG': 8,
    'VERY STRONG': 10,
  };

  let debounceTimer = null;

  toggleBtn.addEventListener('click', () => {
    const showing = pwInput.type === 'text';
    pwInput.type = showing ? 'password' : 'text';
    toggleBtn.textContent = showing ? 'SHOW' : 'HIDE';
    toggleBtn.setAttribute('aria-pressed', String(!showing));
  });

  pwInput.addEventListener('input', () => {
    const value = pwInput.value;
    charCount.textContent = `${value.length} character${value.length === 1 ? '' : 's'}`;

    clearTimeout(debounceTimer);
    if (!value) {
      showEmptyState();
      return;
    }
    debounceTimer = setTimeout(() => analyze(value), 180);
  });

  function showEmptyState() {
    readoutEmpty.hidden = false;
    readoutContent.hidden = true;
  }

  async function analyze(password) {
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (!response.ok) return;
      const result = await response.json();
      render(result);
    } catch (err) {
      // Network/parse failure: fail quietly rather than showing a
      // scary error over a password field.
      console.error('Analysis request failed', err);
    }
  }

  function render(result) {
    readoutEmpty.hidden = true;
    readoutContent.hidden = false;

    const color = STRENGTH_COLORS[result.strength] || 'var(--muted)';
    strengthTag.textContent = result.strength;
    strengthTag.style.color = color;
    scoreValue.textContent = `${result.score} / ${result.max_score}`;

    renderMeter(STRENGTH_BARS[result.strength] || 0, color);

    gridChecks.innerHTML = '';
    addCheck('Length \u2265 8', result.length >= 8);
    addCheck('Uppercase', result.has_uppercase);
    addCheck('Lowercase', result.has_lowercase);
    addCheck('Digit', result.has_digit);
    addCheck('Symbol', result.has_symbol);
    addCheck('Not a common password', !result.common_password);
    addCheck('No obvious pattern', result.detected_patterns.length === 0);

    entropyValue.textContent = `${result.entropy_estimate_bits} bits (theoretical)`;
    crackValue.textContent = result.estimated_crack_time;

    renderList(issuesBlock, issuesList, result.issues);
    renderList(recsBlock, recsList, result.recommendations);
  }

  function renderMeter(activeBars, color) {
    const bars = meter.querySelectorAll('span');
    bars.forEach((bar, i) => {
      const active = i < activeBars;
      bar.style.height = active ? `${10 + i * 3}px` : '6px';
      bar.style.background = active ? color : 'var(--border)';
    });
  }

  function addCheck(label, ok) {
    const item = document.createElement('div');
    item.className = 'check-item';
    item.innerHTML = `
      <span class="check-name">${label}</span>
      <span class="check-mark ${ok ? 'ok' : 'fail'}">${ok ? '\u2713' : '\u2717'}</span>
    `;
    gridChecks.appendChild(item);
  }

  function renderList(blockEl, listEl, items) {
    listEl.innerHTML = '';
    if (!items || items.length === 0) {
      blockEl.hidden = true;
      return;
    }
    blockEl.hidden = false;
    items.forEach((text) => {
      const li = document.createElement('li');
      li.textContent = text;
      listEl.appendChild(li);
    });
  }
})();
