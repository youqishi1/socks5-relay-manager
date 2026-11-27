'use strict';

const search = document.querySelector('#search');
const copyList = document.querySelector('#copy-list');
const detectMissing = document.querySelector('#detect-missing');
const detectStatus = document.querySelector('#detect-status');
const relayTable = document.querySelector('#relay-rows');
const relayRows = Array.from(document.querySelectorAll('#relay-rows tr'));
const detectButtons = Array.from(document.querySelectorAll('[data-detect]'));
let detecting = false;

function missingRows() {
  return relayRows.filter((row) => !row.hidden && row.dataset.exitReady !== 'yes' && row.querySelector('[data-detect]'));
}

function updateDetectControls() {
  detectButtons.forEach((button) => { button.disabled = detecting; });
  if (detectMissing) detectMissing.disabled = detecting || missingRows().length === 0;
}

if (search) {
  const empty = document.querySelector('#filter-empty');
  search.addEventListener('input', () => {
    const query = search.value.trim().toLowerCase();
    relayRows.forEach((row) => {
      row.hidden = !row.textContent.toLowerCase().includes(query);
    });
    empty.hidden = relayRows.some((row) => !row.hidden);
    if (copyList) {
      copyList.disabled = !relayRows.some((row) => !row.hidden && row.querySelector('[data-share]'));
    }
    updateDetectControls();
  });
}

function reportDetection(message) {
  detectStatus.textContent = message;
  detectStatus.hidden = false;
}

async function checkExit(row) {
  const button = row.querySelector('[data-detect]');
  button.textContent = '检测中';
  try {
    const response = await fetch(button.dataset.detect, {
      method: 'POST',
      headers: {Accept: 'application/json'},
      body: new URLSearchParams({csrf: relayTable.dataset.csrf})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || '出口检测未完成。');
    row.querySelector('[data-exit-result]').textContent = result.text;
    row.dataset.exitReady = result.ok ? 'yes' : 'no';
    row.querySelectorAll('[data-share-kind]').forEach((copy) => {
      const value = result.links[copy.dataset.shareKind];
      if (value) copy.dataset.share = value;
    });
    return result.ok;
  } finally {
    button.textContent = '检测';
  }
}

async function runDetection(rows) {
  if (detecting || !rows.length) return;
  detecting = true;
  updateDetectControls();
  let success = 0;
  let failed = 0;
  try {
    for (const [index, row] of rows.entries()) {
      reportDetection('正在检测出口 ' + (index + 1) + ' / ' + rows.length + '。');
      if (await checkExit(row)) success++;
      else failed++;
    }
    reportDetection('检测完成，成功 ' + success + ' 条，失败 ' + failed + ' 条。');
  } catch (error) {
    reportDetection(error.message || '检测未完成，请稍后重试。');
  } finally {
    detecting = false;
    updateDetectControls();
  }
}

if (detectMissing) detectMissing.addEventListener('click', () => runDetection(missingRows()));
detectButtons.forEach((button) => {
  button.addEventListener('click', () => runDetection([button.closest('tr')]));
});
updateDetectControls();

async function copyShare(value) {
  const status = document.querySelector('#copy-status');
  const fallback = document.querySelector('#copy-fallback');
  try {
    await navigator.clipboard.writeText(value);
    fallback.value = '';
    fallback.hidden = true;
    status.textContent = '链接已复制，可在客户端从剪贴板导入。';
  } catch {
    fallback.value = value;
    fallback.hidden = false;
    fallback.focus();
    fallback.select();
    status.textContent = '已选中链接，请复制。';
  }
  status.hidden = false;
}

document.querySelectorAll('[data-share]').forEach((button) => {
  button.addEventListener('click', () => copyShare(button.dataset.share));
});

if (copyList) {
  copyList.addEventListener('click', () => {
    const links = relayRows.filter((row) => !row.hidden).flatMap((row) =>
      Array.from(row.querySelectorAll('[data-share]'), (button) => button.dataset.share));
    if (links.length) copyShare(links.join('\n'));
  });
}

document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const input = document.getElementById(button.dataset.copy);
    input.select();
    try {
      await navigator.clipboard.writeText(input.value);
      button.textContent = '已复制';
    } catch {
      button.textContent = '已选中，请复制';
    }
  });
});

document.querySelectorAll('form[data-save]').forEach((form) => {
  form.addEventListener('submit', () => {
    const submit = form.querySelector('button[type=submit]');
    submit.disabled = true;
    submit.textContent = form.dataset.save;
  });
});
