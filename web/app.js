'use strict';

const search = document.querySelector('#search');
const copyList = document.querySelector('#copy-list');
const relayRows = Array.from(document.querySelectorAll('#relay-rows tr'));
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
  });
}

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
    status.textContent = '已选中链接，请按 Ctrl+C 复制。';
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
