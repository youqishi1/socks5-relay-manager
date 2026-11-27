'use strict';

const search = document.querySelector('#search');
if (search) {
  const rows = Array.from(document.querySelectorAll('#relay-rows tr'));
  const empty = document.querySelector('#filter-empty');
  search.addEventListener('input', () => {
    const query = search.value.trim().toLowerCase();
    rows.forEach((row) => {
      row.hidden = !row.textContent.toLowerCase().includes(query);
    });
    empty.hidden = rows.some((row) => !row.hidden);
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
    submit.textContent = '处理中…';
  });
});
