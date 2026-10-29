document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.querySelector('[data-menu-toggle]');
  const nav = document.querySelector('[data-nav]');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const expanded = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!expanded));
      toggle.setAttribute('aria-label', expanded ? 'Open navigation' : 'Close navigation');
      nav.classList.toggle('is-open', !expanded);
    });
    nav.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        nav.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', 'Open navigation');
        nav.querySelectorAll('details[open]').forEach((menu) => {
          menu.open = false;
        });
      });
    });
  }

  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  document.querySelectorAll('.flash-close').forEach((button) => {
    button.addEventListener('click', () => button.closest('.flash')?.remove());
  });

  const helpSearch = document.querySelector('[data-help-search]');
  if (helpSearch) {
    const articles = [...document.querySelectorAll('[data-help-item]')];
    const resultCount = document.querySelector('[data-help-count]');
    const noResults = document.querySelector('[data-help-empty]');
    helpSearch.addEventListener('input', () => {
      const query = helpSearch.value.trim().toLocaleLowerCase();
      let visibleCount = 0;
      articles.forEach((article) => {
        const matches = article.textContent.toLocaleLowerCase().includes(query);
        article.hidden = !matches;
        if (matches) visibleCount += 1;
      });
      if (resultCount) {
        resultCount.textContent = query
          ? `Showing ${visibleCount} matching help article${visibleCount === 1 ? '' : 's'}.`
          : 'Showing all help articles.';
      }
      if (noResults) noResults.hidden = visibleCount !== 0;
    });
  }

  document.querySelectorAll('form[data-auth-form][data-clear-on-load="true"]').forEach((form) => {
    const clearCredentials = () => {
      form.querySelectorAll('input[type="password"]').forEach((input) => {
        input.value = '';
      });
    };

    clearCredentials();
    window.addEventListener('pageshow', (event) => {
      if (event.persisted) clearCredentials();
    });
  });

  document.querySelectorAll('[data-password-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.getAttribute('aria-controls'));
      if (!(input instanceof HTMLInputElement)) return;
      const showPassword = input.type === 'password';
      input.type = showPassword ? 'text' : 'password';
      button.setAttribute('aria-label', showPassword ? 'Hide password' : 'Show password');
      button.setAttribute('aria-pressed', String(showPassword));
      const visibleIcon = button.querySelector('[data-eye-visible]');
      const hiddenIcon = button.querySelector('[data-eye-hidden]');
      if (visibleIcon) visibleIcon.hidden = showPassword;
      if (hiddenIcon) hiddenIcon.hidden = !showPassword;
    });
  });

  document.querySelectorAll('[data-image-upload]').forEach((input) => {
    const formField = input.closest('.upload-control');
    const preview = formField?.querySelector('[data-image-preview]');
    const feedback = formField?.querySelector('[data-upload-feedback]');
    const clearButton = formField?.querySelector('[data-image-clear]');
    let previewUrl = null;

    const clearPreview = () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      previewUrl = null;
      if (preview) {
        preview.removeAttribute('src');
        preview.hidden = true;
      }
      if (clearButton) clearButton.hidden = true;
    };

    input.addEventListener('change', () => {
      clearPreview();
      const file = input.files?.[0];
      if (!file) {
        input.setCustomValidity('');
        if (feedback) feedback.textContent = '';
        return;
      }

      const message = file.size > 10 * 1024 * 1024
        ? 'Each image must be 10 MB or smaller.'
        : '';
      input.setCustomValidity(message);
      if (feedback) feedback.textContent = message || `${file.name} selected (${(file.size / 1024 / 1024).toFixed(2)} MB).`;
      if (message) return;

      if (preview && file.type.startsWith('image/')) {
        previewUrl = URL.createObjectURL(file);
        preview.src = previewUrl;
        preview.hidden = false;
      }
      if (clearButton) clearButton.hidden = false;
    });

    clearButton?.addEventListener('click', () => {
      input.value = '';
      input.setCustomValidity('');
      if (feedback) feedback.textContent = '';
      clearPreview();
      input.focus();
    });
  });
});
