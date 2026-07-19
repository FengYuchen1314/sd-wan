export async function copyText(text, environment = globalThis) {
  const value = String(text ?? '');
  const navigatorObject = environment.navigator;
  if (environment.isSecureContext && typeof navigatorObject?.clipboard?.writeText === 'function') {
    try {
      await navigatorObject.clipboard.writeText(value);
      return { method: 'clipboard' };
    } catch {
      // Permission can still be denied in a secure context; continue with the
      // synchronous user-gesture fallback below.
    }
  }

  const documentObject = environment.document;
  if (!documentObject?.body || typeof documentObject.execCommand !== 'function') {
    throw new Error('浏览器阻止了自动复制，请选中命令后手动复制');
  }
  const textarea = documentObject.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', '');
  textarea.setAttribute('aria-hidden', 'true');
  Object.assign(textarea.style, {
    position: 'fixed',
    top: '0',
    left: '-9999px',
    width: '1px',
    height: '1px',
    opacity: '0',
    pointerEvents: 'none',
  });
  const previousFocus = documentObject.activeElement;
  documentObject.body.append(textarea);
  let copied = false;
  try {
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange?.(0, value.length);
    copied = documentObject.execCommand('copy');
  } finally {
    textarea.remove();
    previousFocus?.focus?.();
  }
  if (!copied) throw new Error('浏览器阻止了自动复制，请选中命令后手动复制');
  return { method: 'compatibility' };
}
