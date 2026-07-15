// Clicking an input's padding/border can leave the caret at position 0 even
// when the box already has text (browsers map frame clicks inconsistently).
// After the browser applies its own click-caret, a 0,0 collapse on a filled
// box means the click missed the text — move the caret to the end. Tab-focus
// (select-all) and mid-text clicks are untouched. Document-level: covers
// every text-like input in the SPA.
export function installCaretFix() {
  document.addEventListener('focusin', (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    if (!/^(text|password|search|tel|url)$/.test(el.type)) return;
    requestAnimationFrame(() => {
      if (document.activeElement === el && el.value &&
          el.selectionStart === 0 && el.selectionEnd === 0) {
        try { el.setSelectionRange(el.value.length, el.value.length); } catch { /* unsupported type */ }
      }
    });
  });
}
