import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { InvitationButton } from './InvitationControls.jsx';

const css = readFileSync(new URL('./Invitations.css', import.meta.url), 'utf8');
test('feedback resting labels use the stylesheet visible state, so copy buttons remain named and visible', () => {
  const markup = renderToStaticMarkup(createElement(InvitationButton, { label: 'Copy link', doneLabel: 'Copied' }));
  assert.match(markup, /class="iv-on">Copy link<\/span>/);
  assert.match(css, /\.iv-fb-label>span\.iv-on\{[^}]*visibility:visible/);
  assert.match(css, /\.iv-input\.iv-wide\{/); assert.match(css, /\.iv-settings-picker-trigger\.iv-block\{/);
  assert.doesNotMatch(css, /\.iv-fb-label>span\.on\{/);
});
test('compact Revoke reserves only the resting label and provides an accessible spinner-only busy name', () => {
  const markup = renderToStaticMarkup(createElement(InvitationButton, { label: 'Revoke', phase: 'busy', busyLabel: 'Revoking…', doneLabel: 'Revoked', failLabel: 'Try again', iconOnly: true, className: 'iv-revoke-confirm' }));
  assert.match(markup, /aria-label="Revoking…"/); assert.match(markup, /aria-busy="true"/);
  assert.doesNotMatch(markup, />Revoking…<\/span>/); assert.match(css, /\.iv-revoke-confirm>\.iv-fb-slot\{position:absolute;left:50%/);
});
