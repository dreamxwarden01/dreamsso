import React from 'react';
const paths = {
  check: <><circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.4 2.4 4.6-5"/></>,
  tick: <path d="m5 12.5 4.2 4.2L19 7"/>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 1.8"/></>,
  alert: <><circle cx="12" cy="12" r="9"/><path d="M12 8v4.5M12 16h.01"/></>,
  ban: <><circle cx="12" cy="12" r="9"/><path d="m6.5 6.5 11 11"/></>,
  plus: <path d="M12 5v14M5 12h14"/>,
  copy: <><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/></>,
  link: <><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></>,
  mail: <><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m4 7 8 6 8-6"/></>,
  lock: <><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></>,
  chev: <path d="m6 9 6 6 6-6"/>,
};
export default function InvitationIcon({ name, className = '' }) {
  return <span className={'iv-ico ' + className} aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" focusable="false">{paths[name]}</svg></span>;
}
