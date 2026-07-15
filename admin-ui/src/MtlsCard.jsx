import { useEffect, useState } from 'react';
import { getMtls, mtlsCsr, mtlsInstall, mtlsEnforce, mtlsReset } from './api.js';

// Service-to-service mTLS — the SSO twin of videosite's card. The edge
// (Cloudflare) enforces mTLS and lets S2S calls skip bot management; the cert
// is issued by Cloudflare from a CSR generated server-side (the key never
// leaves) and is stripped at the edge, so there is no verification side here.
// Enforce = present the certificate on all outbound service calls (event
// delivery); it applies immediately on flip.

// Server sends ISO UTC; render in the viewer's zone like "Sep 7, 2026 at
// 1:41:47 AM PDT" — Intl falls back to GMT+N where the zone has no short name.
const fmtTs = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'long' }) : '—');

// Same validation vocabulary as videosite's card (mtls service reasons).
const CERT_ERR = {
  expired: 'This certificate is already expired. Submit a current certificate.',
  key_mismatch: "Certificate doesn't match the generated key. Submit the CSR shown above.",
  parse_failed: "That doesn't look like a valid PEM certificate.",
  no_key: 'No key on file — generate a CSR first.',
  no_cert: 'Paste the issued certificate.',
};

function Modal({ title, children, onClose, wide }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      {/* wide = PEM-bearing modals; confirms keep the SPA's standard 420px */}
      <div className="modal" role="dialog" aria-modal="true" style={wide ? { maxWidth: 560 } : undefined} onClick={(e) => e.stopPropagation()}>
        <h3 className="modal-title">{title}</h3>
        {children}
      </div>
    </div>
  );
}

function InfoCell({ label, value, style }) {
  return (
    <div>
      <p className="k" style={{ margin: 0 }}>{label}</p>
      <p className="row-title mono" style={{ margin: '2px 0 0', fontSize: 13, overflowWrap: 'anywhere', ...style }}>{value}</p>
    </div>
  );
}

export default function MtlsCard() {
  const [mtls, setMtls] = useState(null); // GET /admin/api/mtls snapshot
  const [loadErr, setLoadErr] = useState(false);
  const [actErr, setActErr] = useState(null); // card-level operation error

  const [modal, setModal] = useState(null); // 'setup' | 'renew' | 'reset'
  const [cn, setCn] = useState('');
  const [csr, setCsr] = useState(null);
  const [genBusy, setGenBusy] = useState(false);
  const [certPaste, setCertPaste] = useState('');
  const [installing, setInstalling] = useState(false);
  const [installErr, setInstallErr] = useState(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false); // toggle / reset

  const load = () =>
    getMtls()
      .then((d) => {
        setMtls(d);
        setLoadErr(false);
      })
      .catch((e) => {
        if (e.message !== 'unauthenticated') setLoadErr(true);
      });
  useEffect(() => {
    load();
  }, []);

  const configured = mtls?.state === 'configured';
  const expired = configured && mtls.expired;
  // Not configured = amber (a grey pill vanishes on the grey page background);
  // Expired = red, the loud one.
  const pill = !mtls
    ? null
    : !configured
      ? { c: 'pill-warn', t: 'Not configured' }
      : expired
        ? { c: 'pill-bad', t: 'Expired' }
        : mtls.enforce
          ? { c: 'pill-ok', t: 'Enabled' }
          : { c: 'pill-warn', t: 'Disabled' };

  const openModal = (m) => {
    setCn('');
    setCsr(null);
    setGenBusy(false);
    setCertPaste('');
    setInstalling(false);
    setInstallErr(null);
    setCopied(false);
    setActErr(null);
    setModal(m);
  };
  const closeModal = () => (genBusy || installing || busy ? null : setModal(null));

  const generateCsr = async () => {
    setGenBusy(true);
    try {
      const d = await mtlsCsr(cn.trim() || undefined);
      setCn(d.cn);
      setCsr(d.csr);
    } catch (e) {
      if (e.message !== 'unauthenticated') setInstallErr(`Couldn't generate the CSR. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setGenBusy(false);
    }
  };

  const copyCsr = async () => {
    try {
      await navigator.clipboard.writeText(csr);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked — the text stays selectable */ }
  };

  const installCert = async () => {
    setInstalling(true);
    setInstallErr(null);
    try {
      await mtlsInstall(certPaste);
      setModal(null);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.status === 422) setInstallErr(CERT_ERR[e.data?.error] || 'Certificate rejected.');
      else setInstallErr(`Couldn't install the certificate. [${e.data?.error || 'http_' + e.status}]`);
    } finally {
      setInstalling(false);
    }
  };

  // Applies immediately on flip — optimistic knob; a failed save reloads (snaps back).
  const toggleEnforce = async (enabled) => {
    setBusy(true);
    setActErr(null);
    setMtls((cur) => ({ ...cur, enforce: enabled }));
    try {
      await mtlsEnforce(enabled);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      setActErr(
        e.status === 422 && e.data?.error === 'expired'
          ? 'Renew the certificate before enabling.'
          : `Couldn't save. [${e.data?.error || 'http_' + e.status}]`,
      );
      await load();
    } finally {
      setBusy(false);
    }
  };

  const resetCert = async () => {
    setBusy(true);
    try {
      await mtlsReset();
      setModal(null);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      setActErr(`Couldn't reset. [${e.data?.error || 'http_' + e.status}]`);
      setModal(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <p className="section" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        Service mTLS
        {pill && <span className={'pill ' + pill.c} style={{ textTransform: 'none' }}>{pill.t}</span>}
      </p>
      <div className="card pad">
        <div className="form">
          <p className="k" style={{ margin: 0, fontSize: 13 }}>
            A client certificate authenticates DreamSSO&rsquo;s server-to-server calls at the Cloudflare edge —
            event delivery to apps, and anything added later. Cloudflare issues the certificate from a CSR generated
            here; the private key never leaves this server.
          </p>

          {loadErr && <p className="err">Couldn&rsquo;t load the mTLS status.</p>}
          {actErr && <p className="err">{actErr}</p>}

          {!mtls && !loadErr && <div className="skel" style={{ height: 34, width: 220, borderRadius: 8 }} />}

          {mtls && !configured && (
            <div>
              <button className="btn btn-primary" onClick={() => openModal('setup')} disabled={busy}>
                Set up mTLS…
              </button>
            </div>
          )}

          {configured && (
            <>
              <div className="grid2">
                <InfoCell label="Common name" value={mtls.cn || '—'} />
                <InfoCell label="Issuer" value={mtls.issuer || '—'} />
                <InfoCell label="Not valid before" value={fmtTs(mtls.not_before)} />
                <InfoCell label="Not valid after" value={fmtTs(mtls.not_after)} style={expired ? { color: 'var(--danger)' } : undefined} />
              </div>
              {expired && (
                <p className="err" style={{ margin: 0 }}>
                  This certificate has expired. Renew it (the private key is kept) to re-enable mTLS.
                </p>
              )}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <p style={{ margin: 0, fontWeight: 500 }}>Enable mTLS</p>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={!!mtls.enforce}
                      disabled={expired || busy}
                      onChange={(e) => toggleEnforce(e.target.checked)}
                    />
                    <span className="slider" />
                  </label>
                </div>
                <p className="k" style={{ margin: '4px 0 0' }}>
                  Present the client certificate on all outbound service calls. Applies immediately.
                </p>
              </div>
              <div className="form-actions">
                <button className="btn btn-primary" onClick={() => openModal('renew')} disabled={busy}>
                  Renew certificate…
                </button>
                <button className="btn btn-danger" onClick={() => openModal('reset')} disabled={busy}>
                  Reset…
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {(modal === 'setup' || modal === 'renew') && (
        <Modal
          wide
          title={modal === 'setup' ? 'Set up mTLS certificate' : 'Renew mTLS certificate'}
          onClose={closeModal}
        >
          {modal === 'setup' && !csr && (
            <>
              <p className="modal-msg">
                Generates a private key and a certificate signing request. Submit the CSR to Cloudflare (SSL/TLS &rarr;
                Client certificates), then paste the issued certificate back here.
              </p>
              <div className="field" style={{ textAlign: 'left' }}>
                <span>
                  Common name <span className="note">(optional — auto-generated when blank)</span>
                </span>
                <input
                  className="input mono"
                  value={cn}
                  placeholder="dreamsso-…"
                  onChange={(e) => setCn(e.target.value)}
                  disabled={genBusy}
                />
              </div>
              {installErr && <p className="err">{installErr}</p>}
              <div className="modal-actions">
                <button className="btn btn-primary" onClick={generateCsr} disabled={genBusy}>
                  {genBusy ? 'Generating…' : 'Generate key & CSR'}
                </button>
                <button className="btn" onClick={closeModal} disabled={genBusy}>
                  Cancel
                </button>
              </div>
            </>
          )}
          {(modal === 'renew' || csr) && (
            <>
              {csr && (
                <div className="field" style={{ textAlign: 'left' }}>
                  <span>
                    Submit this CSR to Cloudflare <span className="note">(CN {cn})</span>
                  </span>
                  <textarea className="input mono" readOnly rows={5} value={csr} style={{ fontSize: 11, minHeight: 104 }} />
                  <button className="btn" style={{ marginTop: 8, alignSelf: 'flex-start' }} onClick={copyCsr}>
                    {copied ? '✓ Copied' : 'Copy CSR'}
                  </button>
                </div>
              )}
              {modal === 'renew' && (
                <p className="modal-msg">
                  The existing private key is kept — request the renewed certificate from Cloudflare for the same key,
                  then paste it here.
                </p>
              )}
              <div className="field" style={{ textAlign: 'left' }}>
                <span>
                  Paste the {modal === 'renew' ? 'renewed' : 'issued'} certificate{' '}
                  <span className="note">(PEM — a full chain with intermediates is fine, any order)</span>
                </span>
                <textarea
                  className={'input mono' + (installErr ? ' bad' : '')}
                  rows={5}
                  style={{ fontSize: 11, minHeight: 104 }}
                  value={certPaste}
                  placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
                  onChange={(e) => {
                    setCertPaste(e.target.value);
                    setInstallErr(null);
                  }}
                  disabled={installing}
                />
                {installErr && <span className="ferr">{installErr}</span>}
              </div>
              <div className="modal-actions">
                <button
                  className="btn btn-primary"
                  onClick={installCert}
                  disabled={installing || !certPaste.trim() || (modal === 'setup' && !csr)}
                >
                  {installing ? 'Validating…' : 'Save certificate'}
                </button>
                <button className="btn" onClick={closeModal} disabled={installing}>
                  Cancel
                </button>
              </div>
            </>
          )}
        </Modal>
      )}

      {modal === 'reset' && (
        <Modal title="Reset mTLS?" onClose={closeModal}>
          <p className="modal-msg">
            This permanently deletes the certificate, private key, and CSR, and turns enforcement off. You&rsquo;ll
            need to set it up again from scratch.
          </p>
          <div className="modal-actions">
            <button className="btn btn-danger" onClick={resetCert} disabled={busy}>
              {busy ? 'Resetting…' : 'Reset mTLS'}
            </button>
            <button className="btn" onClick={closeModal} disabled={busy}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
