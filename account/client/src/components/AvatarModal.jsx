import { useCallback, useEffect, useRef, useState } from 'react';
import { uploadAvatar, deleteAvatar } from '../api.js';
import Icon from './Icon.jsx';
import Modal from './Modal.jsx';

// Profile picture upload + crop. Pick: square drop zone (drag lands anywhere
// on the page while the modal is open) or click to browse. Edit: pan + zoom a
// 1:1 crop, live round preview. The client uploads the finished square (webp
// via canvas — tiny); the server re-validates and re-encodes regardless, so
// this is UX, not the trust boundary.
const V = 280; // crop viewport px
const P = 56; // round preview px
const F = P / V;
const OK_TYPES = /^image\/(png|jpeg|webp)$/;

export default function AvatarModal({ hasPicture, onSaved, onClose }) {
  const [phase, setPhase] = useState('pick'); // pick | edit
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);

  // crop state
  const [src, setSrc] = useState(null);
  const nat = useRef({ w: 0, h: 0 });
  const view = useRef({ z: 1, ox: 0, oy: 0 });
  const fileRef = useRef(null);
  const imgRef = useRef(null);
  const prevRef = useRef(null);
  const vpRef = useRef(null);
  const zoomRef = useRef(null);
  const drag = useRef(null);

  const cover = () => V / Math.min(nat.current.w, nat.current.h);
  const scale = () => cover() * view.current.z;

  const clamp = () => {
    const v = view.current;
    const dw = nat.current.w * scale();
    const dh = nat.current.h * scale();
    v.ox = Math.min(0, Math.max(V - dw, v.ox));
    v.oy = Math.min(0, Math.max(V - dh, v.oy));
  };

  const render = () => {
    const s = scale();
    const v = view.current;
    if (imgRef.current) {
      imgRef.current.style.width = `${nat.current.w * s}px`;
      imgRef.current.style.transform = `translate(${v.ox}px, ${v.oy}px)`;
    }
    if (prevRef.current) {
      prevRef.current.style.width = `${nat.current.w * s * F}px`;
      prevRef.current.style.transform = `translate(${v.ox * F}px, ${v.oy * F}px)`;
    }
  };

  const setZoom = (nz) => {
    const v = view.current;
    nz = Math.min(4, Math.max(1, nz));
    const so = scale();
    const cx = (V / 2 - v.ox) / so;
    const cy = (V / 2 - v.oy) / so;
    v.z = nz;
    const sn = scale();
    v.ox = V / 2 - cx * sn;
    v.oy = V / 2 - cy * sn;
    clamp();
    render();
    if (zoomRef.current) zoomRef.current.value = Math.round(nz * 100);
  };

  const handleFile = useCallback((file) => {
    setErr(null);
    if (!OK_TYPES.test(file.type)) {
      setErr('Choose a PNG, JPEG or WebP image.');
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setErr('That file is over 8 MB. Choose a smaller image.');
      return;
    }
    const rd = new FileReader();
    rd.onload = () => {
      const im = new Image();
      im.onload = () => {
        nat.current = { w: im.naturalWidth, h: im.naturalHeight };
        view.current = { z: 1, ox: 0, oy: 0 };
        setSrc(rd.result);
        setPhase('edit');
      };
      im.onerror = () => setErr("Couldn't read that image — it may be corrupted.");
      im.src = rd.result;
    };
    rd.readAsDataURL(file);
  }, []);

  // Center the image once the edit view mounts.
  useEffect(() => {
    if (phase !== 'edit' || !src) return;
    const v = view.current;
    const s = scale();
    v.ox = (V - nat.current.w * s) / 2;
    v.oy = (V - nat.current.h * s) / 2;
    render();
    if (zoomRef.current) zoomRef.current.value = 100;
  }, [phase, src]); // eslint-disable-line react-hooks/exhaustive-deps

  // Full-page drop while the modal is open.
  useEffect(() => {
    let depth = 0;
    const over = (e) => {
      e.preventDefault();
    };
    const enter = (e) => {
      e.preventDefault();
      depth++;
      setDragging(true);
    };
    const leave = (e) => {
      e.preventDefault();
      depth--;
      if (depth <= 0) {
        depth = 0;
        setDragging(false);
      }
    };
    const drop = (e) => {
      e.preventDefault();
      depth = 0;
      setDragging(false);
      const f = e.dataTransfer?.files?.[0];
      if (f) handleFile(f);
    };
    window.addEventListener('dragover', over);
    window.addEventListener('dragenter', enter);
    window.addEventListener('dragleave', leave);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragover', over);
      window.removeEventListener('dragenter', enter);
      window.removeEventListener('dragleave', leave);
      window.removeEventListener('drop', drop);
    };
  }, [handleFile]);

  const onPointerDown = (e) => {
    drag.current = { id: e.pointerId, x: e.clientX, y: e.clientY };
    vpRef.current.setPointerCapture(e.pointerId);
    vpRef.current.style.cursor = 'grabbing';
  };
  const onPointerMove = (e) => {
    if (!drag.current || e.pointerId !== drag.current.id) return;
    const v = view.current;
    v.ox += e.clientX - drag.current.x;
    v.oy += e.clientY - drag.current.y;
    drag.current.x = e.clientX;
    drag.current.y = e.clientY;
    clamp();
    render();
  };
  const onPointerUp = (e) => {
    if (drag.current && e.pointerId === drag.current.id) {
      drag.current = null;
      if (vpRef.current) vpRef.current.style.cursor = 'grab';
    }
  };
  const onWheel = (e) => {
    e.preventDefault();
    setZoom(view.current.z * (e.deltaY < 0 ? 1.06 : 0.94));
  };
  // React attaches wheel listeners passively — preventDefault needs a manual one.
  useEffect(() => {
    const vp = vpRef.current;
    if (!vp || phase !== 'edit') return;
    vp.addEventListener('wheel', onWheel, { passive: false });
    return () => vp.removeEventListener('wheel', onWheel);
  }, [phase]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const s = scale();
      const v = view.current;
      const sw = V / s;
      const out = Math.min(512, Math.round(sw));
      const cv = document.createElement('canvas');
      cv.width = out;
      cv.height = out;
      const im = new Image();
      await new Promise((resolve, reject) => {
        im.onload = resolve;
        im.onerror = reject;
        im.src = src;
      });
      cv.getContext('2d').drawImage(im, -v.ox / s, -v.oy / s, sw, sw, 0, 0, out, out);
      const blob = await new Promise((resolve) => cv.toBlob(resolve, 'image/webp', 0.85));
      if (!blob) throw new Error('encode_failed');
      const d = await uploadAvatar(blob);
      onSaved(d.avatar);
      onClose();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      setErr(
        e.data?.error === 'unprocessable_image'
          ? "The server couldn't process that image. Try a different one."
          : "Couldn't save your picture. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    setErr(null);
    try {
      await deleteAvatar();
      onSaved(null);
      onClose();
    } catch (e) {
      if (e.message !== 'unauthenticated') setErr("Couldn't remove your picture. Please try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Profile picture" onClose={() => (busy ? null : onClose())}>
      {err && <div className="err-banner">{err}</div>}

      {phase === 'pick' && (
        <>
          <div className="drop-zone" onClick={() => fileRef.current?.click()}>
            <Icon name="camera" size={26} />
            <p className="dz-main">Drag an image here, or</p>
            <p className="dz-alt">Choose an image to upload</p>
          </div>
          <p className="hint" style={{ textAlign: 'center', marginTop: 10 }}>
            PNG, JPEG or WebP · up to 8 MB · shown as a circle across apps
          </p>
          <input
            ref={fileRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            style={{ display: 'none' }}
            onChange={(e) => {
              if (e.target.files?.[0]) handleFile(e.target.files[0]);
              e.target.value = '';
            }}
          />
          <div className="modal-actions">
            {hasPicture && (
              <button className="btn btn-danger" onClick={remove} disabled={busy}>
                {busy ? 'Removing…' : 'Remove picture'}
              </button>
            )}
            <button className="btn" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          </div>
        </>
      )}

      {phase === 'edit' && (
        <>
          <div
            ref={vpRef}
            className="crop-vp"
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
          >
            <img ref={imgRef} src={src} alt="" draggable={false} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '12px 0 0' }}>
            <Icon name="zoom-out" size={16} />
            <input
              ref={zoomRef}
              type="range"
              min="100"
              max="400"
              step="1"
              defaultValue="100"
              style={{ flex: 1 }}
              aria-label="Zoom"
              onInput={(e) => setZoom(Number(e.target.value) / 100)}
            />
            <Icon name="zoom-in" size={16} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 12 }}>
            <div className="crop-preview">
              <img ref={prevRef} src={src} alt="" draggable={false} />
            </div>
            <p className="hint" style={{ margin: 0, textAlign: 'left' }}>
              Drag to reposition · scroll to zoom. Saved as a square, shown as a circle.
            </p>
          </div>
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={save} disabled={busy}>
              {busy ? 'Saving…' : 'Save picture'}
            </button>
            <button
              className="btn"
              onClick={() => {
                setPhase('pick');
                setSrc(null);
                setErr(null);
              }}
              disabled={busy}
            >
              Back
            </button>
          </div>
        </>
      )}

      {dragging && (
        <div className="drop-full">
          <div className="drop-full-inner">
            Drop your image here
            <span className="drop-full-sub">Anywhere on the page works</span>
          </div>
        </div>
      )}
    </Modal>
  );
}
