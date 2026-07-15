// Skeleton placeholders — left-to-right shimmer ported from videosite's video
// list. Used to pre-render a page's shape while data loads, so content swaps in
// without a flash/layout shift.
import Icon from './Icon.jsx';

export function Skeleton({ w, h = 14, r = 4, style }) {
  return <span className="skeleton" style={{ width: w, height: h, borderRadius: r, display: 'block', ...style }} />;
}

// Inline placeholder that inherits the SURROUNDING text's font metrics: put it
// inside the real <p>/<h2>/etc. and the line box keeps exactly the height the
// loaded text will have — static chrome renders, only the value shimmers.
export function Ph({ w }) {
  return <span className="skeleton" style={{ display: 'inline-block', width: w, maxWidth: '100%', height: '1em', borderRadius: 4, verticalAlign: 'middle' }} />;
}

// One MFA-method placeholder row: the REAL icon tile and action buttons render
// (they're static chrome — the glyph is fixed per page), only the label and
// dates shimmer at final line height.
export function MethodRowSkeleton({ icon }) {
  return (
    <div className="row">
      <div className="mfa-lhs">
        <span className="mfa-ico"><Icon name={icon} size={20} /></span>
        <div className="row-main">
          <p className="mfa-title"><Ph w={120} /></p>
          <p className="k"><Ph w={230} /></p>
        </div>
      </div>
      <div className="row-actions">
        <button className="btn"><Icon name="edit" size={14} />Rename</button>
        <button className="btn btn-danger"><Icon name="trash" size={14} />Remove</button>
      </div>
    </div>
  );
}

// A card of `rows` placeholder rows shaped like an MFA/list row: an optional
// icon chip + two text lines, and a right-side control block.
export function SkeletonRows({ rows = 3, icon = true }) {
  return (
    <div className="card">
      {Array.from({ length: rows }).map((_, i) => (
        <div className="row" key={i}>
          <div className="mfa-lhs">
            {icon && <span className="skeleton" style={{ width: 38, height: 38, borderRadius: 9, flexShrink: 0 }} />}
            <div style={{ minWidth: 0 }}>
              <Skeleton w={150} h={14} />
              <Skeleton w={90} h={11} style={{ marginTop: 8 }} />
            </div>
          </div>
          <Skeleton w={74} h={30} r={8} />
        </div>
      ))}
    </div>
  );
}

// Full app-chrome skeleton for the very first load (replaces the boot spinner).
export function SkeletonShell() {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Icon name="shield-lock" size={20} />
          <span>DreamSSO account</span>
        </div>
        <Skeleton w={120} h={28} r={8} />
      </header>
      <div className="body">
        <nav className="side">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} w="78%" h={18} r={6} style={{ margin: '9px 12px' }} />
          ))}
        </nav>
        <main className="content">
          <div className="content-inner">
            <Skeleton w={180} h={26} r={6} />
            <Skeleton w={260} h={14} style={{ marginTop: 10, marginBottom: 22 }} />
            <SkeletonRows rows={3} />
          </div>
        </main>
      </div>
    </div>
  );
}
