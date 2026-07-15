// Windowed pager shared by the org list pages (users, invitations): always 1 and
// `pages`, plus the current page and its two neighbours; gaps render an ellipsis.
// On mobile (≤640px) the page-number buttons and the "Prev"/"Next" labels hide
// (see styles.css), collapsing the row to count + two clear arrow buttons.
const pageNums = (page, pages) => {
  const s = new Set([1, pages, page, page - 1, page + 1]);
  return [...s].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
};

const ChevL = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m15 18-6-6 6-6" /></svg>;
const ChevR = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m9 18 6-6-6-6" /></svg>;

export default function Pager({ page, pages, total, from, to, onPage }) {
  if (total === 0) return null;
  return (
    <div className="pager">
      <span className="pager-count">{from}–{to} of {total}</span>
      <button className="pbtn" disabled={page === 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
        <ChevL /><span className="pbtn-lbl">Prev</span>
      </button>
      {pageNums(page, pages).map((n, i, arr) => (
        <span key={n}>
          {i > 0 && n - arr[i - 1] > 1 && <span className="pdots">…</span>}
          <button className={'pnum' + (n === page ? ' on' : '')} onClick={() => onPage(n)}>{n}</button>
        </span>
      ))}
      <button className="pbtn" disabled={page === pages} onClick={() => onPage(page + 1)} aria-label="Next page">
        <span className="pbtn-lbl">Next</span><ChevR />
      </button>
    </div>
  );
}
