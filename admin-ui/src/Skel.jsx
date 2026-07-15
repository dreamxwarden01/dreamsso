// Per-element skeletons: static chrome renders for REAL (labels, icon tiles,
// chevrons), only variable values shimmer at their final size.
import Icon from './Icon.jsx';

export const SkelInput = ({ width }) => (
  <div className="skel" style={{ height: 38, borderRadius: 9, ...(width ? { maxWidth: width } : {}) }} />
);

// Inline placeholder that inherits the surrounding text's font metrics — put
// it inside the real <p>/<h1> so the line box keeps its final height.
export const Ph = ({ w }) => (
  <span className="skel" style={{ display: 'inline-block', width: w, maxWidth: '100%', height: '1em', borderRadius: 4, verticalAlign: 'middle' }} />
);

// A list-row placeholder shaped like the real rows: the icon tile is static
// chrome (fixed glyph per page) so it renders for real; name, meta line, and
// status pill shimmer.
export const SkelListRow = ({ icon, tileStyle, chevron = false }) => (
  <div className="row">
    <span className="lhs" style={{ flex: 1 }}>
      <span className="tile" style={tileStyle}>
        <Icon name={icon} size={17} />
      </span>
      <span style={{ minWidth: 0, flex: 1, maxWidth: 260 }}>
        <p className="row-title"><Ph w="55%" /></p>
        <p className="k"><Ph w="80%" /></p>
      </span>
    </span>
    <span style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div className="skel" style={{ height: 20, width: 56, borderRadius: 99 }} />
      {chevron && <Icon name="chevron" size={15} className="chev" />}
    </span>
  </div>
);
