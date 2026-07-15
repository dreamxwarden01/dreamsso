import { useRef } from 'react';

// The 6-box code entry — React port of the SSO login challenge's OTP input
// (videosite OtpInput lineage): auto-advance, backspace walks back, paste
// fills all six, arrows move, onComplete fires when the sixth digit lands.
// `value` is the contiguous code string (0–6 digits).
export default function OtpBoxes({ value, onChange, onComplete, disabled = false, autoFocus = true }) {
  const refs = useRef([]);
  const digits = Array.from({ length: 6 }, (_, i) => value[i] ?? '');

  const commit = (next) => {
    onChange(next);
    if (next.length === 6) onComplete?.(next);
  };

  const handleChange = (i, raw) => {
    const ds = raw.replace(/\D/g, '');
    if (!ds) {
      commit(value.slice(0, i));
      return;
    }
    // Typed digit or pasted run: place from position i, cap at six.
    const next = (value.slice(0, i) + ds).slice(0, 6);
    commit(next);
    refs.current[Math.min(next.length, 5)]?.focus();
  };

  const handleKeyDown = (i, e) => {
    if (e.key === 'Backspace') {
      e.preventDefault();
      if (digits[i]) {
        commit(value.slice(0, i));
      } else if (i > 0) {
        commit(value.slice(0, i - 1));
        refs.current[i - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && i > 0) {
      refs.current[i - 1]?.focus();
    } else if (e.key === 'ArrowRight' && i < 5) {
      refs.current[i + 1]?.focus();
    }
  };

  return (
    <div className="otp">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => { refs.current[i] = el; }}
          className="input"
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          maxLength={6} /* a full-code paste can land in any box */
          value={d}
          disabled={disabled}
          autoFocus={autoFocus && i === 0}
          onChange={(e) => handleChange(i, e.target.value)}
          onKeyDown={(e) => handleKeyDown(i, e)}
          onFocus={(e) => e.target.select()}
        />
      ))}
    </div>
  );
}
