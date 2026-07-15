// Live password requirement indicators — ported from videosite's PasswordRules.
// Neutral (grey) when empty, then green (pass) / red (fail) per rule as you type.
// Policy mirrors the SSO: ≥8 chars AND ≥3 of {upper, lower, digit, special}.
export function checkPasswordComplexity(pw) {
  const rules = { length: false, complexity: false };
  if (!pw) return { rules, error: '' };

  rules.length = pw.length >= 8;

  let cats = 0;
  if (/[A-Z]/.test(pw)) cats++;
  if (/[a-z]/.test(pw)) cats++;
  if (/[0-9]/.test(pw)) cats++;
  if (/[^A-Za-z0-9]/.test(pw)) cats++;
  rules.complexity = cats >= 3;

  let error = '';
  if (!rules.length) error = 'Password must be at least 8 characters long.';
  else if (!rules.complexity) error = 'Must include at least 3 of: uppercase, lowercase, digits, special characters.';

  return { rules, error };
}

export function passwordValid(pw) {
  const { rules } = checkPasswordComplexity(pw);
  return rules.length && rules.complexity;
}

export default function PasswordRules({ password }) {
  const hasInput = password.length > 0;
  const { rules } = checkPasswordComplexity(password);

  const items = [
    { key: 'length', label: 'At least 8 characters' },
    { key: 'complexity', label: 'Includes 3 of: uppercase, lowercase, digit, special character' },
  ];

  return (
    <ul className="pwrules">
      {items.map(({ key, label }) => {
        const state = !hasInput ? 'neutral' : rules[key] ? 'pass' : 'fail';
        const icon = state === 'pass' ? '✓' : state === 'fail' ? '✗' : '•';
        return (
          <li key={key} className={`pwrule ${state}`}>
            <span className="pwrule-ico">{icon}</span>
            {label}
          </li>
        );
      })}
    </ul>
  );
}
