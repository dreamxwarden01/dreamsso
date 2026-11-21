// Shared DreamSSO brand geometry: optical small mark through 20px, master at 22px+.
// Text remains outside the decorative mark so configured site names stay intact.
const MASTER = 'M12 2.5L19.2 5.1Q20 5.4 20 6.3V11C20 15.6 16.8 18.9 12 20.9C7.2 18.9 4 15.6 4 11V6.3Q4 5.4 4.8 5.1ZM9.25 10.5A2.75 2.75 0 1 0 14.75 10.5A2.75 2.75 0 1 0 9.25 10.5Z';
const SMALL = 'M8 1L14.2 3.25Q15 3.55 15 4.4V7.7C15 11.3 12.4 13.8 8 15.25C3.6 13.8 1 11.3 1 7.7V4.4Q1 3.55 1.8 3.25ZM6 7A2 2 0 1 0 10 7A2 2 0 1 0 6 7Z';

export default function BrandMark({ size = 24, className, style }) {
  const small = size <= 20;
  return (
    <svg className={className} style={{ flexShrink: 0, ...style }} width={size} height={size}
      viewBox={small ? '0 0 16 16' : '0 0 24 24'} fill="currentColor" stroke="none" aria-hidden="true">
      <path fillRule="evenodd" d={small ? SMALL : MASTER} />
    </svg>
  );
}
