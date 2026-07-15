import ChallengeModal from './ChallengeModal.jsx';
import { stepupPasskeyOptions, stepupVerify, stepupSendEmail } from '../api.js';

// Step-up (sudo window) adapter over the shared ChallengeModal. Maps the
// /account/stepup/status shape onto the unified card + the sudo-window verify
// endpoints. `status.methods` is the accepted set (strong factors today; the
// tiered model widens it per scenario); `enroll_required` => no factor to
// challenge with => ChallengeModal renders the enroll card. Solving stamps the
// master session so the window also covers /admin.
export default function StepUpModal({ status, onSuccess, onCancel }) {
  const accepted = status.enroll_required ? [] : (status.methods || []);
  return (
    <ChallengeModal
      accepted={accepted}
      maskedEmail={status.masked_email}
      getPasskeyOptions={stepupPasskeyOptions}
      sendEmail={() => stepupSendEmail().then((d) => ({ otpMinutes: d?.minutes, resendIn: 60 }))}
      verify={({ method, code, credential, password }) =>
        stepupVerify(
          method === 'passkey'
            ? { method, credential }
            : method === 'password'
              ? { method, password }
              : { method, code },
        )
      }
      onSuccess={onSuccess}
      onCancel={onCancel}
    />
  );
}
