import { useCallback, useEffect, useState } from 'react';
import { Outlet, Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';
import { getStepupStatus, setStepUpRequiredHandler } from '../../api.js';
import Icon from '../../components/Icon.jsx';
import StepUpModal from '../../components/StepUpModal.jsx';
import { DashboardSkeleton } from './OrgDashboardPage.jsx';
import { UsersSkeleton } from './OrgUsersPage.jsx';
import { UserDetailSkeleton } from './OrgUserDetailPage.jsx';
import { InvitesSkeleton } from './OrgInvitesPage.jsx';
import { RolesSkeleton } from './OrgRolesPage.jsx';
import { AppsSkeleton } from './OrgAppsPage.jsx';
import { LogsSkeleton } from './OrgLogsPage.jsx';

// While the step-up check runs, paint the DESTINATION pane's own skeleton —
// the pane mounts into identical pixels, so gate-wait and pane-load read as
// one continuous loading state instead of two different placeholders.
function PaneSkeleton() {
  const { can } = useAuth();
  const { pathname } = useLocation();
  if (/^\/organization\/users\/./.test(pathname)) return <UserDetailSkeleton />;
  if (pathname.startsWith('/organization/users')) return <UsersSkeleton />;
  if (pathname.startsWith('/organization/invites')) return <InvitesSkeleton />;
  if (pathname.startsWith('/organization/roles')) return <RolesSkeleton />;
  if (pathname.startsWith('/organization/apps')) return <AppsSkeleton />;
  if (pathname.startsWith('/organization/logs')) return <LogsSkeleton />;
  // Index route: mirror the dashboard's landing rule (no org.dashboard ->
  // it redirects to the first pane the caller holds).
  if (!can('org.dashboard')) return can('org.logs.view') ? <LogsSkeleton /> : null;
  return <DashboardSkeleton showRecent={can('org.logs.view')} />;
}

// The organization area's layout gate: every /organization/* route renders
// through here. Entry = step-up sudo window (setting-driven; strong-factor
// login pre-clears it); the SSO ALSO re-checks freshness server-side on every
// org mutation, so pages get `recheckStepup` via outlet context to re-open the
// modal when a long-lived tab's window expires mid-action.
export default function OrgGate() {
  const { canAny } = useAuth();
  const [gate, setGate] = useState({ state: 'loading' }); // entry lifecycle: loading | modal | blocked | open | error
  const [reverify, setReverify] = useState(null); // mid-session overlay challenge: null | status

  const check = useCallback(async () => {
    setGate({ state: 'loading' });
    try {
      const s = await getStepupStatus();
      if (!s.required || s.verified) setGate({ state: 'open' });
      else setGate({ state: 'modal', status: s });
    } catch (e) {
      if (e.message !== 'unauthenticated') setGate({ state: 'error' });
    }
  }, []);
  useEffect(() => {
    check();
  }, [check]);

  // Mid-session sudo-window expiry (an org request 403'd step_up_required). A READ
  // re-gates (check → remount → the pane re-fetches on success). A MUTATION
  // overlays the challenge WITHOUT tearing down the pane, so staged (unsaved)
  // edits survive and the user just re-submits. A transient status-probe failure
  // shows nothing (fail-safe: the next 403 retries) instead of stranding the area.
  const demandReverify = useCallback(async () => {
    const s = await getStepupStatus().catch(() => null);
    if (s && s.required && !s.verified) setReverify(s);
  }, []);
  const handleExpired = useCallback(
    (method) => (method && method !== 'GET' ? demandReverify() : check()),
    [check, demandReverify],
  );
  useEffect(() => {
    setStepUpRequiredHandler(handleExpired);
    return () => setStepUpRequiredHandler(null);
  }, [handleExpired]);

  if (!canAny('org.**')) return <Navigate to="/" replace />;

  return (
    <>
      {(gate.state === 'loading' || gate.state === 'modal') && <PaneSkeleton />}
      {gate.state === 'error' && (
        <div className="stub">
          <p className="err">Couldn't check verification status.</p>
          <button className="btn btn-primary" style={{ marginTop: 14 }} onClick={check}>
            Retry
          </button>
        </div>
      )}

      {gate.state === 'open' && <Outlet context={{ recheckStepup: demandReverify }} />}

      {gate.state === 'blocked' && (
        <div className="stub">
          <Icon name="lock" size={34} />
          <h3>Verification required</h3>
          <p>Confirm it's you with a passkey or authenticator code to manage the organization.</p>
          <button className="btn btn-primary" style={{ marginTop: 14 }} onClick={check}>
            Verify
          </button>
        </div>
      )}

      {gate.state === 'modal' && (
        <StepUpModal
          status={gate.status}
          onSuccess={() => setGate({ state: 'open' })}
          onCancel={() => setGate({ state: 'blocked' })}
        />
      )}

      {/* Mid-session re-verify (a mutation 403'd): overlaid on the still-mounted
          pane so staged edits survive; dismiss on either outcome and the user
          re-submits with a fresh window. */}
      {reverify && (
        <StepUpModal
          status={reverify}
          onSuccess={() => setReverify(null)}
          onCancel={() => setReverify(null)}
        />
      )}
    </>
  );
}
