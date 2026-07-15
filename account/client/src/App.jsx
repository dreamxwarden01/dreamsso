import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext.jsx';
import { SiteProvider } from './context/SiteContext.jsx';
import { Toaster } from './components/Toast.jsx';
import AppShell from './components/AppShell.jsx';
import { SkeletonShell } from './components/Skeleton.jsx';
import ProfilePage from './pages/ProfilePage.jsx';
import SecurityPage from './pages/SecurityPage.jsx';
import PasswordPage from './pages/PasswordPage.jsx';
import AuthenticatorPage from './pages/AuthenticatorPage.jsx';
import PasskeysPage from './pages/PasskeysPage.jsx';
import DevicesPage from './pages/DevicesPage.jsx';
import OrgGate from './pages/org/OrgGate.jsx';
import OrgDashboardPage from './pages/org/OrgDashboardPage.jsx';
import OrgLogsPage from './pages/org/OrgLogsPage.jsx';
import OrgUsersPage from './pages/org/OrgUsersPage.jsx';
import OrgInvitesPage from './pages/org/OrgInvitesPage.jsx';
import OrgUserDetailPage from './pages/org/OrgUserDetailPage.jsx';
import OrgRolesPage from './pages/org/OrgRolesPage.jsx';
import OrgAppsPage from './pages/org/OrgAppsPage.jsx';
import ForgotPage from './pages/ForgotPage.jsx';
import ResetPage from './pages/ResetPage.jsx';
import RegisterStartPage from './pages/RegisterStartPage.jsx';
import RegisterCompletePage from './pages/RegisterCompletePage.jsx';
import VerifyEmailPage from './pages/VerifyEmailPage.jsx';

function Gate({ children }) {
  const { loading, user } = useAuth();
  if (loading) return <SkeletonShell />;
  if (!user) return null; // getMe already redirected to /auth/login
  return children;
}

// Everything session-gated lives under this element; the public reset pages
// (/forgot, /reset) mount OUTSIDE it so an anonymous visitor is never bounced
// to /auth/login.
function Private() {
  return (
    <AuthProvider>
      <Gate>
        <Outlet />
      </Gate>
    </AuthProvider>
  );
}

export default function App() {
  return (
    <SiteProvider>
      <Toaster />
      <Routes>
        <Route path="forgot" element={<ForgotPage />} />
        <Route path="reset" element={<ResetPage />} />
        <Route path="register/start" element={<RegisterStartPage />} />
        <Route path="register/complete" element={<RegisterCompletePage />} />
        <Route path="verify-email" element={<VerifyEmailPage />} />
        <Route element={<Private />}>
          <Route element={<AppShell />}>
            <Route index element={<ProfilePage />} />
            <Route path="security" element={<SecurityPage />} />
            <Route path="security/password" element={<PasswordPage />} />
            <Route path="security/authenticator" element={<AuthenticatorPage />} />
            <Route path="security/passkeys" element={<PasskeysPage />} />
            <Route path="devices" element={<DevicesPage />} />
            <Route path="organization" element={<OrgGate />}>
              <Route index element={<OrgDashboardPage />} />
              <Route path="users" element={<OrgUsersPage />} />
              <Route path="users/:sub" element={<OrgUserDetailPage />} />
              <Route path="invites" element={<OrgInvitesPage />} />
              <Route path="roles" element={<OrgRolesPage />} />
              <Route path="apps" element={<OrgAppsPage />} />
              <Route path="logs" element={<OrgLogsPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Routes>
    </SiteProvider>
  );
}
