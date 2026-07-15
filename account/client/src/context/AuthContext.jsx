import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { getMe, logout as apiLogout, setPermissionDeniedHandler } from '../api.js';
import { matchPerm } from '../permMatch.js';

const AuthCtx = createContext(null);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ loading: true, user: null, error: null });

  const reload = useCallback(async () => {
    try {
      const user = await getMe();
      setState({ loading: false, user, error: null });
    } catch (e) {
      // 'unauthenticated' already triggered a redirect to /auth/login.
      if (e.message === 'unauthenticated') return;
      setState({ loading: false, user: null, error: e });
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  // Re-sync the effective permission set whenever an action is denied.
  useEffect(() => {
    setPermissionDeniedHandler(reload);
    return () => setPermissionDeniedHandler(null);
  }, [reload]);

  // can(key): the BFF returns only GRANTED keys; anything absent is denied.
  const can = useCallback(
    (key) => !!state.user?.permissions?.includes(key),
    [state.user],
  );
  // canAny(pattern): wildcard check over the granted set — e.g. canAny('org.**')
  // decides whether the Organization rail entry shows at all.
  const canAny = useCallback(
    (pattern) => (state.user?.permissions ?? []).some((k) => matchPerm(pattern, k)),
    [state.user],
  );

  return (
    <AuthCtx.Provider value={{ ...state, reload, can, canAny, logout: apiLogout }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
