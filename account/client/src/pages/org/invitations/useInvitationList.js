import { useEffect, useRef, useState } from 'react';
import { loadInvitations } from './invitationApi.js';
import { DEFAULT_QUERY } from './invitationModel.js';
import { createInvitationListEngine } from './invitationListEngine.js';

export function useInvitationList() {
  const engine = useRef(null);
  const [model, setModel] = useState({ data: null, committedQuery: null, query: { ...DEFAULT_QUERY }, pending: true, overlay: false, error: null });
  useEffect(() => {
    let active = true;
    const current = createInvitationListEngine({ request: loadInvitations, publish: (state) => { if (active) setModel(state); } });
    engine.current = current; current.load(DEFAULT_QUERY);
    return () => { active = false; current.dispose(); if (engine.current === current) engine.current = null; };
  }, []);
  return { model, engine };
}
