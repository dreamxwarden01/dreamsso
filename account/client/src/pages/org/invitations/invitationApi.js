import { orgApi } from '../../../api.js';
import { invitationFromDto, invitationMutationFromDto, invitationPageFromDto, queryParams } from './invitationModel.js';

export const loadInvitations = (query, signal) => orgApi('GET', '/invites?' + queryParams(query), undefined, { signal, timeoutMs: 15000 }).then(invitationPageFromDto);
export const loadInvitationRoles = (signal) => orgApi('GET', '/roles', undefined, { signal, timeoutMs: 15000 });
export const loadInvitation = (id, signal) => orgApi('GET', '/invites/' + encodeURIComponent(id), undefined, { signal, timeoutMs: 15000 }).then((d) => invitationFromDto(d?.invitation));
export const createInvitation = (body) => orgApi('POST', '/invites', body, { timeoutMs: 15000 }).then(invitationMutationFromDto);
export const resendInvitation = (id, requestId) => orgApi('POST', `/invites/${encodeURIComponent(id)}/resend`, { request_id: requestId }, { timeoutMs: 15000 }).then(invitationMutationFromDto);
export const revokeInvitation = (id, requestId) => orgApi('POST', `/invites/${encodeURIComponent(id)}/revoke`, { request_id: requestId }, { timeoutMs: 15000 }).then(invitationMutationFromDto);
