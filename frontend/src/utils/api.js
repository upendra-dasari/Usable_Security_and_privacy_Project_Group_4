/**
 * api.js — lightweight fetch wrapper
 * All requests include credentials (cookies) for session support.
 */

const BASE = '';

async function post(url, body) {
  const res = await fetch(BASE + url, {
    method:      'POST',
    headers:     { 'Content-Type': 'application/json' },
    credentials: 'include',
    body:        JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

async function get(url) {
  const res = await fetch(BASE + url, { credentials: 'include' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

export const api = { post, get };
