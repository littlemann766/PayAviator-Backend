/**
 * Firebase Auth Admin lookup used only to distinguish "this uid still has an account"
 * from "Auth reports the uid does not exist". It does not read email, and it does not
 * list users. Missing credentials or any error other than auth/user-not-found must be
 * treated as unavailable by classifyAccountLookupError — never as deletion.
 */
export async function createAccountLookup({ serviceAccount, projectId } = {}) {
  if (!serviceAccount?.client_email || !serviceAccount?.private_key || !projectId) return null;
  const { initializeApp, cert, getApps } = await import('firebase-admin/app');
  const { getAuth } = await import('firebase-admin/auth');
  const name = 'payaviator-auth';
  const app = getApps().find(a => a.name === name) || initializeApp({ credential: cert(serviceAccount), projectId }, name);
  const auth = getAuth(app);
  return {
    configured: true,
    getUser: uid => auth.getUser(uid),
  };
}
