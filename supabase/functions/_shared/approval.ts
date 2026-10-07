// Integrate into the EXISTING sheet-reference handler; preserve all Sheet logic/secrets.
// Never authorize by client-submitted UID, email, user_metadata, or a service-role client.
import { createClient } from 'npm:@supabase/supabase-js@2';

export async function requireApproval(req: Request, headers: HeadersInit = {}): Promise<Response | null> {
  const deny = (status: number, error: string) => Response.json({ error }, { status, headers });
  const authorization = req.headers.get('Authorization');
  if (!authorization?.startsWith('Bearer ')) return deny(401, 'Authentication required');
  const url = Deno.env.get('SUPABASE_URL');
  const key = Deno.env.get('SUPABASE_ANON_KEY');
  if (!url || !key) return deny(503, 'Authorization unavailable');
  const client = createClient(url, key, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  try {
    const { data: { user }, error: authError } = await client.auth.getUser(authorization.slice(7));
    if (authError || !user) return deny(401, 'Invalid session');
    if (!user.email_confirmed_at) return deny(403, 'Email verification required');
    const { data, error } = await client.rpc('has_approved_access');
    if (error) return deny(503, 'Authorization unavailable');
    return data === true ? null : deny(403, 'Approval required');
  } catch {
    return deny(503, 'Authorization unavailable');
  }
}
