import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: 'Missing authorization header' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 401 },
      )
    }

    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      { auth: { autoRefreshToken: false, persistSession: false } },
    )

    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: authHeader } } },
    )

    const { data: { user: callerUser }, error: callerError } = await supabaseClient.auth.getUser()
    if (callerError || !callerUser) {
      return new Response(
        JSON.stringify({ error: 'Invalid authentication' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 401 },
      )
    }

    const { data: callerAgencyUser } = await supabaseAdmin
      .from('agency_users')
      .select('agency_id, role')
      .eq('id', callerUser.id)
      .eq('role', 'admin')
      .eq('is_active', true)
      .maybeSingle()

    if (!callerAgencyUser) {
      return new Response(
        JSON.stringify({ error: 'Only agency admins can remove staff' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 },
      )
    }

    const { userId } = await req.json()

    if (!userId) {
      return new Response(
        JSON.stringify({ error: 'Missing required field: userId' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
      )
    }

    if (userId === callerUser.id) {
      return new Response(
        JSON.stringify({ error: 'You cannot remove yourself from the agency' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
      )
    }

    // Verify target user belongs to the caller's agency
    const { data: targetAgencyUser } = await supabaseAdmin
      .from('agency_users')
      .select('id')
      .eq('id', userId)
      .eq('agency_id', callerAgencyUser.agency_id)
      .maybeSingle()

    if (!targetAgencyUser) {
      return new Response(
        JSON.stringify({ error: 'Staff member not found in your agency' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 404 },
      )
    }

    // SOFT DELETE — Preserve audit trail by deactivating instead of deleting
    // This maintains historical data in applications, documents, etc.
    const { error: deactivateError } = await supabaseAdmin
      .from('agency_users')
      .update({ 
        is_active: false,
        last_active_at: null,
        permissions: {} // Clear permissions on deactivation
      })
      .eq('id', userId)
      .eq('agency_id', callerAgencyUser.agency_id)

    if (deactivateError) {
      console.error('Failed to deactivate agency user:', deactivateError)
      throw new Error('Failed to deactivate staff member')
    }

    // Log the deactivation for audit purposes
    console.log(`Agency user ${userId} deactivated by admin ${callerUser.id}`)

    return new Response(
      JSON.stringify({ 
        success: true,
        message: 'Staff member deactivated successfully'
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 200 },
    )
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message ?? 'An unexpected error occurred' }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
    )
  }
})
