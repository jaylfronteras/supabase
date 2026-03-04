import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

function generateTempPassword(): string {
  const bytes = new Uint8Array(12)
  crypto.getRandomValues(bytes)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('') + 'Aa1!'
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
        JSON.stringify({ error: 'Only agency admins can invite staff' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 },
      )
    }

    const { email, role, fullName, agencyId } = await req.json()

    if (!email || !role || !fullName) {
      return new Response(
        JSON.stringify({ error: 'Missing required fields: email, role, fullName' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
      )
    }

    if (callerAgencyUser.agency_id !== agencyId) {
      return new Response(
        JSON.stringify({ error: 'You can only invite staff to your own agency' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 },
      )
    }

    const tempPassword = generateTempPassword()

    // Check if a user with this email already exists (e.g. previously removed staff)
    const { data: existingAppUser } = await supabaseAdmin
      .from('app_users')
      .select('id, role')
      .eq('email', email)
      .maybeSingle()

    if (existingAppUser) {
      // Don't allow re-inviting seafarer or super_admin accounts as staff
      if (existingAppUser.role !== 'agency_staff') {
        return new Response(
          JSON.stringify({ error: 'This email is already registered as a different account type' }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 409 },
        )
      }

      // Check they're not already active in this agency
      const { data: existingAgencyUser } = await supabaseAdmin
        .from('agency_users')
        .select('id')
        .eq('id', existingAppUser.id)
        .eq('agency_id', agencyId)
        .maybeSingle()

      if (existingAgencyUser) {
        return new Response(
          JSON.stringify({ error: 'This staff member is already in your agency' }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 409 },
        )
      }

      // Reset their password so they can log in with fresh credentials
      const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
        existingAppUser.id,
        { password: tempPassword, email_confirm: true },
      )
      if (updateError) throw updateError

      // Update their display name in case it changed
      await supabaseAdmin
        .from('app_users')
        .update({ full_name: fullName })
        .eq('id', existingAppUser.id)

      // Re-add to agency_users
      const { error: agencyUserError } = await supabaseAdmin.from('agency_users').insert({
        id: existingAppUser.id,
        agency_id: agencyId,
        role,
        permissions: {},
      })
      if (agencyUserError) throw agencyUserError

      return new Response(
        JSON.stringify({ success: true, userId: existingAppUser.id, tempPassword }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 200 },
      )
    }

    // New user — create auth account
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password: tempPassword,
      email_confirm: true,
      user_metadata: {
        role: 'agency_staff',
        full_name: fullName,
      },
    })

    if (authError) throw authError

    // Wait for handle_new_user trigger to create app_users row
    await new Promise((resolve) => setTimeout(resolve, 800))

    const { error: agencyUserError } = await supabaseAdmin.from('agency_users').insert({
      id: authData.user.id,
      agency_id: agencyId,
      role,
      permissions: {},
    })

    if (agencyUserError) {
      await supabaseAdmin.auth.admin.deleteUser(authData.user.id)
      throw agencyUserError
    }

    return new Response(
      JSON.stringify({ success: true, userId: authData.user.id, tempPassword }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 200 },
    )
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message ?? 'An unexpected error occurred' }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
    )
  }
})
