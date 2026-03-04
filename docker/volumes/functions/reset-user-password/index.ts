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

    // Verify caller is authenticated
    const { data: { user: callerUser }, error: callerError } = await supabaseClient.auth.getUser()
    if (callerError || !callerUser) {
      return new Response(
        JSON.stringify({ error: 'Invalid authentication' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 401 },
      )
    }

    // Verify caller is a super admin
    const { data: callerAppUser } = await supabaseAdmin
      .from('app_users')
      .select('role, is_active')
      .eq('id', callerUser.id)
      .eq('role', 'super_admin')
      .eq('is_active', true)
      .maybeSingle()

    if (!callerAppUser) {
      return new Response(
        JSON.stringify({ error: 'Only active super admins can reset passwords' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 },
      )
    }

    const { userId, email, tempPassword } = await req.json()

    if (!userId || !email || !tempPassword) {
      return new Response(
        JSON.stringify({ error: 'Missing required fields: userId, email, tempPassword' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
      )
    }

    // Verify the user exists and get their role
    const { data: targetUser } = await supabaseAdmin
      .from('app_users')
      .select('id, role')
      .eq('id', userId)
      .maybeSingle()

    if (!targetUser) {
      return new Response(
        JSON.stringify({ error: 'User not found' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 404 },
      )
    }

    // Prevent resetting password of another super admin (security measure)
    if (targetUser.role === 'super_admin' && targetUser.id !== callerUser.id) {
      return new Response(
        JSON.stringify({ error: 'Cannot reset password of another super admin' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 },
      )
    }

    // Reset password using Admin API
    const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
      userId,
      { password: tempPassword, email_confirm: true },
    )

    if (updateError) {
      console.error('Failed to update password:', updateError)
      throw updateError
    }

    return new Response(
      JSON.stringify({ success: true, userId }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 200 },
    )
  } catch (error) {
    console.error('reset-user-password error:', error)
    return new Response(
      JSON.stringify({ error: error.message ?? 'An unexpected error occurred' }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 },
    )
  }
})
