import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    status,
  })
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // Validate required env vars before doing anything
    const supabaseUrl = Deno.env.get('SUPABASE_URL')
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')

    if (!supabaseUrl || !serviceRoleKey) {
      console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY')
      return json({ error: 'Server configuration error' }, 500)
    }

    const body = await req.json()
    const { agencyName, agencySlug, location, vesselTypes, adminEmail, adminPassword, adminFullName } = body

    if (!agencyName || !agencySlug || !adminEmail || !adminPassword || !adminFullName) {
      return json({ error: 'Missing required fields' }, 400)
    }

    const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    // Step 1: Create agency record
    const { data: agency, error: agencyError } = await supabaseAdmin
      .from('agencies')
      .insert({
        name: agencyName,
        slug: agencySlug,
        location: location ?? null,
        vessel_types: vesselTypes ?? [],
      })
      .select()
      .single()

    if (agencyError) {
      console.error('Agency insert error:', agencyError)
      if (agencyError.code === '23505') {
        return json({ error: 'An agency with this name already exists. Please choose a different name.' }, 409)
      }
      return json({ error: agencyError.message }, 400)
    }

    // Step 2: Create subscription record
    const { error: subError } = await supabaseAdmin
      .from('agency_subscriptions')
      .insert({ agency_id: agency.id })

    if (subError) {
      console.error('Subscription insert error:', subError)
      // Non-fatal — continue anyway
    }

    // Step 3: Create admin auth user
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: adminEmail,
      password: adminPassword,
      email_confirm: true,
      user_metadata: {
        role: 'agency_admin',
        full_name: adminFullName,
      },
    })

    if (authError) {
      console.error('Auth user creation error:', authError)
      await supabaseAdmin.from('agencies').delete().eq('id', agency.id)
      return json({ error: authError.message }, 400)
    }

    // Step 4: Poll for app_users row created by handle_new_user trigger (max 3s)
    let appUserCreated = false
    for (let attempt = 0; attempt < 6; attempt++) {
      await new Promise((r) => setTimeout(r, 500))
      const { data } = await supabaseAdmin
        .from('app_users')
        .select('id')
        .eq('id', authData.user.id)
        .maybeSingle()
      if (data) {
        appUserCreated = true
        break
      }
    }

    if (!appUserCreated) {
      console.error('app_users row not created by trigger for user:', authData.user.id)
      // Manually insert app_users in case trigger hasn't fired
      const { error: manualInsertError } = await supabaseAdmin.from('app_users').insert({
        id: authData.user.id,
        email: adminEmail,
        role: 'agency_admin',
        full_name: adminFullName,
      })
      if (manualInsertError) {
        console.error('Manual app_users insert error:', manualInsertError)
        await supabaseAdmin.auth.admin.deleteUser(authData.user.id)
        await supabaseAdmin.from('agencies').delete().eq('id', agency.id)
        return json({ error: 'Failed to create user profile: ' + manualInsertError.message }, 400)
      }
    }

    // Step 5: Link admin to agency
    const { error: agencyUserError } = await supabaseAdmin.from('agency_users').insert({
      id: authData.user.id,
      agency_id: agency.id,
      role: 'admin',
      permissions: {},
    })

    if (agencyUserError) {
      console.error('Agency user insert error:', agencyUserError)
      await supabaseAdmin.auth.admin.deleteUser(authData.user.id)
      await supabaseAdmin.from('agencies').delete().eq('id', agency.id)
      return json({ error: agencyUserError.message }, 400)
    }

    return json({ success: true, agencyId: agency.id, userId: authData.user.id })
  } catch (err) {
    console.error('Unhandled error in agency-onboard:', err)
    return json({ error: err instanceof Error ? err.message : 'An unexpected error occurred' }, 400)
  }
})
