import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const publishableKey =
  process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ??
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const email = process.argv[2];
const password = process.argv[3];

if (!url || !publishableKey) {
  console.error(
    "Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.",
  );
  process.exit(1);
}

if (!email || !password) {
  console.error("Usage: node scripts/create-login-user.mjs <email> <password>");
  process.exit(1);
}

const supabase = createClient(url, serviceRoleKey ?? publishableKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

if (serviceRoleKey) {
  const { error } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });

  if (error) {
    console.error(error.message);
    process.exit(1);
  }

  console.log(`Created confirmed user ${email}`);
  process.exit(0);
}

const { error } = await supabase.auth.signUp({ email, password });

if (error) {
  console.error(error.message);
  process.exit(1);
}

console.log(`Created user ${email}. Confirm the email in Supabase if required.`);
