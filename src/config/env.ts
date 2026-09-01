type SupabasePublicConfig = {
  url: string;
  publishableKey: string;
};

function readSupabasePublicConfig(): SupabasePublicConfig | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const publishableKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ??
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !publishableKey) {
    return null;
  }

  return { url, publishableKey };
}

export function hasSupabasePublicConfig() {
  return readSupabasePublicConfig() !== null;
}

export function getSupabasePublicConfig(): SupabasePublicConfig {
  const config = readSupabasePublicConfig();

  if (!config) {
    throw new Error(
      "Missing Supabase env. Copy .env.example to .env.local and set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY.",
    );
  }

  return config;
}
