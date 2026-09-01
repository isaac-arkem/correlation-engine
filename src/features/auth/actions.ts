"use server";

import { redirect } from "next/navigation";

import { AFTER_LOGIN_PATH, LOGIN_PATH } from "@/features/auth/constants";
import { createSupabaseServerClient } from "@/lib/supabase/server";

export type LoginState = {
  error: string | null;
};

export async function login(
  _prevState: LoginState,
  formData: FormData,
): Promise<LoginState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");

  if (!email || !password) {
    return { error: "Email and password are required." };
  }

  const supabase = await createSupabaseServerClient();
  const { error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    if (error.code === "email_not_confirmed") {
      return {
        error:
          "Email is not confirmed. Open this user in Supabase → Authentication → Users and confirm the email.",
      };
    }

    return { error: "Invalid email or password." };
  }

  redirect(AFTER_LOGIN_PATH);
}

export async function signOut() {
  const supabase = await createSupabaseServerClient();
  await supabase.auth.signOut();
  redirect(LOGIN_PATH);
}
