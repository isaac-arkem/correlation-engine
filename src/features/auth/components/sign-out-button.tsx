import { Button } from "@/components/ui/button";
import { signOut } from "@/features/auth/actions";

export function SignOutButton() {
  return (
    <form action={signOut}>
      <Button type="submit" variant="ghost">
        Sign out
      </Button>
    </form>
  );
}
