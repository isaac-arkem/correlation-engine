import { BrandMark } from "@/components/brand/mark";
import { Caption } from "@/components/ui/caption";
import { siteConfig } from "@/config/site";
import { LoginForm } from "@/features/auth/components/login-form";

export const metadata = {
  title: `Sign in · ${siteConfig.name}`,
};

export default function LoginPage() {
  return (
    <div className="w-full max-w-[22rem]">
      <div className="mb-6 flex items-center gap-2.5">
        <BrandMark />
        <div>
          <p className="text-[12px] font-semibold text-highlight">
            {siteConfig.name}
          </p>
          <Caption>Correlation engine</Caption>
        </div>
      </div>

      <div className="rounded-brand border border-line bg-field p-5">
        <div className="mb-5">
          <Caption>Operator access</Caption>
          <h1 className="mt-1 text-[12px] font-semibold text-highlight">
            Sign in
          </h1>
          <p className="mt-1 text-[12px] text-muted">
            Authenticated operators only.
          </p>
        </div>
        <LoginForm />
      </div>

      <Caption className="mt-4 text-center">
        Session is cookie-bound · unauthorized access is logged
      </Caption>
    </div>
  );
}
