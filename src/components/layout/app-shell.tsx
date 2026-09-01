import { Suspense, type ReactNode } from "react";

import { BrandMark } from "@/components/brand/mark";
import { Sidebar } from "@/components/layout/sidebar";
import { siteConfig } from "@/config/site";
import { SignOutButton } from "@/features/auth/components/sign-out-button";
import { NotificationBell } from "@/features/notifications/components/notification-bell";
import { getSessionUser } from "@/features/auth/lib/session";

type AppShellProps = {
  children: ReactNode;
};

async function SidebarWithUser() {
  const user = await getSessionUser();
  return <Sidebar userEmail={user?.email ?? undefined} />;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="flex h-full min-h-full flex-1 flex-col bg-base">
      <header className="flex h-11 items-center justify-between border-b border-line px-3 lg:hidden">
        <div className="flex items-center gap-2">
          <BrandMark />
          <p className="text-[12px] font-semibold text-highlight">
            {siteConfig.name}
          </p>
        </div>
        <div className="flex items-center gap-1">
          <NotificationBell />
          <SignOutButton />
        </div>
      </header>
      <div className="flex min-h-0 flex-1">
        <Suspense>
          <SidebarWithUser />
        </Suspense>
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">{children}</div>
      </div>
    </div>
  );
}
