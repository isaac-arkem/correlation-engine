"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useTransition } from "react";

/**
 * Navigation for the dashboard filters.
 *
 * Changing a filter rewrites the query string, which re-runs the page's server
 * components. React keeps the previous UI on screen while that happens, so
 * without an explicit pending state the dashboard looks frozen — and the user
 * clicks the control again, queueing another round trip. Wrapping the
 * navigation in a transition exposes `isPending` so callers can show progress
 * and disable the control until the new data arrives.
 */
export function useFilterNav() {
  const router = useRouter();
  const params = useSearchParams();
  const [isPending, startTransition] = useTransition();

  const navigate = useCallback(
    (next: URLSearchParams) => {
      const query = next.toString();
      startTransition(() => {
        router.replace(query ? `?${query}` : "/", { scroll: false });
      });
    },
    [router],
  );

  return { isPending, navigate, params };
}
