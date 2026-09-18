import { useSyncExternalStore } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, auth, subscribeToAuth } from "@/lib/api";
import type { Organization } from "@/lib/types";

/** The organizations the signed-in user belongs to, own ones first. */
export function useOrganizations() {
  return useQuery({
    queryKey: ["organizations"],
    queryFn: () => api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });
}

/**
 * The organization requests act in.
 *
 * Read through the auth store's own subscription, so switching organization
 * anywhere re-renders everything that asked. Falls back the way the API does:
 * an own organization before the demo (the list arrives in that order).
 */
export function useCurrentOrganization(): Organization | undefined {
  const selected = useSyncExternalStore(
    subscribeToAuth,
    () => auth.organizationId,
    () => null,
  );
  const { data } = useOrganizations();
  const rows = Array.isArray(data) ? data : [];
  return rows.find((org) => org.id === selected) ?? rows[0];
}

/**
 * Whether the reader is in the shared demo.
 *
 * Used to take write actions off the screen there -- the API refuses them
 * anyway (``TenantContext.require_write``), and a button that can only ever
 * answer "read-only" is a button that should not be drawn.
 */
export function useIsDemo(): boolean {
  return useCurrentOrganization()?.is_demo === true;
}

/**
 * Join the demo and open it.
 *
 * The same switch the organization menu makes: store the id, drop every cached
 * answer about the previous organization, and land on the overview.
 */
export function useJoinDemo() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.post<Organization>("/api/v1/organizations/demo/join").then((r) => r.data),
    onSuccess: (org) => {
      // `auth` is an external store; see the same exemption in AccountMenu.
      // eslint-disable-next-line react-hooks/immutability
      auth.organizationId = org.id;
      queryClient.clear();
      navigate("/", { replace: true });
    },
  });
}

/** Leave the demo, and go back to an own organization or to creating one. */
export function useLeaveDemo() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data } = useOrganizations();
  return useMutation({
    mutationFn: () => api.post("/api/v1/organizations/demo/leave"),
    onSuccess: () => {
      const own = (Array.isArray(data) ? data : []).find((org) => !org.is_demo);
      // eslint-disable-next-line react-hooks/immutability
      auth.organizationId = own?.id ?? null;
      queryClient.clear();
      navigate(own ? "/" : "/onboarding", { replace: true });
    },
  });
}
