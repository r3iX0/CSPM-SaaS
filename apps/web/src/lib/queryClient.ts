import { QueryClient } from "@tanstack/react-query";

import { ApiError, auth, subscribeToAuth } from "@/lib/api";

/**
 * Whether a failed request is worth sending a second time.
 *
 * The default was one blanket retry, which spends a second round trip on every
 * answer the server has already given definitively. A 4xx is not a fault to ride
 * out: not signed in, not allowed, not found and bad request all say the same
 * thing twice, and the reader waits twice as long to be told. What is worth
 * retrying is the class of failure that is nobody's answer at all -- a 5xx from
 * a container mid-restart, a request that timed out, a connection that dropped
 * -- which is what `status === 0` covers, the code the client stamps on a
 * network error or a timeout.
 */
export function shouldRetry(attempt: number, error: unknown): boolean {
  if (attempt >= 1) return false;
  const status = error instanceof ApiError ? error.status : 0;
  return status === 0 || status >= 500;
}

export function createQueryClient(): QueryClient {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: shouldRetry,
        refetchOnWindowFocus: false,
        staleTime: 15_000,
      },
    },
  });

  // Cache keys do not carry the organization id, so any sign-out (including an
  // expired session's 401 or another tab signing out) or organization change
  // clears the cache here rather than relying on every caller to remember.
  let lastToken = auth.token;
  let lastOrg = auth.organizationId;
  subscribeToAuth(() => {
    const nextToken = auth.token;
    const nextOrg = auth.organizationId;
    if ((lastToken && !nextToken) || (lastOrg && nextOrg !== lastOrg)) {
      client.clear();
    }
    lastToken = nextToken;
    lastOrg = nextOrg;
  });

  return client;
}
