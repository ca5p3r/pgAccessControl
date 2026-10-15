import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./client";

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        // Don't retry client errors (404, 403, 409 …); only transient failures.
        retry: (count, err) => !(err instanceof ApiError && err.status > 0 && err.status < 500) && count < 2,
      },
    },
  });
}
