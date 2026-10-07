import { useEffect, useState } from "react";
import { safeMessage } from "../services/api/client";
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  dependencies: unknown[],
) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setData(undefined);
    setError("");
    setLoading(true);
    load(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setData(value);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(safeMessage(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [...dependencies, revision]);
  return { data, error, loading, reload: () => setRevision((x) => x + 1) };
}
