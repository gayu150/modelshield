import type { ReactNode } from "react";
export function Loading({ children = "Loading…" }: { children?: ReactNode }) {
  return (
    <div className="feedback" role="status" aria-live="polite">
      {children}
    </div>
  );
}
export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="feedback feedback-error" role="alert">
      <p>{message}</p>
      {onRetry && (
        <button className="btn outline" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
export function EmptyState({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <b>{title}</b>
      <span>{children}</span>
    </div>
  );
}
export function Pagination({
  page,
  total,
  pageSize = 10,
  onChange,
}: {
  page: number;
  total: number;
  pageSize?: number;
  onChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, pages);
  return (
    <nav className="pagination" aria-label="Pagination">
      <button
        className="btn outline"
        disabled={current <= 1}
        onClick={() => onChange(current - 1)}
      >
        Previous
      </button>
      <span>
        Page {current} of {pages} · {total} records
      </span>
      <button
        className="btn outline"
        disabled={current >= pages}
        onClick={() => onChange(current + 1)}
      >
        Next
      </button>
    </nav>
  );
}
