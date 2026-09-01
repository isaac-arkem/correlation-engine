export default function IncidentDetailLoading() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-line border-t-accent" />
      <p className="text-[12px] text-subtle">Loading incident…</p>
    </div>
  );
}
