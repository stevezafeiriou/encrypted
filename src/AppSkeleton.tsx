export default function AppSkeleton() {
  return (
    <main className="min-h-svh bg-background text-foreground">
      <section className="mx-auto flex min-h-svh w-full max-w-7xl flex-col px-4 py-4 sm:px-6">
        <header className="flex shrink-0 items-center justify-between py-2">
          <div className="size-10 animate-pulse rounded-md bg-muted" />
          <div className="h-10 w-56 animate-pulse rounded-full bg-muted" />
        </header>
        <div className="mx-auto flex w-full max-w-5xl flex-1 items-center justify-center">
          <div className="w-full max-w-3xl rounded-[2rem] border border-border bg-white p-4 shadow-[0_12px_38px_rgba(0,0,0,0.08)]">
            <div className="flex items-center gap-3">
              <div className="size-11 animate-pulse rounded-full bg-muted" />
              <div className="h-5 flex-1 animate-pulse rounded-full bg-muted" />
              <div className="size-11 animate-pulse rounded-full bg-muted" />
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}
