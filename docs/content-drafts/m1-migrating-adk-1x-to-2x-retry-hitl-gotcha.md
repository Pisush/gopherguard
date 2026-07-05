# Migrating ADK Go 1.x → 2.0: the retry/HITL gotcha that bit me

*Draft — gopherguard milestone M1. Content draft for engineer-to-engineer publication; unverified claims are marked inline with `<!-- VERIFY -->`.*

Short version: I put a broad `recover()` inside a tool function during the 1.x → 2.0 migration, out of old habit, and it silently ate the exact signal ADK 2.0 uses to drive both automatic retries and human-in-the-loop confirmation. No panic in the logs, no error surfaced anywhere — just a mutating tool that quietly stopped asking for confirmation and a retry policy that quietly stopped retrying. It cost me an afternoon to trace back to one `defer func() { recover() }()` I'd written without thinking twice about it.

## The mechanical parts of the migration first

Two boring but mandatory changes before anything else works:

1. **Import path.** `google.golang.org/adk` becomes `google.golang.org/adk/v2`. Every file that imports the SDK needs the update — a repo-wide find/replace across imports, not a one-liner in `go.mod`.
2. **Go version floor.** ADK 2.0 requires **Go 1.25+**. If you're pinning toolchains per-module (worth doing regardless — see the M0 notes on `GOTOOLCHAIN=auto`), bump the `go` and `toolchain` directives together.

Both of these fail loudly — a broken import path or a toolchain mismatch won't compile. Easy to fix, easy to notice. The gotcha below is the opposite: it compiles fine, runs fine most of the time, and fails silently.

## The actual gotcha: recover() eats the framework's signal

Here's roughly the shape of the code that caused the problem — a mutating tool wrapped in a defensive recover, the kind of thing that felt like due diligence carried over from 1.x:

```go
func writeRecordTool(ctx context.Context, args ToolArgs) (result *ToolResult, err error) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("tool panicked: %v", r)
            err = fmt.Errorf("internal error")
        }
    }()

    // ... does the actual write ...
    return doWrite(ctx, args)
}
```

This looks responsible. It isn't, under ADK 2.0's execution model. In 2.0, the framework relies on the panic or error propagating *out* of the tool call to know that something went wrong — that signal is what drives the node-level `RetryConfig` (deciding whether to retry the tool call) and what drives the HITL confirmation pause (deciding whether to hold execution for a human's approve/deny). A broad `recover()` that swallows the panic and converts it into a quiet log line, or that maps every failure mode into the same generic error, breaks both of those mechanisms at once:

- **Retries silently stop happening.** The framework never sees the failure signal it was watching for, so it never re-enters the retry path. The tool just "completes" from the framework's point of view, and the caller keeps going as if it had succeeded — or gets a downstream error days later that has nothing to do with the actual cause.
- **HITL confirmation gets bypassed.** If the panic happens in a code path that runs *before* or *during* the confirmation gate's bookkeeping, the recover can eat the exact event ADK uses to know a mutating tool is waiting on human approval. The practical effect: a tool that's supposed to require a human's approve/deny can end up running, or ending, without ever surfacing the prompt — and nothing in the logs tells you that happened. `<!-- VERIFY -->` (exact mechanism of interaction between panic recovery and the confirmation gate's internal state — confirmed as a real 2.0 behavior, but I haven't traced the exact internal code path in the framework source.)

The nasty part is that everything looks healthy. No error in the aggregate logs, no crash, no alert. Just retries that don't happen and confirmations that don't fire — the kind of absence that's very hard to grep for.

## The fix: errors as values, all the way through

The idiomatic Go answer is the boring one: don't recover, return errors. Thread `context.Context` properly, return `(*ToolResult, error)` from every tool, and let the framework's own machinery — `RetryConfig` at the node level, the confirmation flow around `functiontool.Config{RequireConfirmation: true}` — do the job it was built for.

```go
func writeRecordTool(ctx context.Context, args ToolArgs) (*ToolResult, error) {
    result, err := doWrite(ctx, args)
    if err != nil {
        return nil, fmt.Errorf("write record: %w", err)
    }
    return result, nil
}
```

No defer, no recover, no swallowed signal. If `doWrite` panics on something truly unexpected (a nil pointer, a slice out of range), let it propagate — that's a bug to fix, not a condition to paper over with a generic error string. The framework's retry and confirmation logic is designed around seeing real failures; hiding them from it doesn't make the system more robust, it just moves the failure somewhere less visible.

If there's ever a genuine need for `recover()` in a tool — wrapping a flaky third-party library that panics on bad input, say — keep it narrow and re-panic anything you don't specifically expect and handle:

```go
defer func() {
    if r := recover(); r != nil {
        if pe, ok := r.(expectedPanicType); ok {
            err = fmt.Errorf("known failure mode: %w", pe.Unwrap())
            return
        }
        panic(r) // don't swallow what you don't understand
    }
}()
```

That's a narrow catch for one named failure mode, not a blanket safety net around the whole function body. The difference matters: a blanket `recover()` optimizes for "the tool never crashes the process," which sounds safe but actually means "the framework never finds out anything went wrong" — and in a system where retries and human confirmation both depend on that signal, that's the opposite of safe.

## Takeaway

If you're migrating a tool-heavy ADK Go codebase from 1.x to 2.0, grep for `recover()` inside anything registered as a tool before you ship. The import path and Go version bumps will fail your build if you get them wrong. This one won't — it'll just quietly turn off retries and HITL for whatever tool has it, and you'll find out the hard way, probably from a support ticket about a write that should have needed approval and didn't.
