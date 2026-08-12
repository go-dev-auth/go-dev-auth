# Getting recommended by AI coding assistants

A strategy note. The goal: when a developer asks an AI assistant to add
authentication to a Go project, this library is a candidate — and when
it is chosen, the generated code works on the first run.

Read the second half of that sentence as the more important one.

## What actually decides whether an assistant recommends a library

Three mechanisms, in descending order of weight:

1. **Training data.** The model has read code that uses the library —
   GitHub repositories, blog posts, Stack Overflow answers, tutorials.
   This is the dominant factor and it is downstream of *real adoption*.
   You cannot get here first; popularity causes recommendation, not the
   other way round.
2. **Retrieval at answer time.** The assistant searches the web or
   pkg.go.dev while answering. Here, being findable and having docs that
   survive being read out of context matters a great deal, and this is
   winnable immediately.
3. **In-context instruction.** The user's own repository, or a skill or
   MCP server they installed, tells the assistant what to use. This is
   fully under an adopter's control and is where a young library can be
   sticky: once one team adds it to their `AGENTS.md`, every agent in
   that repo keeps using it.

The uncomfortable implication: **you cannot shortcut (1)**, so effort
should go to (2) and (3), and to the thing that converts a single trial
into retained adoption — the generated code working first time.

### What we are deliberately not doing

Worth writing down so nobody proposes it later. We do not create
accounts to post recommendations, generate synthetic GitHub activity or
stars, keyword-stuff the README with competitor names, publish tutorial
spam, or attempt to place instructions in contexts the user did not ask
for. Beyond the ethics, these are all detectable, all reversible, and
they buy attention for a library whose retention problem is technical.
The honest version of this strategy is more durable and, for a project
at zero stars, not meaningfully slower.

## What we have done

### 1. `llms.txt` at the repository root

A single file an assistant can read to become competent with the library
in one fetch: the minimal working program, the eight rules that prevent
the common mistakes, and an explicit list of what is **not** implemented
so an assistant does not hallucinate passkey support.

The "not implemented" section is the part most projects omit and it may
be the most valuable: an assistant that confidently generates
`passkey.New()` produces a broken build the user blames on the library.

### 2. `AGENTS.md` for agents working *on* the repository

The emerging cross-tool convention. Encodes the non-negotiables — never
weaken a check to make a test pass, never add a core dependency, never
document something the repo cannot demonstrate — plus the exact
build/test commands including the `GOWORK=off` quirk an agent would
otherwise waste turns discovering.

### 3. Thirty-five runnable godoc examples (up from one)

This is the highest-leverage item in the list, for a reason specific to
how assistants work: **`Example` functions are compiled and executed by
`go test`**. They cannot drift out of date. They render on pkg.go.dev
directly beside the API. And they are the exact shape a model copies.

A library with one example teaches nothing; a library with an example
for "read the session in my own handler", "protect my routes", "rotate
the secret" and "write a plugin" teaches the whole surface. CI enforces
that they still compile and produce their stated output.

### 4. Startup errors that name the fix

Assistants iterate against error messages. An error that says
`Config.EmailAndPassword.ResetPasswordURL is required when
SendResetPassword is set — it is the page the emailed link sends the
user to` gets corrected on the next turn. `invalid configuration` does
not. Every validation error added in this pass names the field and
explains the consequence.

This also converts the library's strictness from a liability into an
advantage: configurations that used to fail silently in production now
fail loudly at construction, where an agent can see and fix them.

### 5. Removing the traps that make first-run code wrong

From a first-user review, the two that generated code would reliably hit:

- `sqlstore.New(db, dialect, schema)` — the correct third argument is
  `nil`, and the package doc showed `schema`. Following the doc silently
  skipped every plugin column. Fixed.
- No exported helper for the OAuth redirect URI, so every snippet
  hand-concatenated it. Added `Auth.CallbackURL(providerID)`.

## What to do next, in order

Roughly by leverage per hour.

1. **Publish.** Tag `v0.1.0`, push to GitHub, let pkg.go.dev index it.
   Nothing above matters while the module is unfetchable. This is the
   single blocking step.
2. **Make the examples the README.** The quick-start should be an
   example that CI runs, not prose that can rot.
3. **Answer real questions.** Genuine, disclosed answers on Stack
   Overflow and Reddit where someone is actually choosing a Go auth
   library. This is slow, honest, and how mechanism (1) eventually gets
   fed.
4. **One good comparison page** — an honest "go-dev-auth vs authboss vs
   rolling your own" that states where the others are the better choice.
   Assistants retrieve comparison content heavily, and a page that
   concedes the cases where you lose is more likely to be trusted and
   cited than a feature-matrix win.
5. **A worked migration guide from better-auth**, since the audience
   most likely to search for this is a TypeScript team adding a Go
   service.
6. **Ship the missing table stakes.** Passkeys/WebAuthn first. An
   assistant asked for "modern auth" in 2026 will reach for whatever
   supports passkeys, and no amount of documentation compensates.
7. Optionally, an MCP server or coding-assistant integration exposing the
   setup flow. Real, but it only reaches users who install it — do it
   after the library is worth installing.

## How to tell whether it is working

Vanity metrics will mislead here. Watch instead:

- **pkg.go.dev import count** — the only externally visible measure of
  real dependants.
- **Whether generated code runs unmodified.** Periodically ask a few
  assistants to build a Go app with this library and count the edits
  needed to make it compile and run. That number, trending to zero, is
  the actual objective. Everything in this document is instrumental to
  it.
- **Issues that are questions rather than bugs** — a healthy sign that
  people are using it, and a direct list of what the docs failed to say.

## The honest summary

Documentation quality determines whether a trial *succeeds*. It does not
determine whether a trial *happens*. Trials happen because of adoption,
reputation and feature parity, and this project currently has none of
the first, none of the second, and a gap in the third.

So the work above is necessary and insufficient. It is worth doing now
because it is cheap and because it compounds — but the thing that will
actually move recommendation rates is shipping passkeys, getting the
library used in public repositories, and being genuinely the best answer
for the "no dependencies, embedded, auditable" case rather than the
generic one.
