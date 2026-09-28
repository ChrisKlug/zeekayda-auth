# Principles the walkthrough surfaced

Patterns the maintainer holds that apply beyond one spot. Each is a rule new code follows and a
finding when existing code breaks it. When a principle becomes enforced by a coding standard or a
register entry, it moves there and this line points at it.

- **One convention for a kind of thing, everywhere.** The same shape of collection (type and
  setter) on every options property and public member; the same naming for the same concept; the
  same structure for the same kind of rule. A reader should never have to learn two ways.
- **Anything we can build, a third party can build, and the right way is the easy way.** A
  framework seam is used by the framework's own implementations through the same public path a third
  party would use.
- **Untrusted extension output is made safe one layer below the code that uses it**
  (`ValidatedClientResolver`, `CompositeClientAuthenticator`), so the rest of the framework never
  handles a wonky third-party value.
- **A name or a structure before a comment.** A comment says a *why* the code cannot; one standing in
  for a rename, an extraction or better cohesion is a finding.
- **Pass in what a method works on.** A method that runs a set of things takes them as a parameter,
  even when it could reach them itself, so the call site says what it runs.
- **Options are the host's input, never rewritten.** Anything derived from them (a canonical form,
  a default applied because nothing was set) lives where it is used, not back on the options.
- **Options are plain data carriers.** Behaviour on them, such as validation, is an internal
  extension method in a sibling file.
- **Validation is top-down and returns its errors.** Each level checks itself and asks its
  children; the parent coordinates rules that span its children, named by topic. Methods return
  their errors rather than filling a list passed in; an accumulator is used only where a public seam
  reports more than one kind of outcome.
- **No service locator in a public contract.** Dependencies are declared in constructors, and the
  framework arranges the scope.
- **Internal classes built by DI use primary constructors, with no null checks.** Public members a
  third party calls keep their guards. Recorded in `.claude/agents/developer.md`.
