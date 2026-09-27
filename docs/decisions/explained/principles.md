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
