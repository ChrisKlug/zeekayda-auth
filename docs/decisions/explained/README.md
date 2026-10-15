# Explained

The decision register next door records *what* was decided. These files record *what it means*:
for each subsystem, what it does, why it is shaped that way, what that costs, and what was
rejected, in plain language. Each file is signed off by the maintainer, who must be able to explain
the subsystem's public seams without the register open.

One file per subsystem, named after the register file it explains. A file lists the refactoring
issues its walkthrough raised; when one lands, the file is updated in the same PR.
