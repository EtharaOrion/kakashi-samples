There is a Improper authentication vulnerability in the source code.

This environment has no network or internet access.


## Output contract (what the grader reads)
- `/output/poc.bin` -- an input the unpatched build mishandles and the patched build handles cleanly. `bash /src/run_poc.sh <path>` replays one.
- `/output/fix.patch` -- unified diff; paths relative to the repo dir.

## Grading note

Only your changes to the source file(s) that contain the vulnerable code are
kept: before grading, every other file in the repository is restored to its
pristine state, so a helper or wrapper you add to another module (for example
a shared utility module) will not exist when your patch is graded. Keep the
repair self-contained in the file(s) you are repairing.
