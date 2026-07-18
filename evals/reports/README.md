# Retained evaluation reports

Files in this directory are point-in-time evidence, not universal model
benchmarks. A report is tied to an immutable BirdCode source revision, the
exact discovered model identity, the evaluator version, and the checked-in
case catalog.

The live runner reserves a new path before inference and never replaces an
existing report. Committed reports must be reviewed for credentials and local
machine inventory. BirdCode retains only the selected model evidence needed to
reproduce the decision, digests of complete discovery responses, and bounded
raw inference evidence; unrelated models and local model paths are excluded.
