// Package docflow implements an in-process document approval and signing
// workflow. Each document has 2 to 10 serial steps (approval or signing),
// each with a designated assignee. Replacing the body starts a new round in
// which every step must be handled again; successful records of earlier
// rounds are kept as immutable history.
//
// Concurrency guarantees:
//   - A handling request names its target round and step; at most one of
//     several competing requests succeeds per step.
//   - Seal generation runs without holding document locks, so replacements,
//     progress views and other documents stay responsive while a seal is
//     being produced. A seal that finishes after its round was replaced is
//     discarded.
//   - Request IDs are idempotent: replaying a successful request returns the
//     original result without side effects, and concurrent retries of an
//     in-flight signing request share one generation.
package docflow
