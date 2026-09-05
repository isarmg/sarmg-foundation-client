# Current mobile FFI boundary

Foundation owns ABI revision 2, panic containment, input and output bounds,
generational handles, result allocation/release, JNI Unicode validation and
exception classes. Media owns Agent DTOs, SQLite operations and the current
business state identity. There is no previous ABI reader, symbol alias, NUL input
scanner or thread-local error interface.

## C contract

Every operation accepts explicit borrowed input lengths and writable result
storage. The returned status and result status agree. A successful result has an
optional numeric value and owned bytes; failure has value zero and a bounded,
redacted UTF-8 message. Null nonempty input, misaligned output, excess lengths and
invalid UTF-8 are rejected before product work. Input is capped at 16 MiB, output
at 16 MiB and the handle registry at 4096 slots. Products can tighten input limits.
OutputBuffer bounds serializer growth before allocation, not only after encoding.

The host must release each result in its original storage with
sarmg_ffi_result_free_v2. Release resets that storage and is idempotent for the
reset result. Copying an owned result and freeing both copies is invalid. No ABI
wrapper can prove that an arbitrary nonnull foreign pointer is readable/writable;
allocation validity, alignment and non-aliasing remain explicit host obligations.

The guard catches unwinding panics as status 255. A thread-scoped panic hook
suppresses payloads while an FFI operation is active and delegates non-FFI panics
to the prior hook. The host must not replace this hook after initialization.
Abort-mode compilation is rejected; process aborts, invalid pointers and OS
termination are not recoverable Rust panics.

Handles carry slot and generation. Closed generations cannot access later objects;
exhausted generations are retired permanently, and a poisoned registry fails
closed. Product operations clone Arc handles and do not hold the registry mutex
through I/O. A call that already acquired an Arc can finish after another thread
closes the handle; new lookups fail.

## JNI and bindings

Foundation reads bounded UTF-16 and rejects unpaired surrogates rather than
silently replacing text. Invalid arguments map to IllegalArgumentException,
invalid handles to IllegalStateException, resource exhaustion to OutOfMemoryError,
and internal failures/panics to RuntimeException. Pending JVM exceptions are
preserved. JNI sentinel returns accompany exceptions; they are not success values.

tools/ffi_header.py generates the C header from the restricted current Rust ABI
declarations and rejects unsupported types. Products check the generated file
against source. Swift imports the C module, not manually redeclared symbols;
Kotlin checks the runtime ABI before other native calls. Business identity checks
remain independent of the ABI revision.

## Verification and remaining acceptance

Rust tests cover lengths, UTF-8, output ownership/budgets, stale/exhausted handles,
panic status and subprocess log redaction. Media's real Linux dynamic library is
called from a compiled C host using the generated header. The JNI suite
passes on a real Linux JVM, including a test-only Rust panic injection;
iOS simulator tests are supplied but target-native execution must be recorded
separately. Passing host Rust/C/JVM checks is not completion of Android/iOS acceptance
or the immutable release gate.
