# Project: Reticulum in Haskell

## What this is

A Reticulum stack written in Haskell: the wire format, the identity and
link cryptography, destinations, transport, resources, and the
interfaces a node needs to reach another node. It is a node, not a
codec.

This file is read by whoever changes the repository, not by whoever
uses it. There is no README yet. Until there is, everything a
contributor needs is here, and when a README is written, whatever it
says is deleted from this file rather than repeated. A rule written
twice is a rule that can disagree with itself.

Three words are used throughout and are defined once.

    the reference    python-rns 1.4.2, commit
                     b48b96e61676504e0a4e527b33b9a0b4495c6872,
                     openssl backend

    the corpus       LeonhardWeiler/reticulum-vectors, the vector
                     corpus generated from that pin, at the commit
                     named in CORPUS

    a peer           any other Reticulum implementation this one has to
                     talk to, named or not

Compatible means identical to the reference at that pin. That is the
right definition for interoperability and the wrong one for
correctness, and it is chosen with that known.

---

# The Order of Work

The layers are built in the order the bytes require, and each one is
checked against the corpus before the next one starts:

    identity, keyset        hashes and the two curves
    destination             the name rules
    packet, announce        the header and the signature
    link                    the handshake, the token, the proofs
    resource                segmentation and the hashmap
    transport               paths, hops, the tables
    interface               sockets, and the first two other nodes

Nothing above a layer is written while a vector below it fails. The
corpus stops at link and resource; from transport upwards the evidence
is a peer, and there is less of it. That is a reason to reach transport
with everything below it proved, not a reason to hurry through the
part that can be proved.

---

# The Corpus Is the Test Suite

The corpus decides whether this implementation reads and writes what
the reference does. It is neither vendored here nor assumed to be
sitting beside this repository: it is fetched, at a commit this
repository names, by the same command a human and CI both run.

    ./check

That script clones the corpus into `.corpus/` if it is not there,
checks out the commit named in the file `CORPUS`, builds `cmd/dump`,
builds the harness, and runs `cmd/check` against it. `.corpus/` is
ignored by git. Nothing has to be installed for it beyond a C compiler
and a POSIX shell, and nothing else in this repository needs it: a
build of the node never touches the corpus.

`CORPUS` holds the pin, and it is the only place the pin is written:

    commit        <40 hex digits>
    fingerprint   <what cmd/check prints on the result line>

Both lines are load-bearing. The commit is what is checked out; a
floating clone measures a different corpus next week without saying so.
The fingerprint is the corpus's own checksum over its vectors, printed
with every result, and `./check` refuses a result whose fingerprint is
not the one on file. That is what makes the second line worth having:
it catches a corpus that is not what `CORPUS` claims, whichever way it
got there.

    CORPUS_DIR=../reticulum-vectors ./check

is the one override, for working on both repositories at once. It skips
the fetch and uses the checkout as it stands, so the fingerprint check
is the only thing that still says which corpus produced the number.

In CI, the same script. `conformance/example/vectors.yml` in the corpus
is its own workflow to copy, and what that file does — clone at a
pinned commit, build, run — is what `./check` already does, so the
workflow here is a checkout, `nix develop`, and one line. It is copied
and not depended on: nothing in the corpus is published as an
interface, and nothing there may change under this repository.

Two things about the run, both from the corpus and both easy to lose:

    `cmd/check` exits 2 when it could not measure anything at all. That
    is not a pass and not a failure of this implementation, and a build
    log that cannot tell it from a green run reports "nothing was
    checked" as success.

    A step runs under `bash -e` without `pipefail`, and the exit status
    of a pipeline is its last command's. A verdict piped anywhere is a
    verdict read from `tee`.

`harness` is one program in this repository that takes the two
arguments `cmd/dump` takes and prints the same field lines by calling
this implementation's own code. `doc/harness` in the corpus is the
whole of what it must do; its six rules are not copied here. Three of
them decide things about this repository and so are repeated as
consequences rather than as rules:

    A field this implementation does not compute is a dash, and the
    dash is the measurement. The harness never supplies a rule the
    library is missing, and never reaches past the library to compute
    one by hand.

    A kind not yet implemented exits 77. Four kinds on the first day is
    a result.

    Nothing in the library writes to standard output. The field stream
    is standard output; a log line goes to standard error or nowhere.

Every harness written for the corpus so far runs with `ENCODE=no`,
because none of them can write packets. This one can, or it is not a
node. The encode direction is therefore a target and not an
exemption: `ENCODE=no` is where a kind starts, not where it ends.

A test in this repository that duplicates a vector is deleted. What
belongs here instead is what the corpus cannot hold: a property that
must be true for every input rather than for a hundred and four of
them, and the layers above link that have no vectors at all.

---

# Dependencies

    base, bytestring, containers, and one cryptography library.

That is the whole set that needs no argument. Everything else earns its
place one line at a time, in a file named `DEPENDS`, which says which
package, and what could not be written without it:

    network      the TCP and UDP interfaces; base has no sockets

The rules behind that file:

    A dependency is justified by something that has to work, never by
    convenience of expression.

    No dependency for what base already does.

    No test framework, no logging framework, no effect system, no lens.
    A log line is a call to hPutStrLn stderr.

    Cryptography is not written here. Ed25519, X25519, AES-256-CBC,
    SHA-256, SHA-512, HMAC and HKDF come from the one library, and the
    corpus is what says they are the right ones.

A node needs I/O that base does not have, so the set above will grow on
the interface layer and nowhere else. When it does, `DEPENDS` gains a
line and the diff shows the layer that forced it.

---

# Haskell

The language has a large end and a small one, and only the small one is
used here.

    Extensions are listed per file, never in default-extensions. A
    reader of one module sees what that module needs.

    A typeclass with one instance is a record with ceremony. Write the
    record. An interface is a value holding functions, not a class with
    a phantom parameter.

    No type-level programming. A byte string of the wrong length is
    caught by the corpus, and a type that proves the length costs more
    to read than the check it replaces.

    No monad transformer stack. The codec is pure; the node is IO. A
    third thing between them is a fourth thing to debug.

Types, on the wire path:

    Strict ByteString, always. Not String, not Text, not lazy. A
    destination name is arbitrary bytes, and Text cannot hold one.

    A newtype where two values of the same shape can be swapped by
    mistake: an identity hash and a destination hash are both sixteen
    bytes and mean different things. Elsewhere ByteString. The newtype
    is there to stop a bug the corpus would report as a wrong hex
    string, not to decorate.

    StrictData in every module that holds wire data. A packet field
    that is a thunk is a decoding error deferred past the place that
    could name it.

Failure:

    A decoder returns Either. It does not throw, and it does not
    return Maybe where the reference names a reason: a rejection
    carries the rule that was broken and the numbers behind it,
    because two decoders must not agree by accident while failing for
    different reasons.

    No head, no fromJust, no incomplete pattern in the codec. -Wall
    -Werror, and -Wincomplete-uni-patterns with them.

    Bound every read by the bytes actually present. Six harnesses
    written before this repository existed cut a token into iv,
    ciphertext and hmac and assumed the payload was long enough; four
    crashed and two printed an hmac overlapping its own ciphertext.
    That is the commonest defect in this problem and it is not
    specific to a language.

Concurrency, from the transport layer up:

    forkIO and STM. One thread per interface, and every thread owns
    something. A thread that only forwards is a function.

    No thread that outlives the value it serves without a way to stop
    it.

---

# Naming and Citations

A module is named after what the reference names, so that a reader
holding one can find the other:

    Reticulum.Packet    RNS/Packet.py
    Reticulum.Identity  RNS/Identity.py

Code and comments cite the reference by symbol:

    RNS/Packet.py#get_hashable_part

There is no line number. The anchor is the name to grep for, and
nothing in a citation goes stale while the pin holds. When the pin
moves, the corpus is regenerated and this implementation is measured
again.

Where the corpus documents a layout, that document is cited by its path
inside the corpus and not transcribed:

    corpus doc/announce

---

# Configuration

A value in the source is not configuration. Reticulum has constants the
reference fixes, and they are written where they are used, with the
symbol they came from beside them. They are not lifted into a settings
record so that they could be changed, because nothing may change them
and stay compatible.

What a node genuinely has to be told — which interfaces, which
addresses, which shared instance — is read once, at startup, and turned
into values. No component reads configuration; every component is
handed what it needs.

---

# Faults

A behaviour known to disagree with the reference is fixed, or the code
that has it is deleted. It is not written down and left standing. A
comment that documents a fault converts a bug into a feature of the
repository, and the next reader inherits it as one.

Where a fault cannot be fixed today, the vector that shows it fails,
and the failing count is the record. A red number is honest; a green
number with a footnote is not.

---

# Build

    nix develop
    cabal build

`flake.nix` names the compiler and `flake.lock` pins the package set;
both are committed, and a toolchain that moves without a diff is not a
pinned one. There is no second
build path: what CI runs is the two commands above and `./check`, and a
contributor runs the same three. No stack, no per-machine instructions,
nothing that works only in the pipeline, and nothing that has to exist
outside this repository before either of them starts.

A clone of this repository, a network connection and nix are the whole
of what a contributor needs. The corpus arrives through `./check`; the
reference does not arrive at all, because nothing here runs Python.

One library, and the executables a node needs. `harness` is one of
them, and it is the only one whose output format is fixed by something
outside this repository.

---

# Before Adding Anything

Ask, in order:

    Does the corpus already prove this?
    Does base already do it?
    Can a function replace a class?
    Can a value replace a knob?
    Does a running node need it, or only a reader of the code?

If the first answer is yes, stop.

The largest cost in this repository is not the protocol and not the
cryptography. It is everything written to make the protocol convenient,
and none of it is required to talk to another node. Write the node
first. What is left over after it works is the part that was never
needed.

---

# Writing Style

Short sentences. Precise definitions. Concrete byte offsets.

Prefer:

    The flags byte occupies offset 0. Bit 7 is reserved and set to zero.

Avoid:

    The packet framework provides a flexible mechanism...

A comment says what the code does and why it does it that way now. What
it did before is in git log.

Haddock on a module says what the module is for and which symbol of the
reference it follows. Haddock on a function that repeats the type
signature in English is deleted.

---

# License

The upstream license adds two restrictions to a permissive licence: no
use in systems intended to harm humans, and no use in AI or language
model training datasets. LICENSE carries them.

Following the reference and implementing it independently is
unaffected. Copying its code or its documentation text requires
attribution. The reference checkout is not committed; it is pinned and
fetched.

---

# Open Decisions

Written down rather than decided by whoever gets there first:

    Which interface comes first, and whether a shared instance is in
    scope at all before two nodes on one machine can talk.

    Whether `harness` stays here or is contributed to the corpus under
    conformance/, and therefore which repository owns the row in
    CONFORMANCE. It can be both, and then the two copies have to be
    kept agreeing, which is the reason to choose one.

    Whether `./check` is a shell script or a make target. It is written
    here as a script because there is one thing to run and a Makefile
    would be a second vocabulary for it; a Makefile is defensible once
    something else needs building outside cabal.

    Whether interoperability tests that start the reference belong in
    this repository. They need Python and a checkout, which nothing
    else here does.
