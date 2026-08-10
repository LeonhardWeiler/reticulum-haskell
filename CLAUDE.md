# Reticulum in Haskell

A Reticulum node: wire format, identity and link cryptography,
destinations, transport, resources, interfaces.

    the reference   python-rns 1.4.2, commit
                    b48b96e61676504e0a4e527b33b9a0b4495c6872,
                    openssl backend
    the corpus      LeonhardWeiler/reticulum-vectors, at the commit
                    named in CORPUS

Compatible means identical to the reference at that pin.

---

# Order of Work

    identity, keyset      hashes and the two curves
    destination           the name rules
    packet, announce      the header and the signature
    link                  handshake, token, proofs
    resource              segmentation and the hashmap
    transport             paths, hops, tables
    interface             sockets

Nothing above a layer is written while a vector below it fails.

---

# The Corpus

    ./check

Clones the corpus into `.corpus/` at the commit in `CORPUS`, builds it,
builds the harness, runs its `cmd/check`. `.corpus/` is gitignored. CI
runs the same script.

`CORPUS` holds the pin and is the only place it is written:

    commit        <40 hex digits>
    fingerprint   <the corpus number printed on the result line>

`./check` refuses a result whose fingerprint is not the one on file.

    CORPUS_DIR=../reticulum-vectors ./check

skips the fetch and uses that checkout as it stands.

`harness` takes the arguments the corpus's `cmd/dump` takes and prints
the same field lines from this implementation's own code. `doc/harness`
in the corpus is the contract. Three of its rules bind this repository:

    A field this implementation does not compute is a dash. The
    harness never computes one on the library's behalf.

    A kind not implemented exits 77.

    Nothing in the library writes to standard output. Log lines go to
    standard error.

`cmd/check` exits 2 when it measured nothing, and a pipeline needs
`pipefail` or the verdict comes from `tee`.

`ENCODE=no` is where a kind starts, not where it ends: a node writes
packets.

A test here that duplicates a vector is deleted. What belongs here is
what the corpus cannot hold: properties, and the layers above link.

---

# Dependencies

    base, bytestring, containers, one cryptography library

Anything else earns a line in `DEPENDS` naming what needs it:

    network      the TCP and UDP interfaces

No test framework, no logging framework, no effect system, no lens.
Cryptography is not written here.

---

# Haskell

    Extensions per file, never in default-extensions.
    A typeclass with one instance is a record. Write the record.
    No type-level programming. No monad transformer stack.
    The codec is pure. The node is IO.

Wire path:

    Strict ByteString. Not String, not Text, not lazy.
    StrictData wherever wire data is held.
    A newtype where two values of the same shape can be swapped:
    an identity hash and a destination hash are both sixteen bytes.

Failure:

    A decoder returns Either and does not throw. A rejection carries
    the rule broken and the numbers behind it.
    No head, no fromJust, no incomplete pattern.
    -Wall -Werror -Wincomplete-uni-patterns.
    Bound every read by the bytes present.

Threads:

    forkIO and STM. One thread per interface. Every thread owns
    something and can be stopped.

---

# Names and Citations

    Reticulum.Packet    RNS/Packet.py

The reference is cited by symbol, never by line number:

    RNS/Packet.py#get_hashable_part

A corpus document by path: corpus `doc/announce`.

---

# Configuration

Constants the reference fixes are written where they are used, beside
the symbol they came from. They are not settings.

What a node has to be told is read once at startup and turned into
values. No component reads configuration.

---

# Faults

A behaviour known to disagree with the reference is fixed, or the code
is deleted. It is not written down and left standing. Until it is
fixed, the vector fails and the count is the record.

---

# Build

    nix develop
    cabal build
    ./check

Nix is the only thing that has to be installed; the shell carries every
program the three commands run. Both `./check` and cabal need a
network. `flake.nix` names the compiler, `flake.lock` pins the package
set, both committed.

A `packages` output around `callCabal2nix` belongs in the flake once
`reticulum.cabal` exists.

One library, and the executables a node needs.

---

# Before Adding Anything

    Does the corpus already prove this?
    Does base already do it?
    Can a function replace a class?
    Can a value replace a knob?
    Does a running node need it, or only a reader of the code?

If the first answer is yes, stop.

---

# Writing

Short sentences. Concrete byte offsets. This file, a README and a
comment are one discipline: say the thing, then stop.

Comments are rare and the default is none. A comment carries what the
code cannot: where a constant came from, an order that looks arbitrary
and is not, a case got wrong once. Not why one choice was made over
another. Not the name above it, restated. When in doubt, delete it.

Haddock is not exempt. A module names the reference symbol it follows.
A function with a type and a name needs no sentence rewriting them.

git log holds what the code did before. A commented-out line is
nothing.

---

# License

Reticulum's licence and its two restrictions are in LICENSE. Copying
upstream code or documentation text requires attribution. The reference
checkout is not committed.

---

# Open

    Which interface comes first.
    Whether harness lives here or in the corpus under conformance/.
    Whether tests that start the reference belong here at all.
