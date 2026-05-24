# Rust Microservices Authentication Demo

A Rust microservices project built as part of a course, then heavily modified and expanded beyond the original implementation. The project demonstrates a small gRPC-based authentication system using `tonic`, `tokio`, Protocol Buffers, password hashing, and separate service/client binaries.

## Overview

This workspace contains three Rust binaries:

- `auth`: a gRPC authentication service.
- `client`: a CLI client for calling the authentication service.
- `health-check`: a small worker that repeatedly exercises the auth flow.

The service supports:

- User sign-up
- User sign-in
- User sign-out
- Password hashing with PBKDF2
- UUID-based user IDs
- UUID-based session tokens
- gRPC API generation from Protocol Buffers

All state is currently stored in memory, so users and sessions are reset when the auth service restarts.

## Workspace Structure

```text
.
├── auth/              # gRPC authentication service
├── client/            # CLI client for auth operations
├── health-check/      # Repeating auth flow checker
├── proto/             # Protocol Buffer definitions
├── Cargo.toml         # Rust workspace manifest
└── Cargo.lock
```

## gRPC API

The API is defined in `proto/authentication.proto`.

```proto
service Auth {
  rpc SignUp(SignUpRequest) returns (SignUpResponse);
  rpc SignIn(SignInRequest) returns (SignInResponse);
  rpc SignOut(SignOutRequest) returns (SignOutResponse);
}
```

## Requirements

- Rust, using the 2024 edition
- Cargo
- Protocol Buffers tooling compatible with `tonic-prost-build`

## Running The Project

Start the authentication service:

```bash
cargo run -p auth
```

By default, the service listens on:

```text
[::0]:50051
```

Run the CLI client in another terminal.

Sign up:

```bash
cargo run -p client -- sign-up --username alice --password secret
```

Sign in:

```bash
cargo run -p client -- sign-in --username alice --password secret
```

Sign out:

```bash
cargo run -p client -- sign-out --session-token <SESSION_TOKEN>
```

The client connects to `[::0]:50051` by default. To target a different host, set:

```bash
AUTH_SERVICE_IP=<host>
```

Run the health-check worker:

```bash
cargo run -p health-check
```

The health-check process repeatedly creates a random user, signs in, signs out, and prints the response statuses every few seconds.

To target a different auth host for the health-check worker, set:

```bash
AUTH_SERVICE_HOST_NAME=<host>
```

## Testing

Run the test suite:

```bash
cargo test
```

The tests cover user creation, duplicate usernames, password verification, session creation/deletion, and the main auth service flows.

## Implementation Notes

- The project uses `tonic` for gRPC transport.
- Protobuf code is generated at build time from `proto/authentication.proto`.
- Passwords are hashed with PBKDF2 before being stored.
- Users and sessions are stored in in-memory `HashMap`s.
- The project is intentionally small and educational, but structured as a multi-binary workspace to explore service boundaries.

## Course Context

This repository started as part of a course project, but has been substantially changed and extended. It should be treated as a personal learning project and exploration of Rust microservice patterns rather than a direct copy of the original course material.
