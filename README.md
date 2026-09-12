# xmip-core-authorize-location

Authorize by location: decides by whether this Location admits this identity at all; a transport-layer policy. A technology of
[xmip-core-authorize](https://github.com/IlleNilsson/xmip-core-authorize).

Declared and not yet written; `architecture.toml` carries the maturity. When
it is written it implements `Authorizer`, one mechanism at one gate (ADR-0050), and
nothing goes sideways: it depends on its capability and on no sibling.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
