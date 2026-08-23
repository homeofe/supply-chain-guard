# Vendored CycloneDX 1.6 JSON schemas

Unmodified copies of the official CycloneDX schemas, used by
`src/__tests__/sbom-cyclonedx-conformance.test.ts` to validate generated
documents against the real specification rather than against a hand-written
list of expected fields.

They are vendored rather than pulled from a package at test time so the
conformance test runs offline, in CI and in the Docker build, with no network
call between "the document changed" and "the check ran".

| File | Source | SHA-256 |
| --- | --- | --- |
| `bom-1.6.schema.json` | `https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json` | `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93` |
| `spdx.schema.json` | `https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/spdx.schema.json` | `baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e` |
| `jsf-0.82.schema.json` | `https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

Retrieved 2026-08-23 from the `1.6` tag of the CycloneDX specification
repository. The CycloneDX JSON schemas are published under the Apache License
2.0, the same licence this project uses.

`bom-1.6.schema.json` references the other two by their `$id`
(`http://cyclonedx.org/schema/spdx.schema.json` and
`http://cyclonedx.org/schema/jsf-0.82.schema.json`); the test registers both
with those identifiers before compiling, so no `$ref` is silently unresolved.

To refresh: re-download all three from the same tag, update the checksums above,
and re-run the conformance test. Do not hand-edit these files. A schema edited
to make a document pass is a check that can no longer fail.
