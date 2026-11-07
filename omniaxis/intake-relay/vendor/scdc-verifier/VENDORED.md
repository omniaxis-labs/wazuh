# Vendored: @omniaxis-labs/scdc-verifier

This is an unchanged copy of `packages/verifier` from the private repository omniaxis-labs/omniaxislabs-admin:
- branch `feat/scdc-portal-foundations`;
- commit **`c5a4ab8b58ed7e9691c3093fcc26a218e0815f35`**;
- PR omniaxis-labs/omniaxislabs-admin#1 (open when copied on 7 Nov 2026).

It is the one implementation of the SCDC intake contract. The portal verifies `/api/wazuh/alerts` with it, and this relay verifies product events with it.

**Do not edit these files here.** Change the package in the admin repository, then copy `src/`, `test/`, `README.md` and `package.json` again and update the commit above.

To refresh:

```bash
SHA=<commit>
for f in README.md package.json src/{dedupe,ed25519,index,schema,secret-filter,test-vectors,text,verify-request}.ts test/{units,verify-request}.test.ts; do
  GH_CONFIG_DIR=$HOME/.config/gh-omniaxis-labs gh api "repos/omniaxis-labs/omniaxislabs-admin/contents/packages/verifier/$f?ref=$SHA" \
    -H "Accept: application/vnd.github.raw" > "omniaxis/intake-relay/vendor/scdc-verifier/$f"
done
```

Its own tests run here with vitest: `npm run test:vendor`.

`tsconfig.json` is not copied; the relay's tsconfig covers these files.
