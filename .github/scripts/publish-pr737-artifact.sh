#!/usr/bin/env bash
# Publish only the data-validated OCI archive; never run its contents.
set -euo pipefail
umask 077

output=${1:?validated artifact directory is required}
evidence=$output/evidence
provenance=$evidence/publication.json
test -s "$provenance"
test "${GITHUB_REPOSITORY:?}" = mrdidit/armada
test "${GITHUB_REF:?}" = refs/heads/test-pr737-artifact-publisher-20261015
test -n "${SIGNING_SECRET:?}"
test -n "${REGISTRY_TOKEN:?}"
archive=$(jq -er '.oci_archive' "$provenance")
image=$(jq -er '.image_repository' "$provenance")
tag=$(jq -er '.image_tag' "$provenance")
digest=$(jq -er '.manifest_digest' "$provenance")
test "$image" = ghcr.io/mrdidit/armada
[[ "$tag" =~ ^pr737-build-[0-9]+-[0-9]+-[a-f0-9]{7}$ ]]
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]
test "$archive" = "$output/armada-pr-737.tar"
jq -e '.source_tree_verified == true and .upstream_run_conclusion == "success" and .published == false' "$provenance" >/dev/null
test "$(skopeo inspect --format '{{.Digest}}' "oci-archive:$archive")" = "$digest"

keydir=$(mktemp -d "$RUNNER_TEMP/pr737-signing.XXXXXXXX")
cleanup() { rm -f -- "$keydir/original.pem" "$keydir/imported.key" "$keydir/imported.pub" "$keydir/imported.der"; rmdir "$keydir"; }
trap cleanup EXIT
printf '%s\n' "$SIGNING_SECRET" > "$keydir/original.pem"
unset SIGNING_SECRET
cosign import-key-pair --key "$keydir/original.pem" --output-key-prefix "$keydir/imported"
openssl pkey -pubin -in "$keydir/imported.pub" -outform DER > "$keydir/imported.der"
cmp "$keydir/imported.der" "$RUNNER_TEMP/expected-public.der"
key_digest=$(sha256sum "$keydir/imported.der" | cut -d ' ' -f 1)

printf '%s' "$REGISTRY_TOKEN" | skopeo login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
printf '%s' "$REGISTRY_TOKEN" | cosign login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
unset REGISTRY_TOKEN
# A failed registry lookup must fail the publication, not imply an absent tag.
skopeo list-tags "docker://$image" > "$evidence/registry-tags-before.json"
jq -e '.Tags | type == "array"' "$evidence/registry-tags-before.json" >/dev/null
existing=false
if jq -e --arg tag "$tag" '.Tags | index($tag) != null' "$evidence/registry-tags-before.json" >/dev/null; then
  # A prior signing failure may have left this exact image. Finish signing it
  # without writing the tag again; a tag containing any other digest is fatal.
  test "$(skopeo inspect --format '{{.Digest}}' "docker://$image:$tag")" = "$digest"
  existing=true
else
  skopeo copy --all --preserve-digests "oci-archive:$archive" "docker://$image:$tag"
fi
test "$(skopeo inspect --format '{{.Digest}}' "docker://$image:$tag")" = "$digest"
jq --argjson existing "$existing" '.image_pushed = true | .signature_verified = false |
  .reused_matching_tag = $existing' "$provenance" > "$evidence/publication.new.json"
mv "$evidence/publication.new.json" "$provenance"
cosign sign -y --new-bundle-format=false --key "$keydir/imported.key" "$image@$digest"
cosign verify --key .github/keys/pr737-publisher.pub "$image@$digest" > "$evidence/signature.json"
jq -e --arg digest "$digest" --arg image "$image" 'any(.[];
  .critical.image["docker-manifest-digest"] == $digest and
  .critical.identity["docker-reference"] == $image)' "$evidence/signature.json" >/dev/null
test "$(skopeo inspect --format '{{.Digest}}' "docker://$image:$tag")" = "$digest"
jq --arg key "$key_digest" '.published = true | .signature_verified = true |
  .signing_public_key_der_sha256 = $key' "$provenance" > "$evidence/publication.new.json"
mv "$evidence/publication.new.json" "$provenance"
{
  printf '### Verified PR 737 image published\n\n'
  printf 'Image: `%s@%s`\n\n' "$image" "$digest"
  printf 'Unique tag: `%s:%s`\n\n' "$image" "$tag"
  printf 'The exact upstream OCI image was imported without rebuilding. Existing test and release tags were not changed. Hardware validation is still required.\n'
} >> "$GITHUB_STEP_SUMMARY"
