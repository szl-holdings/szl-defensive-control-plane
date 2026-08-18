#!/usr/bin/env python3
"""Publish one signed continuous container-release controller.

Temporary controller: it writes only the permanent current-main image workflow
and its versioned activation manifest to a clean branch rooted at protected
main. The generated workflow performs real local runtime smoke before a signed,
attested multi-architecture GHCR publication.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = os.environ["REPOSITORY"]
TARGET_BRANCH = os.environ["TARGET_BRANCH"]
EXPECTED_PARENT = os.environ["EXPECTED_PARENT"]
TOKEN = os.environ["GITHUB_TOKEN"]
BOT_SIGNOFF = (
    "Signed-off-by: github-actions[bot] "
    "<41898282+github-actions[bot]@users.noreply.github.com>"
)
WORKFLOW_PATH = ROOT / ".github/workflows/publish-current-main-image.yml"
MANIFEST_PATH = ROOT / ".release/container-release.json"

WORKFLOW = r'''name: Publish Current Main Container

on:
  push:
    branches: [main]
    paths:
      - .github/workflows/publish-current-main-image.yml
      - .release/container-release.json
      - Dockerfile
      - pyproject.toml
      - defensive_control_plane/**
  workflow_dispatch: {}

permissions:
  contents: read
  packages: write
  id-token: write
  attestations: write

concurrency:
  group: publish-current-main-container
  cancel-in-progress: false

jobs:
  publish:
    name: verify, smoke, publish, sign, and attest
    if: github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - name: Checkout exact protected revision
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.12'

      - name: Verify release request and source lineage
        id: metadata
        shell: bash
        run: |
          set -euo pipefail
          version="$(python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
          core_version="$(python -c 'from defensive_control_plane.core import PACKAGE_VERSION; print(PACKAGE_VERSION)')"
          manifest_version="$(jq -r '.version' .release/container-release.json)"
          schema="$(jq -r '.schema' .release/container-release.json)"
          minimum_source="$(jq -r '.minimum_source_commit' .release/container-release.json)"
          test "$schema" = 'szl.container-release-request/v1'
          test "$version" = "$core_version"
          test "$version" = "$manifest_version"
          [[ "$minimum_source" =~ ^[0-9a-f]{40}$ ]]
          git merge-base --is-ancestor "$minimum_source" "$GITHUB_SHA"
          image="ghcr.io/${GITHUB_REPOSITORY,,}"
          echo "version=$version" >> "$GITHUB_OUTPUT"
          echo "image=$image" >> "$GITHUB_OUTPUT"
          echo "tag=$image:sha-$GITHUB_SHA" >> "$GITHUB_OUTPUT"

      - name: Run complete local verification
        run: python -B verify.py

      - name: Set up Buildx
        uses: docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4.2.0

      - name: Build local amd64 image for runtime smoke
        uses: docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0
        with:
          context: .
          platforms: linux/amd64
          load: true
          push: false
          tags: local/szl-defensive-control-plane:${{ github.sha }}
          build-args: |
            SOURCE_REVISION=${{ github.sha }}
            SOURCE_VERSION=${{ steps.metadata.outputs.version }}
          provenance: false
          sbom: false

      - name: Smoke the exact local image without network access
        env:
          LOCAL_IMAGE: local/szl-defensive-control-plane:${{ github.sha }}
        run: |
          set -euo pipefail
          event_key="$(openssl rand -hex 32)"
          evidence_key="$(openssl rand -hex 32)"
          container="$(docker run -d --rm \
            --name "dcp-current-main-${GITHUB_RUN_ID}" \
            --network none \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
            -e DCP_EVENT_ROOT_KEY_HEX="$event_key" \
            -e DCP_EVIDENCE_KEY_HEX="$evidence_key" \
            -e DCP_TRUSTED_HOSTS=localhost \
            "$LOCAL_IMAGE" \
            serve --db /tmp/control-plane.sqlite3 --mode cluster-readonly \
            --host 0.0.0.0 --port 8080)"
          unset event_key evidence_key
          trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
          for attempt in $(seq 1 30); do
            if docker exec -i "$container" python - <<'PY'
          import json
          import urllib.request

          for path in ("/livez", "/readyz", "/api/build-info", "/api/lanes"):
              request = urllib.request.Request(
                  "http://127.0.0.1:8080" + path,
                  headers={"Host": "localhost"},
              )
              with urllib.request.urlopen(request, timeout=2) as response:
                  assert response.status == 200
                  payload = json.load(response)
                  if path == "/readyz":
                      assert payload["productionReady"] is False
                      assert payload["externalConnectors"] == "UNAVAILABLE"
                  if path == "/api/build-info":
                      assert payload["version"] == "${{ steps.metadata.outputs.version }}"
                      assert payload["sourceRevision"] == "${{ github.sha }}"
                      assert payload["deploymentVerified"] is False
                  if path == "/api/lanes":
                      assert payload["productionOperational"] is False
          PY
            then
              break
            fi
            test "$attempt" -lt 30
            sleep 1
          done
          docker rm -f "$container" >/dev/null
          trap - EXIT

      - name: Log in to GHCR
        uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and publish immutable multi-architecture image
        id: image
        uses: docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.metadata.outputs.tag }}
          labels: |
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.source=https://github.com/${{ github.repository }}
            org.opencontainers.image.version=${{ steps.metadata.outputs.version }}
          build-args: |
            SOURCE_REVISION=${{ github.sha }}
            SOURCE_VERSION=${{ steps.metadata.outputs.version }}
          provenance: mode=max
          sbom: true

      - name: Install cosign
        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2

      - name: Sign and verify the immutable image subject
        env:
          IMAGE: ${{ steps.metadata.outputs.image }}
          DIGEST: ${{ steps.image.outputs.digest }}
        run: |
          set -euo pipefail
          cosign sign --yes "$IMAGE@$DIGEST"
          cosign verify \
            --certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/publish-current-main-image.yml@refs/heads/main" \
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
            "$IMAGE@$DIGEST"

      - name: Attest the immutable image subject
        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-name: ${{ steps.metadata.outputs.image }}
          subject-digest: ${{ steps.image.outputs.digest }}
          push-to-registry: true

      - name: Record immutable release evidence
        env:
          IMAGE: ${{ steps.metadata.outputs.image }}
          DIGEST: ${{ steps.image.outputs.digest }}
          VERSION: ${{ steps.metadata.outputs.version }}
        run: |
          mkdir -p evidence/current-main-release
          jq -n \
            --arg schema 'SZLDefensiveControlPlaneCurrentMainImageV1' \
            --arg image "$IMAGE" \
            --arg digest "$DIGEST" \
            --arg revision "$GITHUB_SHA" \
            --arg version "$VERSION" \
            '{schema:$schema,image:$image,digest:$digest,sourceRevision:$revision,version:$version,localRuntimeSmoke:true,cosignVerified:true,provenanceAttested:true}' \
            > evidence/current-main-release/image-subject.json
          sha256sum evidence/current-main-release/image-subject.json \
            > evidence/current-main-release/SHA256SUMS

      - name: Upload immutable publication evidence
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: current-main-image-${{ github.sha }}
          path: evidence/current-main-release/
          if-no-files-found: error
          retention-days: 90
'''

MANIFEST = {
    "schema": "szl.container-release-request/v1",
    "version": "0.4.0",
    "generation": 1,
    "channel": "current-main",
    "minimum_source_commit": "2d6ffe7245b96c586f373de55de7cc9461195d1c",
    "reason": "Publish the exact current protected source as a signed, attested immutable GHCR image for downstream cluster acceptance.",
}


def request(url: str, *, data: dict[str, Any] | None = None) -> Any:
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        method="POST" if data is not None else "GET",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "szl-dcp-current-main-materializer/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:4000]
        raise SystemExit(f"GitHub HTTP {exc.code}: {body}") from exc


def main() -> int:
    WORKFLOW_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    WORKFLOW_PATH.write_text(WORKFLOW, encoding="utf-8")
    MANIFEST_PATH.write_text(
        json.dumps(MANIFEST, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    required = (
        "Build local amd64 image for runtime smoke",
        "--network none",
        "Build and publish immutable multi-architecture image",
        "cosign sign --yes",
        "cosign verify",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "retention-days: 90",
    )
    for marker in required:
        if marker not in workflow:
            raise SystemExit(f"publication contract lacks {marker}")
    forbidden = ("--admin", "force=true", "pull_request_target", "latest")
    for marker in forbidden:
        if marker in workflow:
            raise SystemExit(f"publication contract contains forbidden marker {marker}")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest != MANIFEST:
        raise SystemExit("release manifest did not round-trip canonically")
    subprocess.run(["git", "diff", "--check"], cwd=ROOT, check=True)

    paths = [
        ".github/workflows/publish-current-main-image.yml",
        ".release/container-release.json",
    ]
    mutation = """
    mutation($input: CreateCommitOnBranchInput!) {
      createCommitOnBranch(input: $input) { commit { oid url } }
    }
    """
    variables = {
        "input": {
            "branch": {
                "repositoryNameWithOwner": REPOSITORY,
                "branchName": TARGET_BRANCH,
            },
            "message": {
                "headline": "feat(release): publish signed current-main image",
                "body": BOT_SIGNOFF,
            },
            "expectedHeadOid": EXPECTED_PARENT,
            "fileChanges": {
                "additions": [
                    {
                        "path": path,
                        "contents": base64.b64encode((ROOT / path).read_bytes()).decode("ascii"),
                    }
                    for path in paths
                ]
            },
        }
    }
    payload = request(
        "https://api.github.com/graphql",
        data={"query": mutation, "variables": variables},
    )
    if payload.get("errors"):
        raise SystemExit(json.dumps(payload["errors"], indent=2))
    commit = payload["data"]["createCommitOnBranch"]["commit"]
    commit_payload = request(
        f"https://api.github.com/repos/{REPOSITORY}/commits/{commit['oid']}"
    )
    verification = commit_payload["commit"]["verification"]
    author = commit_payload["commit"]["author"]
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise SystemExit(f"target commit is not GitHub-verified: {verification}")
    if author.get("name") != "github-actions[bot]" or author.get("email") != "41898282+github-actions[bot]@users.noreply.github.com":
        raise SystemExit(f"unexpected commit author: {author}")
    if BOT_SIGNOFF not in commit_payload["commit"]["message"]:
        raise SystemExit("target commit DCO identity does not match its author")

    receipt = {
        "schema": "szl.current-main-image-materialization/v1",
        "expected_parent": EXPECTED_PARENT,
        "target_branch": TARGET_BRANCH,
        "commit": commit,
        "verification": {
            "verified": verification.get("verified"),
            "reason": verification.get("reason"),
        },
        "dco_identity": BOT_SIGNOFF,
        "changed_paths": paths,
        "local_runtime_smoke_required": True,
        "multiarch_publish_required": True,
        "cosign_required": True,
        "provenance_attestation_required": True,
        "diagnostic_controller_included": False,
        "secret_value_recorded": False,
    }
    (ROOT / "current-main-image-materialization.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
