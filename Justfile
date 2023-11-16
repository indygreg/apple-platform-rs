default:
  cargo build

exe_suffix := if os() == "windows" { ".exe" } else { "" }

tar := if os() == "macos" { "gtar" } else { "tar" }

macosx_deployment_target := if os() == "macos" {
  if arch() == "arm" {
    "11.0"
  } else {
    "10.9"
  }
} else {
  ""
}

actions-bootstrap-rust-linux:
  sudo apt install -y --no-install-recommends libpcsclite-dev musl-tools

actions-bootstrap-rust-macos:

actions-bootstrap-rust-windows:

# Trigger a workflow on a branch.
ci-run workflow branch="ci-test":
  gh workflow run {{workflow}} --ref {{branch}}

# Trigger all workflows on a given branch.
ci-run-all branch="ci-test":
  just ci-run rcodesign.yml {{branch}}
  just ci-run sphinx.yml {{branch}}
  just ci-run workspace.yml {{branch}}

_remote-sign-exe ref workflow run_id artifact exe_name rcodesign_branch="main":
  gh workflow run sign-apple-exe.yml \
    --ref {{ref}} \
    -f workflow={{workflow}} \
    -f run_id={{run_id}} \
    -f artifact={{artifact}} \
    -f exe_name={{exe_name}} \
    -f rcodesign_branch={{rcodesign_branch}}

# Trigger remote code signing workflow for rcodesign executable.
remote-sign-rcodesign ref run_id rcodesign_branch="main": (_remote-sign-exe ref "rcodesign.yml" run_id "exe-rcodesign-macos-universal" "rcodesign" rcodesign_branch)

# Obtain built executables from GitHub Actions.
assemble-exe-artifacts exe commit dest:
  #!/usr/bin/env bash
  set -exo pipefail

  RUN_ID=$(gh run list \
    --workflow {{exe}}.yml \
    --json databaseId,headSha | \
    jq --raw-output '.[] | select(.headSha=="{{commit}}") | .databaseId' | head -n 1)

  if [ -z "${RUN_ID}" ]; then
    echo "could not find GitHub Actions run with artifacts"
    exit 1
  fi

  echo "GitHub run ID: ${RUN_ID}"

  gh run download --dir {{dest}} ${RUN_ID}

_codesign-exe in_path:
  rcodesign sign \
    --remote-public-key-pem-file ci/developer-id-application.pem \
    --code-signature-flags runtime \
    {{in_path}}

_codesign in_path out_path:
  rcodesign sign \
    --remote-public-key-pem-file ci/developer-id-application.pem \
    {{in_path}} {{out_path}}

# Notarize and staple a path.
notarize path:
  rcodesign notarize \
    --api-issuer 254e4e96-2b8b-43c1-b385-286bdad51dba \
    --api-key 8RXL6MN9WV \
    --staple \
    {{path}}

_tar_directory source_directory dir_name dest_dir:
  {{tar}} \
    --sort=name \
    --owner=root:0 \
    --group=root:0 \
    --mtime="2022-01-01 00:00:00" \
    -C {{source_directory}} \
    -cvzf {{dest_dir}}/{{dir_name}}.tar.gz \
    {{dir_name}}/

_zip_directory source_directory dir_name dest_dir:
  #!/usr/bin/env bash
  set -exo pipefail

  here=$(pwd)

  cd {{source_directory}}
  zip -r ${here}/{{dest_dir}}/{{dir_name}}.zip {{dir_name}}

_release_universal_binary project tag exe:
  mkdir -p dist/{{project}}-stage/{{project}}-{{tag}}-macos-universal
  rcodesign macho-universal-create \
    --output dist/{{project}}-stage/{{project}}-{{tag}}-macos-universal/{{exe}} \
    dist/{{project}}-stage/{{project}}-{{tag}}-aarch64-apple-darwin/{{exe}} \
    dist/{{project}}-stage/{{project}}-{{tag}}-x86_64-apple-darwin/{{exe}}
  cp dist/{{project}}-stage/{{project}}-{{tag}}-aarch64-apple-darwin/COPYING \
    dist/{{project}}-stage/{{project}}-{{tag}}-macos-universal/COPYING

_create_shasums dir:
  #!/usr/bin/env bash
  set -exo pipefail

  (cd {{dir}} && shasum -a 256 *.* > SHA256SUMS)

  for p in {{dir}}/*.*; do
    if [[ "${p}" != *"SHA256SUMS" ]]; then
      shasum -a 256 $p | awk '{print $1}' > ${p}.sha256
    fi
  done

_upload_release name title_name commit tag:
  gh release create \
    --prerelease \
    --target {{commit}} \
    --title '{{title_name}} {{tag}}' \
    --discussion-category general \
    {{name}}/{{tag}}
  gh release upload --clobber {{name}}/{{tag}} dist/{{name}}/*

_release name title_name:
  #!/usr/bin/env bash
  set -exo pipefail

  COMMIT=$(git rev-parse HEAD)
  TAG=$(cargo metadata \
    --manifest-path {{name}}/Cargo.toml \
    --format-version 1 \
    --no-deps | \
      jq --raw-output '.packages[] | select(.name=="{{name}}") | .version')

  just {{name}}-release-prepare ${COMMIT} ${TAG}
  just {{name}}-release-upload ${COMMIT} ${TAG}

apple-codesign-release-prepare commit tag:
  #!/usr/bin/env bash
  set -exo pipefail

  rm -rf dist/apple-codesign*
  just assemble-exe-artifacts rcodesign {{commit}} dist/apple-codesign-artifacts

  for triple in aarch64-apple-darwin aarch64-unknown-linux-musl i686-pc-windows-msvc x86_64-apple-darwin x86_64-pc-windows-msvc x86_64-unknown-linux-musl; do
    release_name=apple-codesign-{{tag}}-${triple}
    source=dist/apple-codesign-artifacts/exe-rcodesign-${triple}
    dest=dist/apple-codesign-stage/${release_name}

    exe=rcodesign
    sign_command=
    archive_action=_tar_directory

    case ${triple} in
      *apple*)
        sign_command="just _codesign-exe ${dest}/${exe}"
        ;;
      *windows*)
        exe=rcodesign.exe
        archive_action=_zip_directory
        ;;
      *)
        ;;
    esac

    mkdir -p ${dest}
    cp -a ${source}/${exe} ${dest}/${exe}
    chmod +x ${dest}/${exe}

    if [ -n "${sign_command}" ]; then
      ${sign_command}
    fi

    pyoxidizer rust-project-licensing \
      --system-rust \
      --target-triple ${triple} \
      --all-features \
      --unified-license \
      apple-codesign > ${dest}/COPYING

    mkdir -p dist/apple-codesign

    just ${archive_action} dist/apple-codesign-stage ${release_name} dist/apple-codesign
  done

  # Create universal binary.
  just _release_universal_binary apple-codesign {{tag}} rcodesign
  just _tar_directory dist/apple-codesign-stage apple-codesign-{{tag}}-macos-universal dist/apple-codesign

  just _create_shasums dist/apple-codesign

apple-codesign-release-upload commit tag:
  just _upload_release apple-codesign 'Apple Codesign' {{commit}} {{tag}}

apple-codesign-release:
  just _release apple-codesign 'Apple Codesign'
