#!/usr/bin/env bash
# Native Linux build from a trusted git archive, without retaining its checkout.
set -euo pipefail

if (( $# < 2 || $# > 3 )) || [[ $1 != --check && $1 != --deploy ]] ||
   [[ ! $2 =~ ^[A-Za-z0-9_.-]+$ || ( $# == 3 && $3 != --enable-alert-evidence && $3 != --archive-only ) ]]; then
    printf '%s\n' 'Usage: git archive REV | bash packrat-build-rollout.sh --check|--deploy INTERFACE [--enable-alert-evidence|--archive-only]' >&2
    printf '%s\n' 'Set PACKRAT_BUILD_EXPECT_SHA256 to verify the trusted archive before extraction (64 MiB maximum).' >&2
    exit 2
fi

cache="$HOME/.cache"
rollout=${PACKRAT_BUILD_ROLLOUT:-"$HOME/.local/bin/packrat-rollout"}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$cache/packrat-native-build/target"}
export CARGO_INCREMENTAL=0
jobs=${PACKRAT_BUILD_JOBS:-3}
minimum_free_mib=${PACKRAT_BUILD_MIN_FREE_MIB:-2048}
expected_sha256=${PACKRAT_BUILD_EXPECT_SHA256:-}
archive_limit=$((64 * 1024 * 1024))
if [[ $rollout != /* || ! -x $rollout || $CARGO_TARGET_DIR != /* || ! $jobs =~ ^[1-9][0-9]?$ ]]; then
    printf '%s\n' 'Build requires an executable absolute rollout path, an absolute Cargo target path, and 1-99 build jobs.' >&2
    exit 2
fi
if [[ ! $minimum_free_mib =~ ^[1-9][0-9]{0,5}$ ]]; then
    printf '%s\n' 'PACKRAT_BUILD_MIN_FREE_MIB must be a positive number of MiB (default: 2048).' >&2
    exit 2
fi
if [[ -n $expected_sha256 && ! $expected_sha256 =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' 'PACKRAT_BUILD_EXPECT_SHA256 must be a lowercase SHA-256 digest.' >&2
    exit 2
fi

mkdir -p -- "$cache"
exec 8>"$cache/packrat-native-build.lock"
if ! flock -n 8; then
    printf '%s\n' 'Another native Packrat build is in progress.' >&2
    exit 1
fi
mkdir -p -- "$CARGO_TARGET_DIR"
for path in "$cache" "$CARGO_TARGET_DIR"; do
    if ! LC_ALL=C df -k --output=avail -- "$path" | awk -v minimum="$minimum_free_mib" '
        NR == 2 && NF == 1 && $1 ~ /^[0-9]+$/ { enough = ($1 >= minimum * 1024) }
        END { exit !(NR == 2 && enough) }
    '; then
        printf 'Cannot verify %s MiB free for native build at %s; capture unchanged.\n' "$minimum_free_mib" "$path" >&2
        exit 1
    fi
done

stage=$(mktemp -d -- "$cache/packrat-native-source.XXXXXXXX")
upload=''
trap 'rm -rf -- "$stage"; if [[ -n $upload ]]; then rm -f -- "$upload"; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
archive=-
if [[ -n $expected_sha256 ]]; then
    upload=$(mktemp -- "$cache/packrat-native-upload.XXXXXXXX")
    head -c "$((archive_limit + 1))" >"$upload"
    archive_bytes=$(stat -c '%s' -- "$upload")
    if (( archive_bytes > archive_limit )); then
        printf '%s\n' 'Source archive exceeds the 64 MiB verification limit; capture unchanged.' >&2
        exit 1
    fi
    digest=$(sha256sum <"$upload")
    if [[ ${digest%% *} != "$expected_sha256" ]]; then
        printf '%s\n' 'Source archive SHA-256 does not match the expected digest; capture unchanged.' >&2
        exit 1
    fi
    archive=$upload
fi
tar --extract --file="$archive" --directory="$stage" --no-same-owner --no-same-permissions
if [[ -n $upload ]]; then rm -f -- "$upload"; upload=''; fi
[[ -f $stage/Cargo.toml && -f $stage/Cargo.lock ]]
binaries=(packrat packrat-analyze packrat-archive)
if [[ ${3-} == --archive-only ]]; then binaries=(packrat-archive); fi
build_args=()
for binary in "${binaries[@]}"; do build_args+=(--bin "$binary"); done
(
    cd -- "$stage"
    cargo build --locked --release --features real-capture -j "$jobs" \
        "${build_args[@]}" </dev/null
)

for binary in "${binaries[@]}"; do
    install -m 0755 -- "$CARGO_TARGET_DIR/release/$binary" "$stage/$binary"
done
if [[ ${3-} == --archive-only ]]; then
    PACKRAT_ROLLOUT_ANALYZER='' PACKRAT_ROLLOUT_ARCHIVE="$stage/packrat-archive" \
        "$rollout" "$1" /usr/local/bin/packrat "$2" --companions-only </dev/null 8>&-
else
    PACKRAT_ROLLOUT_ANALYZER="$stage/packrat-analyze" PACKRAT_ROLLOUT_ARCHIVE="$stage/packrat-archive" \
        "$rollout" "$1" "$stage/packrat" "${@:2}" </dev/null 8>&-
fi
