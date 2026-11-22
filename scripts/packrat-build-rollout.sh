#!/usr/bin/env bash
# Native Linux build from a trusted git archive, without retaining its checkout.
set -euo pipefail

if (( $# < 2 || $# > 3 )) || [[ $1 != --check && $1 != --deploy ]] ||
   [[ ! $2 =~ ^[A-Za-z0-9_.-]+$ || ( $# == 3 && $3 != --enable-alert-evidence ) ]]; then
    printf '%s\n' 'Usage: git archive REV | bash packrat-build-rollout.sh --check|--deploy INTERFACE [--enable-alert-evidence]' >&2
    exit 2
fi

cache="$HOME/.cache"
rollout=${PACKRAT_BUILD_ROLLOUT:-"$HOME/.local/bin/packrat-rollout"}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$cache/packrat-native-build/target"}
export CARGO_INCREMENTAL=0
jobs=${PACKRAT_BUILD_JOBS:-3}
if [[ $rollout != /* || ! -x $rollout || $CARGO_TARGET_DIR != /* || ! $jobs =~ ^[1-9][0-9]?$ ]]; then
    printf '%s\n' 'Build requires an executable absolute rollout path, an absolute Cargo target path, and 1-99 build jobs.' >&2
    exit 2
fi

mkdir -p -- "$cache"
exec 8>"$cache/packrat-native-build.lock"
if ! flock -n 8; then
    printf '%s\n' 'Another native Packrat build is in progress.' >&2
    exit 1
fi

stage=$(mktemp -d -- "$cache/packrat-native-source.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
tar --extract --file=- --directory="$stage" --no-same-owner --no-same-permissions
[[ -f $stage/Cargo.toml && -f $stage/Cargo.lock ]]
(
    cd -- "$stage"
    cargo build --locked --release --features real-capture -j "$jobs" --bin packrat --bin packrat-analyze </dev/null
)

for binary in packrat packrat-analyze; do
    install -m 0755 -- "$CARGO_TARGET_DIR/release/$binary" "$stage/$binary"
done
PACKRAT_ROLLOUT_ANALYZER="$stage/packrat-analyze" "$rollout" "$1" "$stage/packrat" "${@:2}" </dev/null 8>&-
