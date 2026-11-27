#!/bin/sh
# Fork (giantswarm/containerd): ours to keep (FORK.md, "Releases").
# Prints the version of a build of the line:
#   line-version.sh pin          the pin, v<upstream version> from version/version.go
#   line-version.sh <git tag>    the tag itself, once it is a release of the pin (v<pin>-gs.<N>)
#   line-version.sh dev <sha>    a branch build, v<pin>-dev.<first 12 characters of the commit>
set -eu
pin=$(sed -n 's/^[[:space:]]*Version = "\([0-9][0-9.]*\)+unknown"$/v\1/p' version/version.go)
if [ -z "${pin}" ]; then
	echo "ERROR: no upstream version in version/version.go" >&2
	exit 1
fi
case "${1:-pin}" in
pin)
	echo "${pin}"
	;;
dev)
	sha=${2:?commit}
	echo "${pin}-dev.$(printf '%s' "${sha}" | cut -c1-12)"
	;;
*)
	if ! printf '%s\n' "$1" | grep -Eq "^$(printf '%s' "${pin}" | sed 's/\./\\./g')-gs\.[1-9][0-9]*\$"; then
		echo "ERROR: tag $1 is not a release of the pin ${pin} (${pin}-gs.<N>)" >&2
		exit 1
	fi
	echo "$1"
	;;
esac
