#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 6 ]]; then
    echo "usage: $0 <android-kernel-root> <output-dir> [android-version] [kernel-version] [arch] [dist-dir]" >&2
    exit 2
fi

kernel_root=$(realpath "$1")
output_dir=$(realpath -m "$2")
android_version=${3:-15}
kernel_version=${4:-6.6}
architecture=${5:-aarch64}
manifest_branch="common-android${android_version}-${kernel_version}"
package_name="android${android_version}-${kernel_version}-${architecture}-devkit"
stage_dir="${output_dir}/${package_name}"
prebuilts_dir="${stage_dir}/prebuilts/kernel"
repo_bin=$(command -v repo || true)

if [[ ! "${android_version}" =~ ^[0-9]+$ ]]; then
    echo "Invalid Android version: ${android_version}" >&2
    exit 2
fi
if [[ ! "${kernel_version}" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid kernel version: ${kernel_version}" >&2
    exit 2
fi
if [[ ! "${architecture}" =~ ^[A-Za-z0-9_+-]+$ ]]; then
    echo "Invalid architecture: ${architecture}" >&2
    exit 2
fi

if [[ $# -ge 6 && -n "${6}" ]]; then
    dist_dir=$(realpath "${6}")
elif (( android_version <= 13 )); then
    dist_dir="${kernel_root}/out/android${android_version}-${kernel_version}/dist"
else
    dist_dir="${kernel_root}/out/kernel_${architecture}/dist"
fi

if [[ -z "${repo_bin}" ]]; then
    repo_bin="${kernel_root}/.repo/repo/repo"
fi
if [[ ! -x "${repo_bin}" ]]; then
    echo "repo tool not found: ${repo_bin}" >&2
    exit 1
fi

if [[ ! -d "${dist_dir}" ]]; then
    echo "GKI dist directory not found: ${dist_dir}" >&2
    exit 1
fi

common_required_files=(
    kernel-headers.tar.gz
    kernel-uapi-headers.tar.gz
)

ddk_required_files=(
    init_ddk.zip
    "kernel_${architecture}_ddk_headers_archive.tar.gz"
    "kernel_${architecture}_filegroup_decl.tar.gz"
    vmlinux.symvers
)

for file in "${common_required_files[@]}"; do
    if [[ ! -f "${dist_dir}/${file}" ]]; then
        echo "Required GKI development artifact is missing: ${dist_dir}/${file}" >&2
        exit 1
    fi
done

if ! find "${dist_dir}" -maxdepth 1 -type f \
    \( -name 'vmlinux.symvers' -o -name 'Module.symvers' -o -name '*_Module.symvers' \) \
    -print -quit | grep -q .; then
    echo "No symbol version file found in: ${dist_dir}" >&2
    exit 1
fi

if [[ ! -f "${dist_dir}/devkit_probe.ko" ]]; then
    echo "The build-only validation module is missing: ${dist_dir}/devkit_probe.ko" >&2
    exit 1
fi

package_format="gki-dist"
ddk_ready=1
for file in "${ddk_required_files[@]}"; do
    if [[ ! -f "${dist_dir}/${file}" ]]; then
        ddk_ready=0
        break
    fi
done
if (( ddk_ready )); then
    package_format="kleaf-ddk"
fi

rm -rf "${stage_dir}"
mkdir -p "${prebuilts_dir}"
cp -a "${dist_dir}/." "${prebuilts_dir}/"

(
    cd "${kernel_root}"
    "${repo_bin}" manifest -r
) > "${stage_dir}/manifest.xml"
cp "${stage_dir}/manifest.xml" "${prebuilts_dir}/manifest.xml"

kernel_commit=$(git -C "${kernel_root}/common" rev-parse HEAD)
build_time=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

cat > "${stage_dir}/BUILD_INFO.txt" <<EOF
android_version=${android_version}
kernel_version=${kernel_version}
architecture=${architecture}
manifest_branch=${manifest_branch}
kernel_commit=${kernel_commit}
package_format=${package_format}
dist_path=${dist_dir#"${kernel_root}/"}
github_repository=${GITHUB_REPOSITORY:-unknown}
github_sha=${GITHUB_SHA:-unknown}
github_run_id=${GITHUB_RUN_ID:-unknown}
created_at=${build_time}
EOF

cat > "${stage_dir}/README.md" <<EOF
# Android ${android_version} / Kernel ${kernel_version} ${architecture} development package

Package format: ${package_format}

The prebuilts/kernel directory contains the complete GKI distribution output.
When package_format is kleaf-ddk, it also contains init_ddk.zip and the archives
required by Kleaf's kernel_prebuilt_ext and ddk_module rules. Older branches
that report package_format=gki-dist do not expose the same init_ddk contract;
use their pinned manifest with the matching legacy Android kernel build system.

manifest.xml pins every Android kernel project used for this build.
BUILD_INFO.txt records the kernel and workflow revisions. Verify package
contents with sha256sum -c SHA256SUMS.
EOF

(
    cd "${stage_dir}"
    find prebuilts/kernel -type f -print0 \
        | sort -z \
        | xargs -0 sha256sum > SHA256SUMS
)

archive="${output_dir}/${package_name}.tar.zst"
mkdir -p "${output_dir}"
tar --zstd -cf "${archive}" -C "${output_dir}" "${package_name}"

archive_size=$(stat -c '%s' "${archive}")
if (( archive_size >= 2147483648 )); then
    echo "Archive exceeds GitHub's 2 GiB release asset limit: ${archive_size} bytes" >&2
    exit 1
fi

(
    cd "${output_dir}"
    sha256sum "$(basename "${archive}")" \
        > "$(basename "${archive}").sha256"
)

echo "DEVKIT_ARCHIVE=${archive}" >> "${GITHUB_ENV:-/dev/null}"
echo "DEVKIT_CHECKSUM=${archive}.sha256" >> "${GITHUB_ENV:-/dev/null}"
echo "DEVKIT_PACKAGE_FORMAT=${package_format}" >> "${GITHUB_ENV:-/dev/null}"
echo "Packaged ${archive}"
du -h "${archive}" "${archive}.sha256"
