#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <android-kernel-root> <output-dir>" >&2
    exit 2
fi

kernel_root=$(realpath "$1")
output_dir=$(realpath -m "$2")
dist_dir="${kernel_root}/out/kernel_aarch64/dist"
package_name="android15-6.6-aarch64-devkit"
stage_dir="${output_dir}/${package_name}"
prebuilts_dir="${stage_dir}/prebuilts/kernel"
repo_bin=$(command -v repo || true)

if [[ -z "${repo_bin}" ]]; then
    repo_bin="$(dirname "${kernel_root}")/.lyenv/bin/repo"
fi
if [[ ! -x "${repo_bin}" ]]; then
    echo "repo tool not found: ${repo_bin}" >&2
    exit 1
fi

if [[ ! -d "${dist_dir}" ]]; then
    echo "GKI dist directory not found: ${dist_dir}" >&2
    exit 1
fi

required_files=(
    build.config.constants
    init_ddk.zip
    kernel-headers.tar.gz
    kernel-uapi-headers.tar.gz
    kernel_aarch64_ddk_headers_archive.tar.gz
    kernel_aarch64_filegroup_decl.tar.gz
    unstripped_modules.tar.gz
    vmlinux.symvers
)

for file in "${required_files[@]}"; do
    if [[ ! -f "${dist_dir}/${file}" ]]; then
        echo "Required DDK artifact is missing: ${dist_dir}/${file}" >&2
        exit 1
    fi
done

mkdir -p "${prebuilts_dir}"
cp -a "${dist_dir}/." "${prebuilts_dir}/"

(
    cd "${kernel_root}"
    "${repo_bin}" manifest -r
) > "${stage_dir}/manifest.xml"
cp "${stage_dir}/manifest.xml" "${prebuilts_dir}/manifest.xml"

kernel_commit=$(git -C "${kernel_root}/common" rev-parse HEAD)
manifest_branch=$(git -C "${kernel_root}/.repo/manifests" branch --show-current)
build_time=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

cat > "${stage_dir}/BUILD_INFO.txt" <<EOF
android_version=15
kernel_version=6.6
architecture=aarch64
manifest_branch=${manifest_branch}
kernel_commit=${kernel_commit}
github_repository=${GITHUB_REPOSITORY:-unknown}
github_sha=${GITHUB_SHA:-unknown}
github_run_id=${GITHUB_RUN_ID:-unknown}
created_at=${build_time}
EOF

cat > "${stage_dir}/README.md" <<'EOF'
# Android 15 / Kernel 6.6 AArch64 DDK package

`prebuilts/kernel` is the complete `//common:kernel_aarch64_dist` output.
It can be used as the `local_artifact_path` of Kleaf's
`kernel_prebuilt_ext.declare_kernel_prebuilts` rule. External modules should
depend on `@gki_prebuilts//kernel_aarch64` through `ddk_module`.

`manifest.xml` pins every Android kernel project used for this build.
`BUILD_INFO.txt` records the kernel and workflow revisions. Verify package
contents with `sha256sum -c SHA256SUMS`.
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
(
    cd "${output_dir}"
    sha256sum "$(basename "${archive}")" \
        > "$(basename "${archive}").sha256"
)

echo "DEVKIT_ARCHIVE=${archive}" >> "${GITHUB_ENV:-/dev/null}"
echo "DEVKIT_CHECKSUM=${archive}.sha256" >> "${GITHUB_ENV:-/dev/null}"
echo "Packaged ${archive}"
du -h "${archive}" "${archive}.sha256"
