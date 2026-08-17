#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <devkit-archive> <ddk-workspace> <module-source-dir>" >&2
    exit 2
fi

devkit_archive=$(realpath "$1")
ddk_workspace=$(realpath -m "$2")
module_source=$(realpath "$3")

if [[ ! -f "${devkit_archive}" ]]; then
    echo "Development package not found: ${devkit_archive}" >&2
    exit 1
fi
if [[ ! -f "${module_source}/BUILD.bazel" ]]; then
    echo "DDK BUILD.bazel not found in: ${module_source}" >&2
    exit 1
fi

mkdir -p "${ddk_workspace}"
tar --zstd -xf "${devkit_archive}" \
    -C "${ddk_workspace}" \
    --strip-components=1

prebuilts_dir="${ddk_workspace}/prebuilts/kernel"
required_files=(
    ci_target_mapping.json
    init_ddk.zip
    kernel_aarch64_ddk_headers_archive.tar.gz
    kernel_aarch64_filegroup_decl.tar.gz
    manifest.xml
    vmlinux.symvers
)
for file in "${required_files[@]}"; do
    if [[ ! -f "${prebuilts_dir}/${file}" ]]; then
        echo "Development package is missing: ${file}" >&2
        exit 1
    fi
done

# init_ddk needs a repo superproject. Only initialize its manifest here; the
# pinned DDK projects are injected from the manifest in the development kit.
if [[ ! -d "${ddk_workspace}/.repo" ]]; then
    (
        cd "${ddk_workspace}"
        repo init \
            -u https://android.googlesource.com/kernel/manifest \
            -b common-android15-6.6 \
            --no-clone-bundle
    )
    cat > "${ddk_workspace}/.repo/manifests/default.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
</manifest>
EOF
fi

python3 "${prebuilts_dir}/init_ddk.zip" \
    --ddk_workspace "${ddk_workspace}" \
    --kleaf_repo "${ddk_workspace}/external/kleaf" \
    --prebuilts_dir "${prebuilts_dir}"

mkdir -p "${ddk_workspace}/wujishadow"
cp -a "${module_source}/." "${ddk_workspace}/wujishadow/"

test -x "${ddk_workspace}/tools/bazel"
test -f "${ddk_workspace}/MODULE.bazel"
test -f "${ddk_workspace}/wujishadow/BUILD.bazel"
