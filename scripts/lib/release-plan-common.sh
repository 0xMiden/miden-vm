#!/bin/bash

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: Required command '$1' is not installed or not in PATH" >&2
        exit 1
    fi
}

crates_io_get() {
    local path="$1"
    local output_file="$2"
    local status

    if ! status="$(
        curl -sS -A "${CRATES_IO_USER_AGENT:-miden-vm-release-plan}" \
            -o "$output_file" \
            -w "%{http_code}" \
            "https://crates.io/api/v1/${path}"
    )"; then
        echo "ERROR: could not query crates.io path '$path'" >&2
        exit 1
    fi

    printf '%s' "$status"
}

download_published_crate() {
    local package="$1"
    local version="$2"
    local output_file="$3"
    local status

    if ! status="$(
        curl -sS -L -A "${CRATES_IO_USER_AGENT:-miden-vm-release-plan}" \
            -o "$output_file" \
            -w "%{http_code}" \
            "https://crates.io/api/v1/crates/${package}/${version}/download"
    )"; then
        echo "ERROR: could not download $package v$version from crates.io" >&2
        exit 1
    fi

    case "$status" in
        200)
            ;;
        404)
            return 1
            ;;
        *)
            echo "ERROR: crates.io returned HTTP $status while downloading $package v$version" >&2
            exit 1
            ;;
    esac
}

latest_published_version() {
    local package="$1"
    local body_file="$RELEASE_PLAN_TMPDIR/${package}.latest.json"
    local status

    status="$(crates_io_get "crates/${package}" "$body_file")"

    case "$status" in
        200)
            jq -r '.crate.max_stable_version // .crate.max_version // empty' "$body_file"
            ;;
        404)
            printf ''
            ;;
        *)
            echo "ERROR: crates.io returned HTTP $status while checking $package" >&2
            exit 1
            ;;
    esac
}

published_version_info() {
    local package="$1"
    local version="$2"
    local body_file="$RELEASE_PLAN_TMPDIR/${package}-${version}.json"
    local status

    status="$(crates_io_get "crates/${package}/${version}" "$body_file")"

    case "$status" in
        200)
            printf '%s' "$body_file"
            return 0
            ;;
        404)
            return 1
            ;;
        *)
            echo "ERROR: crates.io returned HTTP $status while checking $package v$version" >&2
            exit 1
            ;;
    esac
}

crate_version_exists() {
    local package="$1"
    local version="$2"

    published_version_info "$package" "$version" >/dev/null
}

baseline_commit_for() {
    local package="$1"
    local version="$2"
    local body_file sha tag

    if body_file="$(published_version_info "$package" "$version")"; then
        sha="$(jq -r '.version.trustpub_data.sha // empty' "$body_file")"
        if [[ -n "$sha" ]] && git cat-file -e "${sha}^{commit}" 2>/dev/null; then
            printf '%s\n' "$sha"
            return 0
        fi
    fi

    tag="v$version"
    if git rev-parse --verify --quiet "${tag}^{commit}" >/dev/null; then
        git rev-parse "${tag}^{commit}"
        return 0
    fi

    git fetch --no-tags origin "+refs/tags/${tag}:refs/tags/${tag}" >/dev/null 2>&1 || true

    if [[ -n "${sha:-}" ]] && git cat-file -e "${sha}^{commit}" 2>/dev/null; then
        printf '%s\n' "$sha"
        return 0
    fi

    if git rev-parse --verify --quiet "${tag}^{commit}" >/dev/null; then
        git rev-parse "${tag}^{commit}"
        return 0
    fi

    return 1
}

crate_touched_files() {
    local package_dir="$1"
    local from_commit="$2"
    local to_commit="${3:-HEAD}"
    local changed_files

    changed_files="$(git diff --name-only "$from_commit" "$to_commit" -- "$package_dir")"
    if [[ -z "$changed_files" ]]; then
        return 1
    fi

    printf '%s\n' "$changed_files"
}

package_archive_matches_published() {
    local package="$1"
    local version="$2"
    local workspace_root="$3"
    local package_target_dir package_log local_archive published_archive local_dir published_dir
    local diff_output diff_status

    check_command "diff"
    check_command "tar"

    package_target_dir="$RELEASE_PLAN_TMPDIR/package-target/$package"
    package_log="$RELEASE_PLAN_TMPDIR/package-logs/$package.log"
    local_archive="$package_target_dir/package/$package-$version.crate"
    published_archive="$RELEASE_PLAN_TMPDIR/published-crates/$package-$version.crate"
    local_dir="$RELEASE_PLAN_TMPDIR/package-compare/$package/local"
    published_dir="$RELEASE_PLAN_TMPDIR/package-compare/$package/published"
    diff_output="$RELEASE_PLAN_TMPDIR/package-compare/$package/diff.txt"

    mkdir -p "$(dirname "$package_log")" "$(dirname "$published_archive")" "$local_dir" "$published_dir"

    if ! cargo package \
        --manifest-path "$workspace_root/Cargo.toml" \
        --package "$package" \
        --locked \
        --allow-dirty \
        --no-verify \
        --target-dir "$package_target_dir" >"$package_log" 2>&1; then
        echo "ERROR: failed to package $package v$version for comparison with crates.io:" >&2
        sed 's/^/  /' "$package_log" >&2
        return 2
    fi

    if [[ ! -f "$local_archive" ]]; then
        echo "ERROR: cargo package did not create $local_archive" >&2
        return 2
    fi

    download_published_crate "$package" "$version" "$published_archive"

    if ! tar -xzf "$local_archive" -C "$local_dir"; then
        echo "ERROR: could not extract local archive for $package v$version" >&2
        return 2
    fi
    if ! tar -xzf "$published_archive" -C "$published_dir"; then
        echo "ERROR: could not extract published archive for $package v$version" >&2
        return 2
    fi

    find "$local_dir" "$published_dir" -name .cargo_vcs_info.json -delete
    if diff -qr "$local_dir" "$published_dir" >"$diff_output"; then
        return 0
    else
        diff_status=$?
    fi

    if [[ "$diff_status" -ne 1 ]]; then
        echo "ERROR: could not compare local and published archives for $package v$version" >&2
        return 2
    fi

    echo "Package archive differences for $package v$version:" >&2
    sed 's/^/  /' "$diff_output" >&2
    return 1
}

version_cmp() {
    local left="$1"
    local right="$2"

    awk -v left="$left" -v right="$right" '
        function is_numeric_ident(s) {
            return (s ~ /^[0-9]+$/)
        }

        # Splits `version` (dropping any "+build" metadata) into its release-core components
        # (major.minor.patch) into `parts`, and the dot-separated prerelease identifiers after
        # the first "-", if any, into `pre_parts`. Returns the number of prerelease identifiers
        # found (0 if `version` has no prerelease).
        function split_version(version, parts, pre_parts,    core, dash_pos, pre_str) {
            core = version
            sub(/\+.*/, "", core)
            dash_pos = index(core, "-")
            if (dash_pos == 0) {
                split(core, parts, ".")
                return 0
            }
            split(substr(core, 1, dash_pos - 1), parts, ".")
            pre_str = substr(core, dash_pos + 1)
            return split(pre_str, pre_parts, ".")
        }

        # Compares two sets of prerelease identifiers per semver 2.0 precedence rules
        # (spec section 11): identifiers are compared left to right; a pair of numeric
        # identifiers compares numerically; a pair of non-numeric identifiers compares as
        # strings (ASCII order); a numeric identifier always has lower precedence than a
        # non-numeric one; and if all shared identifiers are equal, the set with fewer
        # identifiers has lower precedence.
        function compare_prerelease(left_arr, left_n, right_arr, right_n,    i, min_n, l, r, l_num, r_num) {
            min_n = (left_n < right_n) ? left_n : right_n
            for (i = 1; i <= min_n; i++) {
                l = left_arr[i]
                r = right_arr[i]
                l_num = is_numeric_ident(l)
                r_num = is_numeric_ident(r)
                if (l_num && r_num) {
                    if (l + 0 > r + 0) return 1
                    if (l + 0 < r + 0) return -1
                } else if (l_num != r_num) {
                    return l_num ? -1 : 1
                } else if (l != r) {
                    return (l > r) ? 1 : -1
                }
            }
            if (left_n > right_n) return 1
            if (left_n < right_n) return -1
            return 0
        }

        BEGIN {
            left_pre_n = split_version(left, left_parts, left_pre)
            right_pre_n = split_version(right, right_parts, right_pre)

            for (i = 1; i <= 3; i++) {
                left_part = left_parts[i] + 0
                right_part = right_parts[i] + 0

                if (left_part > right_part) {
                    print 1
                    exit
                }

                if (left_part < right_part) {
                    print -1
                    exit
                }
            }

            # Release cores are equal: per semver, a version without a prerelease always has
            # higher precedence than one with a prerelease sharing the same core (e.g.
            # "1.5.0" > "1.5.0-alpha.1").
            if (left_pre_n == 0 && right_pre_n == 0) {
                print 0
                exit
            }
            if (left_pre_n == 0) {
                print 1
                exit
            }
            if (right_pre_n == 0) {
                print -1
                exit
            }

            print compare_prerelease(left_pre, left_pre_n, right_pre, right_pre_n)
        }
    '
}

is_publishable_package() {
    local package="$1"

    printf '%s' "$metadata_json" |
        jq -e --arg package "$package" '
          . as $m
          | $m.packages[]
          | select(.name == $package and (.id as $id | $m.workspace_members | index($id)))
          | select(.publish != [])
        ' >/dev/null
}

package_has_library_target() {
    local package="$1"

    printf '%s' "$metadata_json" |
        jq -e --arg package "$package" '
          . as $m
          | $m.packages[]
          | select(.name == $package and (.id as $id | $m.workspace_members | index($id)))
          | .targets[]
          | select(.kind | index("lib") or index("rlib"))
        ' >/dev/null
}

package_rustdoc_name() {
    local package="$1"

    printf '%s' "$metadata_json" |
        jq -r --arg package "$package" '
          . as $m
          | $m.packages[]
          | select(.name == $package and (.id as $id | $m.workspace_members | index($id)))
          | .targets[]
          | select(.kind | index("lib") or index("rlib"))
          | .name
          | gsub("-"; "_")
        ' |
        head -n 1
}

publishable_packages() {
    printf '%s' "$metadata_json" |
        jq -r '
          . as $m
          | $m.packages[]
          | select((.id as $id | $m.workspace_members | index($id)) and .publish != [])
          | [.name, .version, .manifest_path] | @tsv
        ' |
        sort
}

build_rustdoc_json() {
    local package="$1"
    local source_root="$2"
    local target_dir="$3"
    local rustdoc_name

    rustdoc_name="$(package_rustdoc_name "$package")"
    RUSTC_BOOTSTRAP=1 RUSTDOCFLAGS="-Z unstable-options --output-format json" cargo rustdoc \
        --manifest-path "$source_root/Cargo.toml" \
        --package "$package" \
        --lib \
        --locked \
        --target-dir "$target_dir" >/dev/null

    printf '%s/doc/%s.json\n' "$target_dir" "$rustdoc_name"
}

run_semver_check() {
    local package="$1"
    local baseline_version="$2"
    local workspace_root="$3"
    local baseline_commit="${4:-}"
    local semver_cmd semver_cargo_home semver_target_dir semver_workdir
    local baseline_root current_json baseline_json

    check_command "cargo-semver-checks"
    semver_cmd="$(command -v cargo-semver-checks)"
    semver_cargo_home="${CARGO_SEMVER_CARGO_HOME:-$RELEASE_PLAN_TMPDIR/cargo-home}"
    semver_target_dir="${CARGO_SEMVER_TARGET_DIR:-$RELEASE_PLAN_TMPDIR/target}"
    semver_workdir="$RELEASE_PLAN_TMPDIR/semver-workdir"
    mkdir -p "$semver_cargo_home" "$semver_target_dir" "$semver_workdir"

    if ! package_has_library_target "$package"; then
        echo "Skipping semver for $package because it has no library target."
        return 0
    fi

    if [[ -n "$baseline_commit" ]]; then
        baseline_root="$RELEASE_PLAN_TMPDIR/baseline-source/$package-$baseline_commit"
        mkdir -p "$baseline_root"
        git archive "$baseline_commit" | tar -x -C "$baseline_root"

        current_json="$(build_rustdoc_json "$package" "$workspace_root" "$RELEASE_PLAN_TMPDIR/rustdoc/current/$package")"
        baseline_json="$(build_rustdoc_json "$package" "$baseline_root" "$RELEASE_PLAN_TMPDIR/rustdoc/baseline/$package")"

        (
            cd "$semver_workdir"
            CARGO_HOME="$semver_cargo_home" CARGO_TARGET_DIR="$semver_target_dir" \
                "$semver_cmd" semver-checks \
                --current-rustdoc "$current_json" \
                --baseline-rustdoc "$baseline_json" \
                --color never
        )
        return
    fi

    (
        cd "$semver_workdir"
        CARGO_HOME="$semver_cargo_home" CARGO_TARGET_DIR="$semver_target_dir" \
            "$semver_cmd" semver-checks \
            --manifest-path "$workspace_root/Cargo.toml" \
            --package "$package" \
            --baseline-version "$baseline_version" \
            --color never
    )
}
