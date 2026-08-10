#!/usr/bin/env bash
SECONDS=0

set -uo pipefail

PATH="/usr/local/bin:/usr/bin:/bin"



OUTPUT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN_FILE="$OUTPUT_DIR/domains.txt"

mapfile -t DOMAINS < <(
    grep -vE '^[[:space:]]*(#|$)' "$DOMAIN_FILE"
)
OUTPUT_FILE="$OUTPUT_DIR/broken-links.txt"
WORK_DIR="$(mktemp -d)"
RESULTS_FILE="$WORK_DIR/results.txt"
FINAL_FILE="$OUTPUT_DIR/.broken-links.txt.new"

trap 'rm -rf -- "$WORK_DIR"; rm -f -- "$FINAL_FILE"' EXIT

: > "$RESULTS_FILE"

for domain in "${DOMAINS[@]}"; do
    report_file="$WORK_DIR/${domain//[^a-zA-Z0-9.-]/_}.json"

    printf 'Starting: https://%s/\n' "$domain"

    if ! (
        cd "$WORK_DIR" &&
        "$OUTPUT_DIR/bin/siteone-crawler" \
            --url="https://${domain}/" \
            --disable-all-assets \
            --allowed-domain-for-crawling='*' \
            --single-foreign-page \
            --workers=2 \
            --max-reqs-per-sec=2 \
            --max-visited-urls=500 \
            --no-cache \
            --output-html-report='' \
            --output-json-file="$report_file" \
            --output-text-file='' \
            --do-not-truncate-url \
            --show-scheme-and-host \
            --no-color \
            --console-width=4000 \
            >/dev/null 2>&1
    ); then
        printf 'SiteOne crawl failed for %s\n' "$domain" >&2
        continue
    fi

    checked=$(jq '(.results // []) | length' "$report_file")

    before=$(wc -l < "$RESULTS_FILE")

    jq -r '
    def absolute($origin):
        if startswith("http://") or startswith("https://") then
            .
        elif startswith("/") then
            $origin + .
        elif . == "" then
            $origin + "/"
        else
            $origin + "/" + .
        end;

    (.options.url |
        capture("^(?<origin>https?://[^/]+)").origin
    ) as $origin |

    [
        (
            (.tables["404"].rows // [])[] |
            [
                (.url | absolute($origin)),
                .statusCode,
                (.sourceUqId | absolute($origin))
            ]
        ),

        (
            (.results // [])[] |
            (.status | tonumber?) as $code |
            select(
                $code == 410 or
                ($code >= 500 and $code <= 599)
            ) as $result |

            (
                [
                    (.tables["external-urls"].rows // [])[] |
                    select(.url == $result.url) |
                    .foundOn
                ][0] // $origin
            ) as $found_on |

            [
                $result.url,
                $result.status,
                ($found_on | absolute($origin))
            ]
        )
    ]
    | unique
    | .[]
    | @tsv
    ' "$report_file" >> "$RESULTS_FILE"

    after=$(wc -l < "$RESULTS_FILE")
    printf 'Finished: https://%s/ — %s URLs checked, %s broken\n'         "$domain" "$checked" "$((after-before))"
done

{
    printf 'Last scan completed: %s\n' "$(TZ=America/New_York date '+%Y-%m-%d %H:%M:%S %Z')"
    printf 'Scan duration: %02d:%02d:%02d\n\n' "$((SECONDS/3600))" "$(((SECONDS%3600)/60))" "$((SECONDS%60))"
    sort -u "$RESULTS_FILE"
} > "$FINAL_FILE"

mv -f "$FINAL_FILE" "$OUTPUT_FILE"

total=$(grep -c $'\t' "$OUTPUT_FILE" || true)
printf 'Completed all domains — %s broken links total\n' "$total"
