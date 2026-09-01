#!/bin/bash
# gitenv.sh — dedicated .git / .env exposure sweep.
#
# Fixes three gaps in the earlier configsweep:
#   1. runs over ALL content hosts (200/30x/401/403), not only 200-roots —
#      a 403 root says nothing about whether /.git is readable
#   2. tests the full set of git internals + env variants, not just 2 paths
#   3. validates by CONTENT SIGNATURE, not status code, so SPA catch-alls
#      and generic error bodies cannot register as hits
cd "$HOME/gm" || exit 1
set -u
OUT="$HOME/gm/out"
mkdir -p "$OUT/gitenv"
rm -f "$OUT/gitenv_done.txt"
: > "$OUT/gitenv_hits.tsv"

cat > /tmp/gepaths.txt <<'EOF'
/.git/HEAD
/.git/config
/.git/index
/.git/logs/HEAD
/.git/packed-refs
/.git/refs/heads/main
/.git/refs/heads/master
/.git/ORIG_HEAD
/.git/COMMIT_EDITMSG
/.git/description
/.env
/.env.local
/.env.production
/.env.prod
/.env.dev
/.env.development
/.env.staging
/.env.test
/.env.backup
/.env.bak
/.env.old
/.env.save
/.env~
/api/.env
/backend/.env
/app/.env
/.svn/entries
/.DS_Store
/.htpasswd
EOF

cat > /tmp/geprobe.sh <<'EOS'
#!/bin/bash
u="$1"
OUT="$HOME/gm/out"
H="X-HackerOne-Research: <your-h1-handle>"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
tmp=$(mktemp /tmp/ge.XXXXXX)

while read -r p; do
  code=$(curl -s -o "$tmp" -w '%{http_code}' --max-time 10 \
          -H "$H" -H "User-Agent: $UA" "$u$p" 2>/dev/null)
  [ "$code" = "200" ] || continue
  sz=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
  [ "$sz" -lt 4 ] && continue

  head1=$(head -c 400 "$tmp" 2>/dev/null | tr -d '\0')
  verdict=""
  case "$p" in
    */.git/HEAD|*/.git/ORIG_HEAD)
      echo "$head1" | grep -qE '^(ref: refs/|[0-9a-f]{40})' && verdict="REAL_GIT_HEAD" ;;
    */.git/config)
      echo "$head1" | grep -q '\[core\]' && verdict="REAL_GIT_CONFIG" ;;
    */.git/index)
      head -c 4 "$tmp" | grep -q 'DIRC' && verdict="REAL_GIT_INDEX" ;;
    */.git/logs/HEAD)
      echo "$head1" | grep -qE '^[0-9a-f]{40} [0-9a-f]{40}' && verdict="REAL_GIT_LOG" ;;
    */.git/packed-refs)
      echo "$head1" | grep -qE '^#? ?pack-refs|^[0-9a-f]{40} refs/' && verdict="REAL_PACKED_REFS" ;;
    */.git/refs/*)
      echo "$head1" | grep -qE '^[0-9a-f]{40}$' && verdict="REAL_GIT_REF" ;;
    */.git/description)
      echo "$head1" | grep -qi 'Unnamed repository' && verdict="REAL_GIT_DESC" ;;
    */.git/COMMIT_EDITMSG)
      echo "$head1" | grep -qivE '<html|<!doctype' && [ "$sz" -lt 4000 ] && verdict="MAYBE_COMMIT_MSG" ;;
    *.env*)
      # a real dotenv: KEY=VALUE lines, not markup
      if ! echo "$head1" | grep -qiE '<html|<!doctype|^\s*[{<]'; then
        echo "$head1" | grep -qE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' && verdict="REAL_DOTENV"
      fi ;;
    */.svn/entries)
      echo "$head1" | grep -qE '^[0-9]+$|dir$' && verdict="REAL_SVN" ;;
    */.DS_Store)
      head -c 8 "$tmp" | grep -q 'Bud1' && verdict="REAL_DSSTORE" ;;
    */.htpasswd)
      echo "$head1" | grep -qE '^[A-Za-z0-9._-]+:\$?[0-9a-zA-Z./$]+' && verdict="REAL_HTPASSWD" ;;
  esac

  if [ -n "$verdict" ]; then
    n=$(printf '%s%s' "$u" "$p" | md5sum | cut -c1-16)
    cp "$tmp" "$OUT/gitenv/$n.bin"
    snip=$(head -c 180 "$tmp" | tr '\n\t\r' '   ')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$verdict" "$u" "$p" "$sz" "$n" "$snip" \
      >> "$OUT/gitenv_hits.tsv"
  fi
done < /tmp/gepaths.txt
rm -f "$tmp"
EOS
chmod +x /tmp/geprobe.sh

TARGETS=recon/live_content.txt
echo "[*] .git/.env sweep: $(wc -l < $TARGETS) hosts x $(wc -l < /tmp/gepaths.txt) paths"
xargs -a "$TARGETS" -P 14 -I{} /tmp/geprobe.sh {} 2>/dev/null
echo "[*] validated hits: $(wc -l < "$OUT/gitenv_hits.tsv")"
echo DONE > "$OUT/gitenv_done.txt"
