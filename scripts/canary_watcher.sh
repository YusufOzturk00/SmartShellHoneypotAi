#!/bin/bash
CANARY_FILES=("/root/passwords.txt" "/root/config.php" "/root/.env" "/root/.aws/credentials")
CANARY_LOG="/tmp/.canary.log"
for file in "${CANARY_FILES[@]}"; do
    if [ -f "$file" ]; then
        inotifywait -m -e access,open "$file" 2>/dev/null >> "$CANARY_LOG" &
    fi
done
wait
