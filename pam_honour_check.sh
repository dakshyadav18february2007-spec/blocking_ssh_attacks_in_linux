#!/bin/bash

USER="$PAM_USER"
IP="$PAM_RHOST"

LOG_FILE="/home/daksh/lsavproject/auth_tracker.log"
IP_SCORE_FILE="/home/daksh/lsavproject/ip_scores.db"
USER_SCORE_FILE="/home/daksh/lsavproject/user_scores.db"
PAIR_SCORE_FILE="/home/daksh/lsavproject/pair_scores.db"

get_score() {
    file="$1"
    key="$2"
    val=$(grep "^$key|" "$file" | cut -d'|' -f2)
    [[ -z "$val" ]] && echo 0 || echo "$val"
}

pair="$IP->$USER"

ip_score=$(get_score "$IP_SCORE_FILE" "$IP")
user_score=$(get_score "$USER_SCORE_FILE" "$USER")
pair_score=$(get_score "$PAIR_SCORE_FILE" "$pair")

# ----------------------------
# DECISION (same logic as before)
# ----------------------------

if [[ "$IP" == "127.0.0.1" || "$IP" == "::1" ]]; then
    exit 0
fi

if [ "$pair_score" -gt 30 ]; then

    # adaptive delay
    delay=$((pair_score / 10))

    if [ "$delay" -gt 5 ]; then
        delay=5
    fi

    sleep "$delay"

    exit 1
fi


if [ "$ip_score" -gt 40 ]; then
    exit 1
fi

# DO NOT hard block user (avoid DoS)
if [ "$user_score" -gt 50 ]; then
    sleep 2   # slow down attacker
fi

exit 0   #  allow
