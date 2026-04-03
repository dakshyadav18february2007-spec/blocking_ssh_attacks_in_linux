#!/bin/bash

Mode="live"   # change to "test" for simulation  "live" for live script
counter=0   # used in decay score related
LOG_FILE="auth_tracker.log"
ALERT_FILE="alerts.log"

IP_SCORE_FILE="ip_scores.db"
USER_SCORE_FILE="user_scores.db"
PAIR_SCORE_FILE="pair_scores.db"

touch "$LOG_FILE" "$ALERT_FILE"
touch "$IP_SCORE_FILE" "$USER_SCORE_FILE" "$PAIR_SCORE_FILE"


WHITELIST=("127.0.0.1" "::1")

is_whitelisted_ip() {
    ip="$1"

    for whiteip in "${WHITELIST[@]}"; do
        if [[ "$ip" == "$whiteip" ]]; then
            return 0
        fi
    done

    return 1
}



# ----------------------------
# ALERT SYSTEM (with cooldown)
# ----------------------------
log_alert() {
    type="$1"
    key="$2"
    now=$(date +%s)

    last=$(grep "^$type|$key|" "$ALERT_FILE" | tail -1 | cut -d'|' -f3)

    cooldown=60

    [[ "$type" == "BLOCK_IP" ]] && cooldown=300
    [[ "$type" == "BLOCK_PAIR" ]] && cooldown=120
    [[ "$type" == "SUSPICIOUS_USER" ]] && cooldown=600

    if [[ -n "$last" && $((now - last)) -lt $cooldown ]]; then
        return
    fi

    echo "$type|$key|$now" >> "$ALERT_FILE"
    echo "[ALERT] $type → $key"

}

# ----------------------------
# RECORD ATTEMPT
# ----------------------------
record_attempt() {
    ip="$1"
    user="$2"
    timestamp=$(date +%s)

    echo "$timestamp|$ip|$user" >> "$LOG_FILE"
}

# ----------------------------
# GET RECENT LOGS
# ----------------------------
get_recent_logs() {
    window=$1
    now=$(date +%s)
    cutoff=$((now - window))

    awk -F'|' -v cutoff="$cutoff" '$1 >= cutoff' "$LOG_FILE"
}

# ----------------------------
# SCORE STORAGE
# ----------------------------
update_score() {
    file="$1"
    key="$2"
    value="$3"

    current=$(grep "^$key|" "$file" | cut -d'|' -f2)
    [[ -z "$current" ]] && current=0

    new=$((current + value))

    sed -i "/^$key|/d" "$file"
    echo "$key|$new" >> "$file"
}

get_score() {
    file="$1"
    key="$2"

    val=$(grep "^$key|" "$file" | cut -d'|' -f2)
    [[ -z "$val" ]] && echo 0 || echo "$val"
}

#score decay 

decay_scores() {
    for file in "$IP_SCORE_FILE" "$USER_SCORE_FILE" "$PAIR_SCORE_FILE"; do

        awk -F'|' '{
            new = int($2 * 0.9)

            if (new > 0)
                print $1 "|" new
        }' "$file" > tmp && mv tmp "$file"

    done
}

#check for slow attacks
check_multi_layer_attack() {
    user="$1"

    # -------------------------
    # Layer 1: 1 hour window
    # -------------------------
    count_1h=$(get_recent_logs 3600 \
        | awk -F'|' -v user="$user" '$3 == user' \
        | wc -l)

    if [ "$count_1h" -gt 8 ]; then
        log_alert "MEDIUM_ATTACK_1H" "$user"
    fi

    # -------------------------
    # Layer 2: 10 hour window
    # -------------------------
    count_10h=$(get_recent_logs 36000 \
        | awk -F'|' -v user="$user" '$3 == user' \
        | wc -l)

    if [ "$count_10h" -gt 30 ]; then
        log_alert "SLOW_ATTACK_10H" "$user"
    fi

    # -------------------------
    # Layer 3: 24 hour window
    # -------------------------
    count_24h=$(get_recent_logs 86400 \
        | awk -F'|' -v user="$user" '$3 == user' \
        | wc -l)

    if [ "$count_24h" -gt 80 ]; then
        log_alert "PERSISTENT_ATTACK_24H" "$user"
    fi
}


# ----------------------------
# HONOUR SCORE ENGINE
# ----------------------------
calculate_and_update_scores() {
    ip="$1"
    user="$2"
    pair="$ip->$user"

    # base increments
    update_score "$IP_SCORE_FILE" "$ip" 1
    update_score "$USER_SCORE_FILE" "$user" 1
    update_score "$PAIR_SCORE_FILE" "$pair" 2

    # multi-username attack (IP)
    unique_users=$(get_recent_logs 3600 \
        | awk -F'|' -v ip="$ip" '$2 == ip {print $3}' \
        | sort -u | wc -l)

    if [ "$unique_users" -gt 3 ]; then
        update_score "$IP_SCORE_FILE" "$ip" $((unique_users * 3))
    fi

    # distributed attack (USER)
    unique_ips=$(get_recent_logs 3600 \
        | awk -F'|' -v user="$user" '$3 == user {print $2}' \
        | sort -u | wc -l)

    if [ "$unique_ips" -gt 5 ]; then
        update_score "$USER_SCORE_FILE" "$user" $((unique_ips * 2))
    fi
}

# ----------------------------
# DECISION ENGINE
# ----------------------------
decide_action() {
    ip="$1"
    user="$2"
    pair="$ip->$user"

    ip_score=$(get_score "$IP_SCORE_FILE" "$ip")
    user_score=$(get_score "$USER_SCORE_FILE" "$user")
    pair_score=$(get_score "$PAIR_SCORE_FILE" "$pair")

    total=$((ip_score + user_score + pair_score))

    echo "[DEBUG] IP=$ip_score USER=$user_score PAIR=$pair_score TOTAL=$total"

    if [ "$ip_score" -gt 40 ]; then
	   log_alert "BLOCK_IP" "$ip"
    fi

    if [ "$pair_score" -gt 30 ]; then 
	    log_alert "BLOCK_PAIR" "$pair"
    fi
	    
	    
    if [ "$user_score" -gt 50 ]; then
	    log_alert "SUSPICIOUS_USER" "$user"

    fi
}


# ----------------------------
# PARSE SSH LOG
# ----------------------------
parse_log() {
    echo "$1" | awk '
    {
        user=""; ip="";
        for(i=1;i<=NF;i++){
            if($i=="for") {
                if($(i+1)=="invalid" && $(i+2)=="user")
                    user=$(i+3);
                else
                    user=$(i+1);
            }
            if($i=="from")
                ip=$(i+1);
        }
        if(user!="" && ip!="")
            print user "|" ip;
    }'
}

# ----------------------------
# TEST MODE
# ----------------------------
run_tests() {
    echo "[TEST] Running simulations..."

    # Same IP brute force
    for i in {1..12}; do
        record_attempt "192.168.1.10" "daksh"
        calculate_and_update_scores "192.168.1.10" "daksh"
        decide_action "192.168.1.10" "daksh"
    done

    # Distributed attack
    for i in {1..20}; do
        ip="192.168.1.$i"
        record_attempt "$ip" "daksh"
        calculate_and_update_scores "$ip" "daksh"
        decide_action "$ip" "daksh"
    done
}

# ----------------------------
# MAIN LOOP
# ----------------------------
echo "[INFO] SSH monitor started..."

if [[ "$Mode" == "test" ]]; then
    > "$LOG_FILE"
    > "$ALERT_FILE"
    > "$IP_SCORE_FILE"
    > "$USER_SCORE_FILE"
    > "$PAIR_SCORE_FILE"

    run_tests
else
    sudo journalctl -f -o cat | grep --line-buffered "Failed password" | while read -r line; do

        parsed=$(parse_log "$line")
        IFS="|" read -r user ip <<< "$parsed"

        [[ -z "$user" || -z "$ip" ]] && continue

        echo "[LOG] $user from $ip"


	if is_whitelisted_ip "$ip"; then
    		echo "[INFO] Skipping trusted IP: $ip"
   		 continue
	fi

        record_attempt "$ip" "$user"
        calculate_and_update_scores "$ip" "$user"
        decide_action "$ip" "$user"
	check_multi_layer_attack "$user"
	# increment counter
	counter=$((counter + 1))

	# decay every 10 attempts
	if (( counter % 10 == 0 )); then
    		echo "[INFO] Applying score decay..."
    		decay_scores
	fi




    done
fi
