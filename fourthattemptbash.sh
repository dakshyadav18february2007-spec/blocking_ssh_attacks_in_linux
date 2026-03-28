#!/bin/bash
Mode="live"
LOG_FILE="auth_tracker.log"
touch "$LOG_FILE"


ALERT_FILE="alerts.log"
touch "$ALERT_FILE"

log_alert() {
    type="$1"
    key="$2"
    now=$(date +%s)

    # get last alert time
    last=$(grep "^$type|$key|" "$ALERT_FILE" | tail -1 | cut -d'|' -f3)

    cooldown=60  # default

    # custom cooldowns
    if [[ "$type" == "BLOCK_IP" ]]; then
        cooldown=300
    elif [[ "$type" == "BLOCK_PAIR" ]]; then
        cooldown=60
    elif [[ "$type" == "SUSPICIOUS_USER" ]]; then
        cooldown=600
    fi

    # skip if within cooldown
    if [[ -n "$last" && $((now - last)) -lt $cooldown ]]; then
        return
    fi

    echo "$type|$key|$now" >> "$ALERT_FILE"
    echo "[ALERT] $type: $key"
}






# ----------------------------
# Record login attempt
# ----------------------------
record_attempt() {
    ip="$1"
    user="$2"
    timestamp=$(date +%s)

    echo "$timestamp|$ip|$user" >> "$LOG_FILE"
}   

# ----------------------------
# Get logs within time window
# ----------------------------
get_recent_logs() {
    window=$1
    now=$(date +%s)
    cutoff=$((now - window))

    awk -F'|' -v cutoff="$cutoff" '$1 >= cutoff' "$LOG_FILE"
}

# ----------------------@sS------
# Check IP-based attacks
# ----------------------------
check_ip() {
    ip="$1"

    count=$(get_recent_logs 3600 | awk -F'|' -v ip="$ip" '$2 == ip' | wc -l)

    if [ "$count" -gt 10 ]; then
       log_alert "BLOCK_IP" "$ip"
    fi
}

# ----------------------------
# Check user total attempts
# ----------------------------
check_user_attempts() {
    user="$1"

    count=$(get_recent_logs 86400 | awk -F'|' -v user="$user" '$3 == user' | wc -l)

    if [ "$count" -gt 50 ]; then
        #echo "LOCK_USER: $user"
	"LOCK_R: ""$user"
    fi
}

# ----------------------------
# Check unique IPs per user
# ----------------------------
check_user_unique_ips() {
    user="$1"

    unique_ips=$(get_recent_logs 86400 \
        | awk -F'|' -v user="$user" '$3 == user {print $2}' \
        | sort -u \
        | wc -l)

    if [ "$unique_ips" -gt 20 ]; then
        log_alert "SUSPICIOUS_USER" "$user"

    fi
}

# ----------------------------
# Check IP+User pair
# ----------------------------
check_pair() {
    ip="$1"
    user="$2"

    count=$(get_recent_logs 3600 \
        | awk -F'|' -v ip="$ip" -v user="$user" '$2 == ip && $3 == user' \
        | wc -l)

    if [ "$count" -gt 5 ]; then
       log_alert "BLOCK_PAIR" "$ip->$user"
    fi
}

# ----------------------------
# Multi-day persistence detection
# ----------------------------
check_user_days() {
    user="$1"

    days=$(awk -F'|' -v user="$user" '
    $3 == user {
        day = strftime("%Y-%m-%d", $1)
        print day
    }' "$LOG_FILE" | sort -u | wc -l)

    if [ "$days" -gt 3 ]; then
        echo"PERSISTENT_ATTACK: $user targeted over $days days"
    fi
}

# ----------------------------
# Master check
# ----------------------------
check_all() {
    ip="$1"
    user="$2"

    check_ip "$ip"
    check_user_attempts "$user"
    check_user_unique_ips "$user"
    check_pair "$ip" "$user"
    check_user_days "$user"
}

# ----------------------------
# Example usage
# ----------------------------

# Simulate attempts
# record_attempt "192.168.1.1" "daksh"
# record_attempt "192.168.1.2" "daksh"

# Run detection
# check_all "192.168.1.1" "daksh"
#
#


parse_log() {
    line="$1"

    echo "$line" | awk '
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
            print user, ip;
    }'
}




echo "[INFO] Monitoring SSH failed login attempts..."

if [[ "$Mode" == "test" ]]; then
	echo "[INFO] Resetting logs for clean test"
> "$LOG_FILE"
> alerts.log
    echo "[INFO] Running in TEST mode"
    # ----------------------------
    # TEST 1: Same IP brute force
    # ----------------------------
    echo "[TEST] Same IP brute force"
    for i in {1..12}; do
        ip="192.168.1.10"
        user="daksh"

        echo "[TEST] $user from $ip"
        record_attempt "$ip" "$user"
        check_all "$ip" "$user"

        sleep 0.5
    done
    >"$LOG_FILE"

    # ----------------------------
    # TEST 2: Distributed attack
    # ----------------------------
    echo "[TEST] Distributed attack (many IPs → one user)"
    for i in {1..25}; do
        ip="192.168.1.$i"
        user="daksh"

        echo "[TEST] $user from $ip"
        record_attempt "$ip" "$user"
        check_all "$ip" "$user"

        sleep 0.2
    done
    
    >"$LOG_FILE"

    # ----------------------------
    # TEST 3: Pair attack
    # ----------------------------
    echo "[TEST] Pair attack (same IP + same user)"
    for i in {1..8}; do
        ip="10.0.0.5"
        user="admin"

        echo "[TEST] $user from $ip"
        record_attempt "$ip" "$user"
        check_all "$ip" "$user"

        sleep 0.5
    done

    >"$LOG_FILE"
    # ----------------------------
    # TEST 4: Slow attack simulation
    # ----------------------------
    echo "[TEST] Slow attack simulation"

    base_time=$(date +%s)

    for i in {1..5}; do
        ip="172.16.0.$i"
        user="victim"

        fake_time=$((base_time - i*3600))  # 1 hour apart

        echo "$fake_time|$ip|$user" >> "$LOG_FILE"

        echo "[TEST] (slow) $user from $ip at past time"

    done

    check_all "172.16.0.1" "victim"
    
    >"$LOG_FILE"


else

	sudo journalctl -f -o cat | grep --line-buffered "Failed password" | while read -r line; do

#    echo "[DEBUG] RAW: $line"

    parsed=$(echo "$line" | awk '
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
    }')

 #   echo "[DEBUG] PARSED: $parsed"

    IFS="|" read -r user ip <<< "$parsed"

    if [[ -z "$user" || -z "$ip" ]]; then
        continue
    fi

    echo "[LOG] Attempt detected: $user from $ip"

    record_attempt "$ip" "$user"
    check_all "$ip" "$user"

    done


fi




##Here if we see we have not yet solved the problem of slow , below threshhold distributed attacks , don't worry we will solve it using a score system , we will do it in fifth attempt , Bye for now !!
