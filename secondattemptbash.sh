#!/bin/bash

data=$(sudo journalctl --no-pager | grep -i "Failed password" \
| awk '{
    user=""; ip="";
    for(i=1;i<=NF;i++) {

        if($i=="for") {
            if($(i+1)=="invalid" && $(i+2)=="user")
                user=$(i+3);
            else
                user=$(i+1);
        }

        if($i=="from") ip=$(i+1);
    }

    if(user!="" && ip!="") print user, ip;
}' \
| sort | uniq -c)



echo "=== Failed Login Attempts ==="

echo "$data" | while read count user ip
do
    echo "$user ($ip) -> $count attempts"
done

echo -e "\n=== Alerts ==="

echo "$data" | awk '$1 >= 3 {
    print "[ALERT] Possible intrusion from " $3 \
          " trying to access user " $2 \
          " (" $1 " failed attempts)"
}'

#Did you see something strange in the output ??


#┌──(daksh㉿daksh)-[~/lsavproject]
#└─$ bash secondattemptbash.sh 
#=== Failed Login Attempts ===
#daksh (::1) -> 3 attempts
#wronguser (::1) -> 6 attempts

#=== Alerts ===
#[ALERT] Possible intrusion from ::1 trying to access user daksh (3 failed attempts)
#[ALERT] Possible intrusion from ::1 trying to access user wronguser (6 failed attempts)



#Ans : Same ip is trying to access multiple accounts but if the threshold for one user is not reached then it will not be marked alert that means 
#Scenario can happen

# hacker tries user1  threshold-1 times
# then tries user2 threshold-1 times
# then tries user3 threshold-1 times
#
# was he flagged as danger   - > NO   but is he dangerous -> YES
#
# So in next attempt i will flag the attacker ip based on his total number of attempts on the machine's  all users 
#
#
# This is called a distributed attack across users
