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


echo -e "\n=== IP-based Alerts ==="
sudo journalctl --no-pager | grep -i "Failed password" \
| awk '{
    ip="";
    for(i=1;i<=NF;i++) {
        if($i=="from") ip=$(i+1);
    }
    if(ip!="") print ip;
}' \
| sort | uniq -c \
| awk '$1 >= 3 {
    print "[ALERT] Possible brute force from IP " $2 \
          " (" $1 " total attempts across users)"
}'






#The output of this attempt is 



#┌──(daksh㉿daksh)-[~/lsavproject]
#└─$ bash thirdattemptbash.sh
#=== Failed Login Attempts ===
#daksh (::1) -> 3 attempts
#wronguser (::1) -> 6 attempts

#=== Alerts ===
#[ALERT] Possible intrusion from ::1 trying to access user daksh (3 failed attempts)
#[ALERT] Possible intrusion from ::1 trying to access user wronguser (6 failed attempts)

#=== IP-based Alerts ===
#[ALERT] Possible brute force from IP ::1 (9 total attempts across users)


#It has a flaw since the beginning that it counts the attempts since start of the journalctl  but do we really need that ->No as normal user can also have threshold number of failed attempts if the journalctl is not cleared time to time ie journalctl is old enough 

# so in next attempt i will try to add --since "time" feature which will check only for recent journalctl hence will be more accurate
#
#
#
#
#
#
# also what about slow distributed attacks ?? Think
# Don't worry we got it covered in next attempt!!

