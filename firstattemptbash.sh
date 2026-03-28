#!/bin/bash

#echo "=== Failed Login Attempts ==="

#output=`sudo journalctl --no-pager`
#filteroutput=`echo "$output" | grep -i "Failed Password"`
#example of filter output
#Mar 27 22:42:37 daksh sshd-session[104109]: Failed password for invalid user wronguser from ::1 port 48872 ssh2

#requiredData=`echo "$filteroutput" |awk '{for(i=1;i<=NF;i++) if($i=="from") print$(i+1) }'| sort | uniq -c`

#example of requiredData output
#=== Failed Login Attempts ===
#      3 ::1
# first field is number of attempts second field is ip

#possibleintruders=`echo "$requiredData" |awk ' {if($1>=2) print "Possible attack from " $2 }'`



#echo -e "$possibleintruders"


#!/bin/bash

echo "=== Failed Login Attempts ==="

sudo journalctl --no-pager | grep -i "Failed password" \
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
| sort | uniq -c | while read count user ip
do
    echo "$user ($ip) -> $count attempts"
done

echo -e "\n=== Alerts ==="

sudo journalctl --no-pager | grep -i "Failed password" \
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
| sort | uniq -c \
| awk '$1 >= 3 {
    print "[ALERT] Possible intrusion from " $3 \
          " trying to access user " $2 \
          " (" $1 " failed attempts)"
}'




#as we can see we need to compute same thing twice so in next attempt i will store this value so that i could reuse it

