#!/bin/bash

# 监测 vps 突然高占用的情况
LOGFILE="/var/log/xxx_watchdog.log"
CPU_USAGE_THRESHOLD=75  # CPU 占用阈值
MEMORY_USAGE_THRESHOLD=75   # 内存占用阈值

while true
do
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$CPU_USAGE > $CPU_USAGE_THRESHOLD" | bc -l) )) || (( $(echo "$MEMORY_USAGE > $MEMORY_USAGE_THRESHOLD" | bc -l) ))
    then
        echo "$(date) - high resource usage detected: CPU: $CPU_USAGE%, Memory: $MEMORY_USAGE%" >> $LOGFILE # 高占用信息
        echo "Top CPU consuming processes:" >> $LOGFILE
        ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%cpu | head -n 5 >> $LOGFILE  # CPU 占用最高的进程
        
        echo "Top memory consuming processes:" >> $LOGFILE
        ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%mem | head -n 5 >> $LOGFILE  # 内存占用最高的进程信息
    fi
    sleep 60    # 60s
done
