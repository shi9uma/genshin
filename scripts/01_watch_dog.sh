#!/bin/bash

# 监测 vps 突然高占用的情况, 将其记录到日志文件中供排查
LOGFILE="/var/log/xxx_watchdog.log"
CPU_USAGE_THRESHOLD=75  # top, cpu 占用阈值
MEMORY_USAGE_THRESHOLD=75   # free, 内存占用阈值

while true
do
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$CPU_USAGE > $CPU_USAGE_THRESHOLD" | bc -l) )) || (( $(echo "$MEMORY_USAGE > $MEMORY_USAGE_THRESHOLD" | bc -l) ))
    then
        echo "$(date) - high resource usage detected: CPU: $CPU_USAGE%, Memory: $MEMORY_USAGE%" >> $LOGFILE
    fi
    sleep 60    # 60s
done
