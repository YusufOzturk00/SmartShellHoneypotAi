#!/bin/bash
hostname prod-db-01

# Hosts
echo "192.168.1.100  prod-db-01 prod-db-01.finansbank.local" >> /etc/hosts 2>/dev/null || true
echo "192.168.1.101  redis-01.finansbank.local" >> /etc/hosts 2>/dev/null || true
echo "192.168.1.10   backup-srv.finansbank.local" >> /etc/hosts 2>/dev/null || true

# Container izlerini gizle
rm -f /.dockerenv 2>/dev/null
rm -rf /run/.containerenv 2>/dev/null

# Sahte processler
exec -a "postgres: writer process" sleep infinity &
exec -a "postgres: checkpointer" sleep infinity &
exec -a "redis-server *:6379" sleep infinity &
exec -a "nginx: master process" sleep infinity &
exec -a "nginx: worker process" sleep infinity &

# Canary watcher
if [ -f /usr/local/bin/canary_watcher.sh ]; then
    /usr/local/bin/canary_watcher.sh &
fi

# Login banner
cat /etc/motd 2>/dev/null

exec "$@"
