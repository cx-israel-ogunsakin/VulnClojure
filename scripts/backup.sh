#!/bin/bash
# VULNERABILITY: Hardcoded credentials in shell script (CWE-798)
# VULNERABILITY: Insecure file permissions

DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="sample"
DB_USER="admin"
DB_PASSWORD="SuperSecretPassword123!"  # Hardcoded password

BACKUP_DIR="/tmp/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# VULNERABILITY: Password exposed in command line (CWE-214)
PGPASSWORD=$DB_PASSWORD pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER $DB_NAME > $BACKUP_DIR/backup_$TIMESTAMP.sql

# VULNERABILITY: World-readable backup files
chmod 777 $BACKUP_DIR/backup_$TIMESTAMP.sql

# VULNERABILITY: Sending credentials via insecure channel
curl -X POST "http://backup-server.example.com/notify" \
  -d "backup_complete=true&db_password=$DB_PASSWORD"

echo "Backup completed: $BACKUP_DIR/backup_$TIMESTAMP.sql"
