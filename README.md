# Adminer Installation Guide

Adminer is a free and open-source Database Management. A full-featured database management tool written in PHP

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 80 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 80 (default adminer port)
  - Firewall rules configured
- **Dependencies**:
  - php, php-mysql, php-pgsql
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install adminer
sudo dnf install -y adminer php, php-mysql, php-pgsql

# Enable and start service
sudo systemctl enable --now httpd

# Configure firewall
sudo firewall-cmd --permanent --add-service=adminer || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
adminer --version || systemctl status httpd
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install adminer
sudo apt install -y adminer php, php-mysql, php-pgsql

# Enable and start service
sudo systemctl enable --now httpd

# Configure firewall
sudo ufw allow 80

# Verify installation
adminer --version || systemctl status httpd
```

### Arch Linux

```bash
# Install adminer
sudo pacman -S adminer

# Enable and start service
sudo systemctl enable --now httpd

# Verify installation
adminer --version || systemctl status httpd
```

### Alpine Linux

```bash
# Install adminer
apk add --no-cache adminer

# Enable and start service
rc-update add httpd default
rc-service httpd start

# Verify installation
adminer --version || rc-service httpd status
```

### openSUSE/SLES

```bash
# Install adminer
sudo zypper install -y adminer php, php-mysql, php-pgsql

# Enable and start service
sudo systemctl enable --now httpd

# Configure firewall
sudo firewall-cmd --permanent --add-service=adminer || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
adminer --version || systemctl status httpd
```

### macOS

```bash
# Using Homebrew
brew install adminer

# Start service
brew services start adminer

# Verify installation
adminer --version
```

### FreeBSD

```bash
# Using pkg
pkg install adminer

# Enable in rc.conf
echo 'httpd_enable="YES"' >> /etc/rc.conf

# Start service
service httpd start

# Verify installation
adminer --version || service httpd status
```

### Windows

```powershell
# Using Chocolatey
choco install adminer

# Or using Scoop
scoop install adminer

# Verify installation
adminer --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /var/www/adminer

# Set up basic configuration
sudo tee /var/www/adminer/adminer.conf << 'EOF'
# Adminer Configuration
post_max_size = 256M, upload_max_filesize = 256M
EOF

# Set appropriate permissions
sudo chown -R adminer:adminer /var/www/adminer || \
  sudo chown -R $(whoami):$(whoami) /var/www/adminer

# Test configuration
sudo adminer --test || sudo httpd configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false adminer || true

# Secure configuration files
sudo chmod 750 /var/www/adminer
sudo chmod 640 /var/www/adminer/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable httpd

# Start service
sudo systemctl start httpd

# Stop service
sudo systemctl stop httpd

# Restart service
sudo systemctl restart httpd

# Reload configuration
sudo systemctl reload httpd

# Check status
sudo systemctl status httpd

# View logs
sudo journalctl -u httpd -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add httpd default

# Start service
rc-service httpd start

# Stop service
rc-service httpd stop

# Restart service
rc-service httpd restart

# Check status
rc-service httpd status

# View logs
tail -f /var/log/httpd/httpd.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'httpd_enable="YES"' >> /etc/rc.conf

# Start service
service httpd start

# Stop service
service httpd stop

# Restart service
service httpd restart

# Check status
service httpd status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start adminer
brew services stop adminer
brew services restart adminer

# Check status
brew services list | grep adminer

# View logs
tail -f $(brew --prefix)/var/log/adminer.log
```

### Windows Service Manager

```powershell
# Start service
net start httpd

# Stop service
net stop httpd

# Using PowerShell
Start-Service httpd
Stop-Service httpd
Restart-Service httpd

# Check status
Get-Service httpd

# Set to automatic startup
Set-Service httpd -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /var/www/adminer/adminer.conf << 'EOF'
# Performance tuning
post_max_size = 256M, upload_max_filesize = 256M
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart httpd
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream adminer_backend {
    server 127.0.0.1:80;
    keepalive 32;
}

server {
    listen 80;
    server_name adminer.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name adminer.example.com;

    ssl_certificate /etc/ssl/certs/adminer.crt;
    ssl_certificate_key /etc/ssl/private/adminer.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://adminer_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName adminer.example.com
    Redirect permanent / https://adminer.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName adminer.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/adminer.crt
    SSLCertificateKeyFile /etc/ssl/private/adminer.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:80/
        ProxyPassReverse http://127.0.0.1:80/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:80/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend adminer_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/adminer.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend adminer_backend

backend adminer_backend
    balance roundrobin
    option httpchk GET /health
    server adminer1 127.0.0.1:80 check
```

### Caddy Configuration

```caddy
adminer.example.com {
    reverse_proxy 127.0.0.1:80 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /var/www/adminer adminer || true

# Set ownership
sudo chown -R adminer:adminer /var/www/adminer
sudo chown -R adminer:adminer /var/log/httpd

# Set permissions
sudo chmod 750 /var/www/adminer
sudo chmod 640 /var/www/adminer/*
sudo chmod 750 /var/log/httpd

# Configure firewall (UFW)
sudo ufw allow from any to any port 80 proto tcp comment "Adminer"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=adminer
sudo firewall-cmd --permanent --service=adminer --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=adminer
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 80 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/adminer.key \
    -out /etc/ssl/certs/adminer.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=adminer.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/adminer.key
sudo chmod 644 /etc/ssl/certs/adminer.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d adminer.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/adminer.conf
[adminer]
enabled = true
port = 80
filter = adminer
logpath = /var/log/httpd/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/adminer.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE adminer_db;
CREATE USER adminer_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE adminer_db TO adminer_user;
\q
EOF

# Configure connection in Adminer
echo "DATABASE_URL=postgresql://adminer_user:secure_password_here@localhost/adminer_db" | \
  sudo tee -a /var/www/adminer/adminer.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE adminer_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'adminer_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON adminer_db.* TO 'adminer_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://adminer_user:secure_password_here@localhost/adminer_db" | \
  sudo tee -a /var/www/adminer/adminer.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/adminer
sudo chown adminer:adminer /var/lib/adminer

# Initialize database
sudo -u adminer adminer init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
adminer soft nofile 65535
adminer hard nofile 65535
adminer soft nproc 32768
adminer hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /var/www/adminer/performance.conf
# Performance configuration
post_max_size = 256M, upload_max_filesize = 256M

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart httpd
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'adminer'
    static_configs:
      - targets: ['localhost:80/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/adminer-health

# Check if service is running
if ! systemctl is-active --quiet httpd; then
    echo "CRITICAL: Adminer service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 80 2>/dev/null; then
    echo "CRITICAL: Adminer is not listening on port 80"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:80/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: Adminer is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/adminer
/var/log/httpd/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 adminer adminer
    postrotate
        systemctl reload httpd > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/adminer
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/adminer-backup

BACKUP_DIR="/backup/adminer"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/adminer_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping Adminer service..."
systemctl stop httpd

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /var/www/adminer \
    /var/lib/adminer \
    /var/log/httpd

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump adminer_db | gzip > "$BACKUP_DIR/adminer_db_$DATE.sql.gz"
fi

# Start service
echo "Starting Adminer service..."
systemctl start httpd

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/adminer-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping Adminer service..."
systemctl stop httpd

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql adminer_db
fi

# Fix permissions
chown -R adminer:adminer /var/www/adminer
chown -R adminer:adminer /var/lib/adminer

# Start service
echo "Starting Adminer service..."
systemctl start httpd

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status httpd
sudo journalctl -u httpd -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 80
sudo lsof -i :80

# Verify configuration
sudo adminer --test || sudo httpd configtest

# Check permissions
ls -la /var/www/adminer
ls -la /var/log/httpd
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep httpd
curl -I http://localhost:80

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 80

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep adminer
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep httpd)
htop -p $(pgrep httpd)

# Check for memory leaks
ps aux | grep httpd
cat /proc/$(pgrep httpd)/status | grep -i vm

# Analyze logs for errors
grep -i error /var/log/httpd/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U adminer_user -d adminer_db -c "SELECT 1;"
mysql -u adminer_user -p adminer_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /var/www/adminer/adminer.conf

# Restart with debug mode
sudo systemctl stop httpd
sudo -u adminer adminer --debug

# Watch debug logs
tail -f /var/log/httpd/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep httpd) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/adminer.pcap port 80
sudo tcpdump -r /tmp/adminer.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep httpd)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  adminer:
    image: adminer:adminer
    container_name: adminer
    restart: unless-stopped
    ports:
      - "80:80"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/var/www/adminer
      - ./data:/var/lib/adminer
      - ./logs:/var/log/httpd
    networks:
      - adminer_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  adminer_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# adminer-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: adminer
  labels:
    app: adminer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: adminer
  template:
    metadata:
      labels:
        app: adminer
    spec:
      containers:
      - name: adminer
        image: adminer:adminer
        ports:
        - containerPort: 80
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /var/www/adminer
        - name: data
          mountPath: /var/lib/adminer
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: adminer-config
      - name: data
        persistentVolumeClaim:
          claimName: adminer-data
---
apiVersion: v1
kind: Service
metadata:
  name: adminer
spec:
  selector:
    app: adminer
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: adminer-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# adminer-playbook.yml
- name: Install and configure Adminer
  hosts: all
  become: yes
  vars:
    adminer_version: latest
    adminer_port: 80
    adminer_config_dir: /var/www/adminer
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - php, php-mysql, php-pgsql
        state: present
    
    - name: Install Adminer
      package:
        name: adminer
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ adminer_config_dir }}"
        state: directory
        owner: adminer
        group: adminer
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: adminer.conf.j2
        dest: "{{ adminer_config_dir }}/adminer.conf"
        owner: adminer
        group: adminer
        mode: '0640'
      notify: restart adminer
    
    - name: Start and enable service
      systemd:
        name: httpd
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ adminer_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart adminer
      systemd:
        name: httpd
        state: restarted
```

### Terraform Configuration

```hcl
# adminer.tf
resource "aws_instance" "adminer_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.adminer.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install Adminer
    apt-get update
    apt-get install -y adminer php, php-mysql, php-pgsql
    
    # Configure Adminer
    systemctl enable httpd
    systemctl start httpd
  EOF
  
  tags = {
    Name = "Adminer Server"
    Application = "Adminer"
  }
}

resource "aws_security_group" "adminer" {
  name        = "adminer-sg"
  description = "Security group for Adminer"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "Adminer Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update adminer
sudo dnf update adminer

# Debian/Ubuntu
sudo apt update
sudo apt upgrade adminer

# Arch Linux
sudo pacman -Syu adminer

# Alpine Linux
apk update
apk upgrade adminer

# openSUSE
sudo zypper ref
sudo zypper update adminer

# FreeBSD
pkg update
pkg upgrade adminer

# Always backup before updates
/usr/local/bin/adminer-backup

# Restart after updates
sudo systemctl restart httpd
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /var/log/httpd -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze adminer_db

# Check disk usage
df -h | grep -E "(/$|adminer)"
du -sh /var/lib/adminer

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u httpd | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.adminer.org/
- GitHub Repository: https://github.com/adminer/adminer
- Community Forum: https://forum.adminer.org/
- Wiki: https://wiki.adminer.org/
- Docker Hub: https://hub.docker.com/r/adminer/adminer
- Security Advisories: https://security.adminer.org/
- Best Practices: https://docs.adminer.org/best-practices
- API Documentation: https://api.adminer.org/
- Comparison with phpMyAdmin, phpPgAdmin, MySQL Workbench, pgAdmin: https://docs.adminer.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
