<p align="center">
	<a href="https://github.com/tn3w/Redux">
		<picture>
			<source width="800px" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/Redux/releases/download/img/redux-dark.webp">
			<source width="800px" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/Redux/releases/download/img/redux-light.webp">
			<img width="800px" alt="Redux Screenshot" src="https://github.com/tn3w/Redux/releases/download/img/redux-dark.webp">
		</picture>
	</a>
</p>

<h1 align="center">Redux</h1>
<p align="center">A secure link shortener PWA that allows users to create and manage links, with optional end-to-end encryption for enhanced privacy.</p>

## ToDo
- [x] Implement proper native browser history handling for info pages (e.g., when navigating back to URLs like http://127.0.0.1:5000/#eYgGL+).
- [x] Modify the behavior of the info button on the My Links page so that clicking it updates the URL in the address bar to /#id (where id is the identifier of the URL) instead of #info-page and ensure that when users click the "Back" button or navigate back, they are returned to the My Links page instead of the home page.
- [x] Implement logic to display the clear button only when the form contains input content.
- [x] Enhance the displayUrlInfo function by adding a click handler to the "Visit URL" button, which will show users the appropriate redirection page instead of showing the home page and going to /#.

## Installation
1. **Clone this repository**:
   ```bash
   git clone https://github.com/tn3w/Redux.git
   cd Redux
   ```
2. **Create an virtual environment and install dependencies**:
    ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt uvicorn
   ```
3. **Run Redux**:
    ```bash
    python app.py
    ```

## Redis Setup

Redis is required for Redux to function properly. Follow these instructions to set up a Redis server instance with persistent storage, improved performance, and security.

### 1. Install Redis

```bash
sudo apt update
sudo apt install redis-server
```

### 2. Create a Custom Redis Configuration

Create a custom Redis configuration file with optimized settings:

```bash
sudo mkdir -p /etc/redis
sudo nano /etc/redis/redux-redis.conf
```

Add the following configuration (adjust according to your needs):

```
# Network
bind 127.0.0.1
port 6380
protected-mode yes

# Authentication
requirepass YourStrongPasswordHere

# Persistence
dir /var/lib/redis/redux
dbfilename dump.rdb
save 900 1
save 300 10
save 60 10000

# Performance Optimization
maxmemory 500mb
maxmemory-policy allkeys-lru
appendonly yes
appendfsync everysec
no-appendfsync-on-rewrite yes
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
activerehashing yes
```

### 3. Create Persistent Storage Directory

```bash
sudo mkdir -p /var/lib/redis/redux
sudo chown redis:redis /var/lib/redis/redux
sudo chmod 770 /var/lib/redis/redux
```

### 4. Create a Systemd Service

Create a systemd service file to manage the Redis instance:

```bash
sudo nano /etc/systemd/system/redux-redis.service
```

Add the following content:

```
[Unit]
Description=Redis instance for Redux application
After=network.target

[Service]
Type=notify
User=redis
Group=redis
ExecStart=/usr/bin/redis-server /etc/redis/redux-redis.conf
ExecStop=/usr/bin/redis-cli -p 6380 -a YourStrongPasswordHere shutdown
TimeoutStartSec=0
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### 5. Enable and Start the Redis Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable redux-redis
sudo systemctl start redux-redis
```

### 6. Verify Redis is Running

```bash
sudo systemctl status redux-redis
redis-cli -p 6380 -a YourStrongPasswordHere ping
```

Should return `PONG` if everything is working correctly.

### 7. Update Redux Configuration

Update your application configuration to use the new Redis instance:

```python
# Example configuration
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6380
REDIS_PASSWORD = 'YourStrongPasswordHere'
```

## Production Deployment

Follow these instructions to deploy Redux in a production environment with systemd and proper security measures.

### 1. Create a Dedicated User

```bash
sudo useradd -r -s /bin/false redux-app
```

### 2. Set Up Data Directory Structure

```bash
# Create data directory
sudo mkdir -p /var/lib/redux/build

# Set appropriate permissions
sudo chown -R redux-app:redux-app /var/lib/redux
sudo chmod -R 750 /var/lib/redux
```

### 3. Prepare Environment File

Create a .env file with your application configuration:

```bash
sudo nano /var/lib/redux/.env
```

Add your configuration settings:

```
REDIS_HOST=127.0.0.1
REDIS_PORT=6380
REDIS_PASSWORD=YourStrongPasswordHere
# Add other environment variables as needed
```

Secure the .env file:

```bash
sudo chown redux-app:redux-app /var/lib/redux/.env
sudo chmod 600 /var/lib/redux/.env
```

### 5. Create Application Directory and Virtual Environment

```bash
# Create application directory
sudo mkdir -p /opt/redux

# Set up virtual environment
sudo python3 -m venv /opt/redux/.venv
sudo /opt/redux/.venv/bin/pip install --upgrade pip
sudo /opt/redux/.venv/bin/pip install -r requirements.txt uvicorn

# Set proper permissions
sudo chown -R redux-app:redux-app /opt/redux
sudo chmod -R 750 /opt/redux
```

### 6. Build and Copy Templates

```bash
npm run build

# Copy templates and static files
sudo cp -r build/* /var/lib/redux/build/
sudo chown -R redux-app:redux-app /var/lib/redux/build
```

### 7. Copy Application Code

```bash
# Copy application code
sudo cp -r . /opt/redux/
sudo chown -R redux-app:redux-app /opt/redux
```

### 8. Create Systemd Service File

```bash
sudo nano /etc/systemd/system/redux.service
```

Add the following content:

```
[Unit]
Description=Redux Link Shortener
After=network.target redux-redis.service
Requires=redux-redis.service

[Service]
Type=simple
User=redux-app
Group=redux-app
WorkingDirectory=/opt/redux
ExecStart=/opt/redux/.venv/bin/uvicorn asgi:app --host 0.0.0.0 --port 8012 --workers 16
Restart=always
RestartSec=5

Environment="ENV_FILE=/var/lib/redux/.env"
Environment="BUILD_DIR=/var/lib/redux/build"

[Install]
WantedBy=multi-user.target
```

### 9. Enable and Start the Redux Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable redux
sudo systemctl start redux
```

### 10. Verify Service Status

```bash
sudo systemctl status redux
```

### 11. View Application Logs

```bash
sudo journalctl -u redux -f
```

## Attributions

<a href="https://www.flaticon.com/free-icons/letter-r" title="letter r icons">Letter r icons created by Freepik - Flaticon</a>
