# Secret Agent Sidecar

A sidecar service written in Rust that handles dynamic credential management between application microservices and the KMS (Key Management Service).

## What it does

The **Secret Agent** acts as an intermediary for microservices to securely access database credentials and HMAC keys without managing long-lived secrets directly.

* **Dynamic DB Credentials:** Requests short-lived PostgreSQL credentials from the KMS and automatically rotates them before expiration.
* **Secret Caching:** Keeps valid credentials in memory to serve connected microservices instantly.
* **Unix Domain Socket Interface:** Exposes a local IPC interface over Unix Domain Sockets (UDS) so local application services can retrieve credentials securely over standard file sockets without opening network ports.

---

## How it Works

1. **Initialization:** On startup, the sidecar connects to the KMS via HTTP/gRPC using service authentication tokens.
2. **Credential Fetching:** When requested by an application service via UDS, the agent fetches or generates temporary access credentials from KMS.
3. **IPC Delivery:** The agent returns credentials over the UDS socket (`/var/run/agent-sockets/agent.sock`) to the requesting service (e.g., `auth-service`).

---

## Socket API Protocol

Services communicate with the sidecar by writing simple text commands over the Unix socket:

* **Get DB Username:**
```bash
GET postgres_auth_username
# Response: OK kms_tmp_XXXXXX

```


* **Get DB Password:**
```bash
GET postgres_auth_password
# Response: OK <generated_password>

```


* **Get HMAC Key:**
```bash
GET hmac_key_<key_alias>
# Response: OK <secret_key_bytes>

```



---

## Configuration

Set via environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `KMS_ENDPOINT` | URL of the central KMS service | `http://kms-service:8080` |
| `SOCKET_PATH` | Path to the local Unix socket file | `/var/run/agent-sockets/agent.sock` |
| `TARGET_SERVICE` | Name of the service this sidecar belongs to | `auth-service` |
| `CREDENTIAL_TTL` | Cache duration before requesting new credentials | `300s` |

---

## Local Development & Debugging

You can test the UDS socket directly using `nc` (netcat) or `socat`:

```bash
# Query DB username from the sidecar socket
echo "GET postgres_auth_username" | nc -U /var/run/agent-sockets/agent.sock

```

> **Note:** Clearing database volumes locally during development requires restarting the agent to invalidate cached temporary credentials.