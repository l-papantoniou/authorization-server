# Spring Boot Authorization Server

A comprehensive OAuth 2.0 and OpenID Connect (OIDC) Authorization Server built with Spring Boot and Spring Authorization Server.

## ✨ Features

- **OAuth 2.0 Authorization Server** with full OAuth 2.0 protocol support
- **OpenID Connect (OIDC)** support for identity authentication
- **Multiple Grant Types**:
  - Password Grant (Resource Owner Password Credentials)
  - Client Credentials Grant
  - Authorization Code Flow
  - Refresh Token Flow
- **JWT Token Generation** with RSA key pair signing
- **Token Introspection** and revocation endpoints
- **User Authentication** with in-memory user store
- **Client Registration** with configurable scopes and permissions
- **Customizable Token Lifetime** for access and refresh tokens

---

## 🔧 Prerequisites

- **Java 17** or higher
- **Maven 3.6+** or Gradle
---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd authorization-server
```

### 2. Build the Project

```bash
mvn clean install
```

### 3. Run the Application

```bash
mvn spring-boot:run
```

The authorization server will start on **http://localhost:9000**

### 4. Verify It's Running

```bash
curl http://localhost:9000/.well-known/oauth-authorization-server
```

You should see the authorization server metadata response.

---

## 🏗️ Architecture

### Project Structure

```
authorization-server/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/example/authserver/
│   │   │       ├── AuthorizationServerApplication.java
│   │   │       └── config/
│   │   │           └── SecurityConfig.java
│   │   └── resources/
│   │       └── application.yml
│   └── test/
├── pom.xml
└── README.md
```

### Key Components

1. **AuthorizationServerApplication.java**: Main Spring Boot application entry point
2. **SecurityConfig.java**: Security configuration with OAuth2 and OIDC setup
3. **application.yml**: Application configuration properties

### Dependencies

- Spring Boot 3.2.0
- Spring Security 6.x
- Spring Authorization Server 1.2.0
- Nimbus JOSE + JWT library

---

## 🔐 Authentication Scenarios

### Scenario 1: User Authentication (Password Grant)

**Use Case**: A user authenticates with username and password to get a JWT token.

**Registered Users**:
| Username | Password | Role |
|----------|----------|------|
| john.doe | userpass123 | USER |
| admin | adminpass123 | USER, ADMIN |
| alice | alicepass123 | USER |

**Client Configuration**:
- **Client ID**: `user-client`
- **Client Secret**: `user-client-secret`
- **Grant Types**: password, refresh_token
- **Scopes**: openid, profile, email, read, write
- **Access Token Lifetime**: 30 minutes
- **Refresh Token Lifetime**: 8 hours

**Example Request**:
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u user-client:user-client-secret \
  -d "grant_type=password" \
  -d "username=john.doe" \
  -d "password=userpass123" \
  -d "scope=openid profile read write"
```

### Scenario 2: Application Authentication (Client Credentials)

**Use Case**: An application authenticates itself to access APIs (no user involved).

**Client Configuration**:
- **Client ID**: `app-client`
- **Client Secret**: `app-client-secret`
- **Grant Types**: client_credentials
- **Scopes**: api.read, api.write, service.access
- **Access Token Lifetime**: 1 hour

**Example Request**:
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u app-client:app-client-secret \
  -d "grant_type=client_credentials" \
  -d "scope=api.read api.write"
```

### Scenario 3: Authorization Code Flow (Web Applications)

**Use Case**: Most secure flow for web applications with a backend.

**Client Configuration**:
- **Client ID**: `web-app-client`
- **Client Secret**: `web-app-secret`
- **Grant Types**: authorization_code, refresh_token
- **Redirect URIs**: 
  - http://127.0.0.1:8080/login/oauth2/code/web-app-client
  - http://127.0.0.1:8080/authorized

**Authorization Request**:
```
http://localhost:9000/oauth2/authorize?
  response_type=code&
  client_id=web-app-client&
  redirect_uri=http://127.0.0.1:8080/authorized&
  scope=openid profile read&
  state=random_state_string
```

---


## 🌐 API Endpoints

### Authorization Server Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata |
| `GET /.well-known/openid-configuration` | OpenID Connect configuration |
| `GET /oauth2/authorize` | Authorization endpoint |
| `POST /oauth2/token` | Token endpoint |
| `POST /oauth2/introspect` | Token introspection |
| `POST /oauth2/revoke` | Token revocation |
| `GET /oauth2/jwks` | JSON Web Key Set (public keys) |
| `GET /userinfo` | User information endpoint (OIDC) |

### Form Login Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /login` | Login form |
| `POST /login` | Process login |
| `GET /logout` | Logout |

---

## 🧪 Testing

### Using cURL

#### Get Token (Password Grant)
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u user-client:user-client-secret \
  -d "grant_type=password" \
  -d "username=john.doe" \
  -d "password=userpass123" \
  -d "scope=openid profile"
```

#### Get Token (Client Credentials)
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u app-client:app-client-secret \
  -d "grant_type=client_credentials" \
  -d "scope=api.read"
```

#### Refresh Token
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u user-client:user-client-secret \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

#### Introspect Token
```bash
curl -X POST http://localhost:9000/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u user-client:user-client-secret \
  -d "token=YOUR_ACCESS_TOKEN"
```

#### Revoke Token
```bash
curl -X POST http://localhost:9000/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u user-client:user-client-secret \
  -d "token=YOUR_TOKEN" \
  -d "token_type_hint=access_token"
```

### Using Postman

1. Import the authorization server endpoints
2. Use **Basic Auth** with client credentials
3. Send requests with appropriate parameters
   

### Decode JWT Tokens

Visit [jwt.io](https://jwt.io) and paste your access token to see its contents.

