# YAuth
## The OIDC/SSO Provider you didn't ask for

### WHY?
I know you could use Authentik, Authelia, Keycloak, (insert some better thing here).

I wanted something stupid simple. No tenants, no realms, no astronomical flows and stage bindings (looking at you authentik).

### WHAT IT DO
It stores some users and allows for OpenID tokens/identities to be used.

### HOW IT DO
I smashed Asp.NET Identity and OpenIddict together and this is what happened.

### HOW I DO
Hopefully it's not so difficult to get running.

#### YOU NEED
- A Certificate Password (up to you)
- Symmetric Encryption Key (just for the tokens, BASE64)

That's it... It stores everything in `/app/storage` so you can point your volume there.

There's an override for the actual db location, I'll post an example below.

```ini
# THIS USES ASP.NET ENV SCHEMES, BETTER THAN NOTHING I GUESS!
# SYSTEM PROPERTIES
ConnectionStrings__DefaultConnection=Data Source=/app/storage/yauth.db

# CRYPTO & CERTIFICATE MANAGER SEEDS
Crypto__CertPassword=SuperSecretHomelabPassword123!
Crypto__EncryptionKey=eGztWK7NMvHAqUZrczQgLKjH8oFSg0ovnknlfahXxGg=

# GLOBAL AUTHENTICATION RULES & TOGGLES
# THESE ARE NOT STAGED, DISABLING REGISTRATION DOES NOT DISABLE EXTERNAL REGISTRATION
# You might have some use for this, I know I already have. You can assign an external role to these on creation... based.
Authentication__AllowRegistration=true
Authentication__AllowExternalRegistration=true

# EXTERNAL PROVIDERS
# You can have as many of whatever as you want, although I don't know why you'd want 2 discord logins.
# I mean theoretically you can prod AF this thing and go full SAAS but why would you do that when Authentik exists.

# Discord Integration, I might make this simpler.
Authentication__Providers__0__Id=discord
Authentication__Providers__0__Type=Discord
Authentication__Providers__0__DisplayName=Login with Discord
Authentication__Providers__0__ClientId=YOUR_DISCORD_CLIENT_ID_HERE
Authentication__Providers__0__ClientSecret=YOUR_DISCORD_CLIENT_SECRET_HERE

# Custom/Federated OIDC 
Authentication__Providers__1__Id=homelab-authentik
Authentication__Providers__1__Type=Custom
Authentication__Providers__1__DisplayName=Homelab SSO
Authentication__Providers__1__ClientId=YOUR_AUTHENTIK_CLIENT_ID_HERE
Authentication__Providers__1__ClientSecret=YOUR_AUTHENTIK_CLIENT_SECRET_HERE
Authentication__Providers__1__Authority=https://yourhomelabdomain.local
```

#### Obligatory Docker Compose
Use Traefik or something, PLEASE DON'T LEAVE IT RAW LIKE THIS DEAR LORD
```yaml
services:
  yauth:
    image: yesnt/yauth:latest
    container_name: yauth_server
    restart: unless-stopped
    ports:
      - "8080:8080" # <-- STINKY
    env_file:
      - .env
    volumes:
      - yauth-data:/app/storage
    
    deploy:
      replicas: 1
      update_config:
        parallelism: 1
        delay: 5s
        order: start-first

volumes:
  yauth-data:
```

## Contributing
Go for it, just follow the regular issue → fork → fix → pr that we all do.
AI is highly discouraged, something something "explain what it does", I might set some code guidelines if anyone else shows up.
Everything is AGPL 3, per usual.

Anything else, check the [Discord](https://discord.gg/7TtkGtqhxN)
![Discord](https://img.shields.io/discord/1529683600843472916?style=plastic)
