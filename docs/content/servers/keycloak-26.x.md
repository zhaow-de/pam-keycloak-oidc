---
title: "Keycloak 26.x"
weight: 10
---

# Keycloak 26.x

Keycloak 19 replaced the old admin console, so the navigation below does not match the
[Keycloak 12.x](./keycloak-12.x/) page. The end state is the same: a confidential client with
the direct access grant enabled, a role the module can match, and that role delivered in a flat
claim of the access token.

## 1. Client and authentication flow

### 1.1. Create the OIDC client

**Clients → Create client:**

| Setting | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | `demo-pam` |
| Client authentication | On |
| Authorization | Off |
| Authentication flow | Standard flow + Direct access grants |
| Valid redirect URIs | `urn:ietf:wg:oauth:2.0:oob` |

Save, then open the **Credentials** tab and copy the client secret into `client-secret`.

`Direct access grants` is the resource-owner password grant this module uses. Without it every
authentication fails at the token endpoint.

### 1.2. Create the client role

**Clients → demo-pam → Roles → Create role:** name it `pam-login`.

This role gates the authentication flow in step 1.3. It is separate from the role the module
matches (step 1.6), so a user can be allowed to authenticate without being allowed onto a
particular host.

### 1.3. Create the authentication flow

**Authentication → Flows →** find `direct grant` **→ ⋮ → Duplicate →** name it `direct grant role`.

The copy already contains Username Validation, Password and Conditional OTP. Keep all three, then
add the role gate:

1. **Add sub-flow** → name `Access_by_role`, Requirement **Conditional**
2. Inside it, **Add execution** → `Condition - user role` → **Required**
3. Configure it (gear icon): Alias `user_role`, User role `demo-pam pam-login`, **Negate output: On**
4. Inside it, **Add execution** → `Deny access` → **Required**

With *Negate output* on, the condition matches users who do **not** hold `pam-login`, and those
users hit `Deny access`. Everyone else falls through and authenticates.

```
Username Validation                     - Required
Password                                - Required
Direct Grant - Conditional OTP          - Conditional
  ├─ Condition - user configured        - Required
  └─ OTP                                - Required
Access_by_role                          - Conditional
  ├─ Condition - user role (Negate=On)  - Required
  └─ Deny access                        - Required
```

### 1.4. Bind the flow to the client

**Clients → demo-pam → Advanced → Authentication flow overrides:** set *Direct Grant Flow* to
`direct grant role` and leave *Browser Flow* empty.

### 1.5. Configure the OTP policy

**Authentication → Required actions:** set *Configure OTP* to Enabled, and *Set as default action*
to On so new users enrol on first login.

**Authentication → Policies → OTP Policy:** set *Look around window* to `2`, which tolerates a
couple of time steps of clock drift between the server and the user's authenticator.

### 1.6. Publish the roles in a flat claim

The module reads roles from one claim, named by `scope` in the configuration file — it does not
walk Keycloak's nested `realm_access.roles`. A client scope with a role mapper produces that flat
claim.

**Client scopes → Create client scope:**

| Field | Value |
|---|---|
| Name | `pam_roles` |
| Type | Default |
| Protocol | OpenID Connect |

Then **pam_roles → Mappers → Configure a new mapper → User Realm Role:**

| Field | Value |
|---|---|
| Name | `realm-roles` |
| Multivalued | On |
| Token Claim Name | `pam_roles` — must equal the scope name |
| Claim JSON Type | String |
| Add to ID token | Off |
| Add to access token | On |
| Add to userinfo | Off |

Finally **Clients → demo-pam → Client scopes → Add client scope →** select `pam_roles` → add it as
**Default**.

> [!NOTE]
> `scope` in the configuration file is both the OAuth2 scope requested and the claim searched for
> roles. The scope name, the *Token Claim Name* above and `scope` in the TOML must all be the same
> string.

### 1.7. Add the audience mapper

A stock Keycloak access token carries `"aud": "account"`, not the client id. Set `verify-audience`
to `true` only after adding this mapper, or every authentication will be rejected.

**Clients → demo-pam → Client scopes →** open `demo-pam-dedicated` **→ Add mapper → By
configuration → Audience:**

| Field | Value |
|---|---|
| Name | `demo-pam-audience` |
| Included Client Audience | `demo-pam` |
| Add to ID token | Off |
| Add to access token | On |

### 1.8. Create one realm role per server group

The module matches a single role, named by `vpn-user-role`. Give each group of hosts its own realm
role, and make each one a composite that includes `pam-login` so the flow in step 1.3 still passes.

**Realm roles → Create role:** e.g. `demo-pam-authentication`. Then inside the role,
**Action → Add associated roles → Filter by clients →** select `demo-pam pam-login` → **Assign**.

Repeat per group — `prod-ssh`, `staging-ssh` and so on. Only `vpn-user-role` differs between those
hosts' configuration files.

### 1.9. Create groups (optional)

**Groups → Create group**, then **Role mapping → Assign role →** pick the realm role. Members
inherit it, which is easier to audit than per-user assignment.

### 1.10. Create users

**Users → Add user**, set *Email verified* On, add **Configure OTP** to *Required user actions*, then
set a password on the **Credentials** tab with *Temporary* Off. Join the user to a group, or assign
the realm role directly.

## 2. LDAP and Active Directory federation

Skip this section if users are created in Keycloak directly.

### 2.1. OpenLDAP

**User Federation → Add new provider → LDAP:**

| Field | Value |
|---|---|
| Vendor | Other |
| Connection URL | `ldap://openldap-host:389` |
| Bind type | simple |
| Bind DN | `cn=admin,dc=example,dc=local` |
| Edit mode | READ_ONLY |
| Users DN | `ou=users,dc=example,dc=local` |
| Username LDAP attribute | `mail` |
| RDN LDAP attribute | `mail` |
| UUID LDAP attribute | `entryUUID` |
| User object classes | `inetOrgPerson, organizationalPerson, person` |
| User LDAP filter | `(mail=*)` |
| Search scope | Subtree |
| Import users | On |

Save, then **Action → Sync all users**.

### 2.2. Active Directory

Export the **root** CA — not the domain controller's leaf certificate — and import it into
Keycloak's truststore before connecting over LDAPS:

```shell
openssl s_client -connect dc01.example.local:636 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > ad-ca-cert.pem
```

**User Federation → Add new provider → LDAP:**

| Field | Value |
|---|---|
| Vendor | Active Directory |
| Connection URL | `ldaps://DC01.example.local:636` |
| Bind DN | `svc-keycloak@example.local` (UPN form) |
| Edit mode | READ_ONLY |
| Users DN | `OU=Users,DC=example,DC=local` |
| Username LDAP attribute | `sAMAccountName` — Keycloak auto-fills `cn`, which is wrong |
| RDN LDAP attribute | `cn` |
| User object classes | `person, organizationalPerson, user` |
| Search scope | Subtree |
| Pagination | On |
| Import users | On |

Use a plain Domain Users service account, and open TCP 636 from Keycloak to the domain controllers.

A filter that excludes computer accounts, disabled accounts and system accounts:

```
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

> [!NOTE]
> Keycloak's *Custom User LDAP Filter* field takes one line. Strip every line break and any extra
> whitespace before pasting a filter that was formatted for reading.

### 2.3. Map directory groups to roles

**User Federation →** the provider **→ Mappers → Add mapper:**

| Field | Value |
|---|---|
| Mapper type | `group-ldap-mapper` |
| LDAP Groups DN | `OU=Groups,DC=example,DC=local` |
| Group Name LDAP Attribute | `cn` |
| Group Object Classes | `group` |
| Membership LDAP Attribute | `member` |
| Membership Attribute Type | DN |
| User Groups Retrieve Strategy | `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE` |
| Mode | READ_ONLY |

Use `LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY` where groups nest. After the sync, assign the
realm role from step 1.8 to the imported group.

### 2.4. Verify

Run **Test connection** and **Test authentication**, save, then **Action → Sync all users** and
search `*` under **Users** to confirm they arrived.

## 3. Matching configuration

The values above line up with the configuration file like this:

| Keycloak | Configuration key |
|---|---|
| Client ID `demo-pam` | `client-id` |
| Credentials tab secret | `client-secret` |
| Client scope / claim `pam_roles` | `scope` |
| Realm role `demo-pam-authentication` | `vpn-user-role` |
| Realm's `.well-known/openid-configuration` → `token_endpoint` | `endpoint-token-url` |
| Realm's `.well-known/openid-configuration` → `jwks_uri` | `jwks-url` |
| Realm's `.well-known/openid-configuration` → `issuer` | `issuer-url` |
| Audience mapper from step 1.7 present | `verify-audience` |

See [the configuration file](../../config) for the full sample.
