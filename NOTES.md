_This file will be removed as from the first stable release of the plugin._

# Unported changes so far

## OIDC chaining support

```java
// Custom query parameter indicating the login method (NOT CRITICAL)
String kcLoginMethod = userSession.getNote(OID4VPUserAuthBean.PARAM_LOGIN_METHOD);
if (kcLoginMethod != null) {
    redirectUri.addParam(OID4VPUserAuthBean.PARAM_LOGIN_METHOD, kcLoginMethod);
}
```

# Consequential changes as we ported code to this plugin version

- The realm migration logic was moved to `OID4VPUserAuthEndpointFactory`.
