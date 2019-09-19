# Spring Boot Workshop 2.1

## Aufgabenkomplex 6

Der Aufgabenkomplex befasst sich mit der Absicherung der Anwendung mit JWT durch Spring-Security. Ziel ist es, den `PetShopRestController` mit einer
Authentifizierung und Autorisierung mit erweiterten Boardmitteln von Spring-Security umzusetzen. 

zu diesem Aufgabenkomplex wurde bereits eine `de.osp.springworkshop.application.config.SecurityConfig` hinzugefügt.
Diese entspricht im Ken der `SecurityConfig` aus dem Aufgabenkomplex 5.
Abweichend wird kein In-Memory-Realm für die Definition der Benutzer verwendet.
Ferner wird anstelle der Basic Authentication ein Security Filter `de.osp.springbootworkshop.application.rest.JwtAuthorizationFilter` konfiguriert.
Durch den Security Filter soll die Authentifikation durchgeführt werden, dabei soll die Extraktion des Namens und die Rollen des Benutzers für den das JWT Token 
ausgestellt wurde erfolgen.

Der bestehende REST-Controller `de.osp.springbootworkshop.application.rest.PetShopRestController` bei den Endpoint-Methoden um `java.security.Principal` als Argument
und ein logging dessen Namens erweitert.

Desweiteren wurde im Projekt die Abhängigkeit `com.auth0:java-jwt` hinzugefügt, die im Aufgabenkomplex verwendet wird, um mit den JWT zu arbeiten.

**_HINWEIS:_** Durch das Hinzufügen der Abhängigkeit `spring-boot-starter-security` in der pom.xml werden per default alle
vorhandenen Rest-Endpoints im Projekt gesichert. Der Standardbenutzer lautet "user", das Passwort wird bei jedem Start
der Applikation generiert und auf die Konsole geloggt.


### Aufgabe 6.1: Komplettiere den Security Filter

Es soll der Security Filter `de.osp.springbootworkshop.application.rest.JwtAuthorizationFilter` kompletiert werden, so das folgende Schritte implementiert werden:
1. Der HTTP Header `Authorization` muss vom Request abgefragt werden
2. Der HTTP Header `Authorization` muss existiert, nicht leer ist und das Präfix `Bearer` besitzten
3. Das Token muss aus dem HTTP Header `Authorization` extrahiert werden (zwischen `Bearer` und dem eigentlichen Token befindet sich ein Leerzeichen)
4. Das Tokens muss anhand des Algorithmus `HMAC256` mit dem Secret `secret` mit Hilfe von `JWTVerifier` verifiziert werden werden
5. Das Token muss mit Hilfe von `DecodedJWT` dekodiert werden
6. Das Subject muss aus dem dekodierten Token gelesen werden als `String`
7. Die Rollen müssen aus dem dekodierten Token gelesen werden als `List<String>`
8. Die Rollen von String in `SimpleGrantedAuthority` transformieren mit dem Präfix `ROLE_`

Im Fehlerfall soll die Methode `failure()` verwendet werden um eine fehlgeschlagene `Authentication` zu signalisieren.
Im Positivfall soll dagegen die Methode `success(String, List<GrantedAuthority>)` zurück gegeben werden mit den extrahierten Subject und der Liste von Authorities.

```java
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private static final String ROLE_PREFIX = "ROLE_";
    private static final Logger LOG = getLogger(JwtAuthorizationFilter.class);
    private final RequestMatcher requestMatcher;

    public JwtAuthorizationFilter(RequestMatcher requestMatcher,
                                  AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.requestMatcher = requestMatcher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        if (requestMatcher.matches(request)) {
            Authentication authentication = doAuthenticate(request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private Authentication doAuthenticate(final HttpServletRequest request) {
        // TODO: implement me
    }

    private Authentication success(final String subject,
                                   final List<GrantedAuthority> authorities) {
        return new UsernamePasswordAuthenticationToken(new JwtAuthenticatedPrincipal(subject), null, authorities);
    }

    private Authentication failure() {
        return new UsernamePasswordAuthenticationToken(null, null);
    }

    private static class JwtAuthenticatedPrincipal implements AuthenticatedPrincipal {
        private final String name;

        private JwtAuthenticatedPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }
}
```

**_DOKUMENTATION:_** [Auth0 Java JWT](https://github.com/auth0/java-jwt) 


### Aufgabe 6.2: teste den Security Filter

Der zuvor ausimplementierte Security Filter `de.osp.springbootworkshop.application.rest.JwtAuthorizationFilter`  soll anhand folgender Szenarien getestet werden.

| REST-Endpoint       | Szenario                                                        | Erwartung                                            |
|:--------------------|:----------------------------------------------------------------|:-----------------------------------------------------|
| `GET /petshop/pets` | keine HTTP Header `Authorization`                               | HTTP-Status-Code `401` bzw `HttpStatus#UNAUTHORIZED` |
| `GET /petshop/pets` | HTTP Header `Authorization` ohne Präfix `Bearer`                | HTTP-Status-Code `401` bzw `HttpStatus#UNAUTHORIZED` |
| `GET /petshop/pets` | Token mit leerem Claim `sub`                                    | HTTP-Status-Code `401` bzw. `HttpStatus#UNAUTHORIZED`|
| `GET /petshop/pets` | Token mit beliebigen Nutzer in Claim `sub` und keiner Rolle     | HTTP-Status-Code `403` bzw. `HttpStatus#FORBIDDEN`   |
| `GET /petshop/pets` | Token mit beliebigen Nutzer in Claim `sub` und Rolle `SUPPLIER` | HTTP-Status-Code `403` bzw. `HttpStatus#FORBIDDEN`   |
| `GET /petshop/pets` | Token mit beliebigen Nutzer in Claim `sub` und Rolle `ADMIN`    | HTTP-Status-Code `200` bzw. `HttpStatus#OK`          |


**_HINWEIS:_** Tokens können mittels können mit Hilfe von [jwt.io](https://jwt.io/) enkodiert und dekodiert werden.

**_BEISPIEL JWT:_**
```
{
  "alg": "HS256",
  "typ": "JWT"
}
.
{
  "sub": "test",
  "iat": 1516239022,
  "roles": ["ADMIN"]
}
.
<Signature mit HS256 Algorithmus und Secret "secret">
```


**_BEISPIEL REQUEST:_**
```bash
curl -X GET http://localhost:8080/petshop/pets \
     -H "Accept:application/json" \
     -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJBRE1JTiJdfQ.cyCLHQWkQH3MvtvjYhtZZKRhX6gLUzVR_QMBGNvQH2s"
```