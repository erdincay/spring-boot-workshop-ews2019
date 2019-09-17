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

**_HINWEIS:_** Durch das Hinzufügen der Abhängigkeit `spring-boot-starter-security` in der pom.xml werden per default alle
vorhandenen Rest-Endpoints im Projekt gesichert. Der Standardbenutzer lautet "user", das Passwort wird bei jedem Start
der Applikation generiert und auf die Konsole geloggt.


### Aufgabe 6.1: Komplettiere und teste den Security Filter

Es soll der Security Filter `de.osp.springbootworkshop.application.rest.JwtAuthorizationFilter` kompletiert werden.

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
secret
```

**_HINWEIS:_** JWT können mit Hilfe von [jwt.io](https://jwt.io/) enkodiert und dekodiert werden.


**_BEISPIEL REQUEST:_**
```bash
curl -X GET http://localhost:8080/petshop/pets \
     -H "Accept:application/json" \
     -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJBRE1JTiJdfQ.cyCLHQWkQH3MvtvjYhtZZKRhX6gLUzVR_QMBGNvQH2s"
```


**_DOKUMENTATION:_** [Spring Boot HTTP Security](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jc-httpsecurity),
[HttpSecurity Java Doc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/builders/HttpSecurity.html)

### Zusatzaufgabe: Erstelle und teste Web-MVC-Test hinsichtlich Security mit JWT

Der `PetShopRestController` soll hinsichtlich Security getestet werden für die folgenden Szenarien:

| REST-Endpoint       | Szenario                                    | Erwartung                                            |
|:--------------------|:--------------------------------------------|:-----------------------------------------------------|
| `GET /petshop/pets` | Keine credentials bzw. Authentifizierung    | HTTP-Status-Code `401` bzw `HttpStatus#UNAUTHORIZED` |
| `GET /petshop/pets` | Invalide Credentials bzw. Authentifizierung | HTTP-Status-Code `401` bzw `HttpStatus#UNAUTHORIZED` |
| `GET /petshop/pets` | Invalide Rolle bzw. Autorisierung           | HTTP-Status-Code `403` bzw. `HttpStatus#FORBIDDEN`   |

Dazu soll ein neuer Web-MVC-Test `de.osp.springbootworkshop.application.rest.PetShopRestControllerSecurityTest` erstellt werden. 
Durch die `MockMvcConfig`, welche mit `@TestConfiguration` annotiert ist, wird die Bean `MockMvc` so konfiguriert, 
dass die zuvor konfigurierte Spring Security verwendet wird.

```java
// other imports omitted

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// omitted annotations
public class PetShopRestControllerSecurityTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    @MockBean
    private PetShopService service;

    @Autowired
    private ObjectMapper objectMapper;

    @TestConfiguration
    public static class MockMvcConfig {
        @Bean
        public MockMvc mockMvc(WebApplicationContext applicationContext) {
            return MockMvcBuilders.webAppContextSetup(applicationContext)
                    .apply(springSecurity())
                    .build();
        }
    }

    // tests omitted
}
```

**_DOKUMENTATION:_**
[Spring Boot Security Request Builders](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#securitymockmvcrequestbuilders),
[Spring Boot Security Request Matchers](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#securitymockmvcresultmatchers),
[SecurityMockMvcRequestPostProcessors Java Doc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/test/web/servlet/request/SecurityMockMvcRequestPostProcessors.html)

**_HINWEIS:_** Wenn im Web-MVC-Test eine Authentifizierung gegen einen Endpoint erfolgen soll, z.B. mit HTTP-Basic-Auth, muss beim Bauen 
des Requests `MockHttpServletRequestBuilder#with(RequestPostProcessor)` aufgerufen und
`SecurityMockMvcRequestPostProcessors#httpBasic(String, String)` verwendet werden. Wenn dagegen
`SecurityMockMvcRequestPostProcessors#user(String)` aufgerufen wird, wird dieser Benutzer bereits als erfolgreich authentifiziert angesehen 
und ggf. invalide Credentials ignoriert.
