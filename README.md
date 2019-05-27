# Spring Boot Workshop 2.0

## Aufgabenkomplex 5

Der Aufgabenkomplex befasst sich mit der Absicherung der Anwendung mit Spring-Security. Ziel ist es, den `PetShopRestController` mit einer
Authentifizierung und Autorisierung mit Boardmitteln von Spring-Security umzusetzen.

**_HINWEIS:_** Durch das Hinzufügen der Abhängigkeit `spring-boot-starter-security` in der pom.xml werden per default alle
vorhandenen Rest-Endpoints im Projekt gesichert. Der Standardbenutzer lautet "user", das Passwort wird bei jedem Start
der Applikation generiert und auf die Konsole geloggt.

### Aufgabe 5.1: Erstellen einer Security-Konfiguration

Es soll eine Konfiguration `de.osp.springbootworkshop.application.config.SecurityConfig` erstellt werden, 
welche von `WebSecurityConfigurerAdapter` ableitet.


### Aufgabe: 5.2: Erstelle Benutzer im In-Memory-Realm

In der `SecurityConfig` soll die Methode `WebSecurityConfigurerAdapter#configure(AuthenticationManagerBuilder)` überschrieben werden. 
In der neuen Methode sollen mit Hilfe von `AuthenticationManagerBuilder` Benutzer in einem In-Memory-Realm angelegt werden. 
Dabei soll der Benutzername, das Passwort und Role(n) gesetzt werden.

Es sollen die folgenden Benutzer angelegt werden:

| Benutzer   | Passwort         | Rolle(n)   |
|:-----------|:-----------------|:-----------|
| `admin`    | `{noop}admin`    | `ADMIN`    |
| `customer` | `{noop}customer` | `CUSTOMER` |
| `supplier` | `{noop}supplier` | `SUPPLIER` |


**_BEISPIEL:_**
```java
// annotations omitted
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("myuser").password("{noop}mypassword").roles("MYROLE");
    }
}
```

**_DOKUMENTATION:_**
[AuthenticationManagerBuilder Java Doc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/authentication/builders/AuthenticationManagerBuilder.html)

**_HINWEIS:_** Bei der Angabe des Passworts sollte als Prefix `{noop}` verwendet werden, wenn das Passwort im Klartext hinterlegt ist. 
Damit wird der `PasswordEncoder` für Klartext verwendet und keine Operation (wie z.B. MD5 oder SHA-256) auf den darauf folgenden
String angewendet.


### Aufgabe 5.3: Erstelle und teste Absicherung von Endpoints

In der `SecurityConfig` soll die Methode `WebSecurityConfigurerAdapter#configure(HttpSecurity)` überschrieben werden, um 
die Absicherung von HTTP-Endpoints anpassen zu können. Mit Hilfe von `HttpSecurity` sollen die HTTP-Endpoints von `/actuator` und `/h2-console` 
weiterhin ohne Absicherung erreichbar sein. Die HTTP-Endpoints vom `PetShopRestController` sollen
hingegen mit HTTP-Basic-Auth abgesichert werden und es soll ein zustandsloses Session-Management verwendet werden.

| HTTP-Methode | Ressource              | Rolle(n)            |
|:-------------|:-----------------------|:--------------------|
| GET          | `/petshop/pets`        | `ADMIN`, `CUSTOMER` |
| POST         | `/petshop/pets`        | `ADMIN`             |
| DELETE       | `/petshop/pets/{name}` | `ADMIN`             |

**_BEISPIEL:_**
```java
// annotations omitted
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/my-open-endpoint/**").permitAll()
            .antMatchers(HttpMethod.GET, "/my-closed-endpoint/**").hasAnyRole("MYROLE")
            .anyRequest().authenticated()
            .and()
            .httpBasic()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}

```

**_DOKUMENTATION:_** [Spring Boot HTTP Security](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jc-httpsecurity),
[HttpSecurity Java Doc](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/builders/HttpSecurity.html)

**_HINWEIS:_** Die relative Pfadangabe der jeweiligen Resource erfolgt in der ANT-Pfad-Notation. Verwende `?` um ein 
beliebiges Zeichen zu matchen. Verwende `*` um keins, eins oder mehrere Zeichen zu matchen. 
Verwende `**` um keins, eins oder mehrere Sub-Resourcen im Pfad zu matchen.


### Zusatzaufgabe: Erstelle und teste Web-MVC-Test hinsichtlich Security

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
