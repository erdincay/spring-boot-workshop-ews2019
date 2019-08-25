# Spring Boot Workshop 2.1

## Aufgabenkomplex 3

Der Aufgabenkomplex befasst sich mit der Erstellung von Services in Spring Boot. 
Ziel ist, die vorhandene Domain-Logik aus dem REST-Controller `PetShopRestController` heraus in einen Domain-Service zu verschieben. 

### Aufgabe 3.1: Erstelle Domain-Service

Erstelle einen Domain-Service `de.osp.springbootworkshop.domain.service.PetShopService` mit der Domain-Logik aus `PetShopRestController`. 
Des weiteren sollen die Exceptions `PetShopApiException`, `PetAlreadyExistsException` und `PetNotExistsException` in 
`de.osp.springbootworkshop.domain.service` verschoben werden. Die temporäre Persistierung mittels
`Map<String, Pet>` soll ebenfalls aus `PetShopRestController` in den neuen Domain-Service `PetShopService` verschoben werden.

### Aufgabe 3.2: Injiziere Domain-Service in REST-Controller und delegiere API-Aufrufe

Der Domain-Service `PetShopService` soll via Constructor-Injection in den `PetShopRestController` injiziert werden. 
Anschließend sollen die REST-Endpunkt die API vom Domain-Service `PetShopService` verwenden. 
Teste, ob sich die REST-Endpunkte weiterhin korrekt verhalten.

**_HINWEIS:_** Die Annotation `@Autowired` ist bei Constructor-Injection nicht nötig solange nur ein Konstruktor existiert.

**_HINWEIS:_** Wenn der Mock-MVC-Test aus Aufgabenkomplex 2 verwendet wird, muss diesem per Annotation `@Import` der neue Domain-Service
bekannt gemacht werden. Ansonsten wird der Service nicht automatisch in den Application-Context geladen und die Tests schlagen fehl! 

### Zusatzaufgabe: Mocke Domain-Service im WEB-MVC-Test

Der `PetShopRestControllerTest` soll so angepasst werden, dass der `PetShopRestController` einen Mock von `PetShopService` verwendet. 
Für das Mocken von Beans wird das Mock-Framwork Mockito verwendet, jedoch muss die Bean statt per `@Mock` mit `@MockBean` annotiert werden,
damit diese im Application-Context registriert wird.

**_DOKUMENTATION:_**
[Spring Boot Mocking and Spying Beans](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-testing.html#boot-features-testing-spring-boot-applications-mocking-beans)

**_HINWEIS:_** Wenn eine Bean gemockt und deren Verhalten beschrieben und überprüft werden soll, benötigt diese die Annotationen `@MockBean` 
und `@Autowired`.

**_HINWEIS:_** Wenn eine Bean mit `@MockBean` annotiert wird, wird in Abhängigkeit ob es sich um ein Interface oder eine Klasse handelt, ggf. 
auf transitive Abhängigkeiten überprüft. Bei letzterem können transitive Abhängigkeiten vorkommen, wenn entweder nur ein Constructor existiert 
oder ein Constructor mit `@Autowired` annotiert ist. Entsprechend müssen dessen Abhängigkeiten ebenfalls mit `@MockBean` gemockt werden. 
Um transitive Abhängigkeiten zu vermeiden, empfiehlt es sich, ein Interface aus der Klasse zu extrahieren und dieses mit `@MockBean` zu mocken.

**_HINWEIS:_** Das Mock-Framwork Mockito ist Teil der Abhängigkeit `org.springframework.boot:spring-boot-starter-test`. 
Für mehr Informationen zum Mock-Framework Mockito siehe [Reference Documentation](https://site.mockito.org/)
