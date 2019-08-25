# Spring Boot Workshop 2.1

## Aufgabenkomplex 4

Der Aufgabenkomplex befasst sich mit der Erstellung von Repositories für SQL in Spring Boot. 
Ziel ist, die provisorische Persistenz mit `Map<String, Pet>` aus dem Domain-Service `PetShopService` in eine SQL Datenbank 
zu verschieben. Außerdem soll der Zugriff auf die Datenbank mit Repositories durch Spring-Data erfolgen.

Zur Verwendung von Spring-Data wurde die Klasse `Pet` mit Annotationen ergänzt und eine neue Klasse `PetType` zum
Projekt hinzugefügt. Dies ist für den Einsatz von Java Persistence API (JPA) notwendig. Diese Dinge werden hier vorgegeben,
da Details zu JPA außerhalb des Scopes dieses Workshops liegen.

### Aufgabe 4.1: Initialisiere die Datenbank mit Testdaten

Die SQL Datenbank H2 soll zum Start der Anwendung mit Daten initialisiert werden. Dazu muss eine SQL-Datei unter 
`src/main/resources/data.sql` mit folgendem Inhalt erstellt werden:

```sql
INSERT INTO pet_types (name) VALUES
    ('Hamster'),
    ('Maus'),
    ('Fisch'),
    ('Hund'),
    ('Katze'),
    ('Vogel');

insert into pets (name, type, birth_date, price) values
('Klaus', 'Hamster', to_date('13.04.2019', 'dd.mm.yyyy'), 20);
insert into pets (name, type, birth_date, price) values
('Rubert', 'Hund', to_date('18.09.2018', 'dd.mm.yyyy'), 550);
insert into pets (name, type, birth_date, price) values
('Blacky', 'Katze', to_date('12.12.2018', 'dd.mm.yyyy'), 350);
```

Damit in der Anwendung SQL-Statements geloggt werden, müssen in der `application.properties` folgende Properties ergänzt werden:

```properties
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
```

**_DOKUMENTATION:_**
[Spring Boot Database Initialization](https://docs.spring.io/spring-boot/docs/current/reference/html/howto-database-initialization.html#howto-database-initialization)


### Aufgabe 4.2: Aktivieren der H2 Console

Im Workshop wird H2 als Embedded SQL Datenbank verwendet. Im Aufgabenkomplex 1 wurde bei den Abhängigkeiten die H2 Datenbank 
aus der Kategorie SQL ausgewählt. Diese Abhängigkeit befindet sich in der `pom.xml` des Projekts als `com.h2database:h2`. 
Um sich mit der Datenbank via Browser verbinden zu können, muss zunächst die "H2 Console" in den `application.properties` aktiviert werden.

```properties
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console
```

Nach dem Start der Anwendung ist die H2 Console unter [http://localhost:8080/h2-console]( http://localhost:8080/h2-console) verfügbar 
und man kann sich mit folgenden Anmeldedaten gegen die Datenbank verbinden:

| Bezeichnung  | Wert                 |
|:-------------|:---------------------|
| Driver Class | org.h2.Driver        |
| JDBC URL     | `jdbc:h2:mem:testdb` |
| User Name    | sa                   |
| Password     | -                    |

Die Tabellen `pets` und `pet_types` sollten angelegt und die zuvor mit `data.sql` beschriebenen SQL-DML-Statements ausgeführt worden sein.

**_DOKUMENTATION:_** [Spring Boot H2 Web Console](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-sql.html#boot-features-sql-h2-console)

### Aufgabe 4.3: Implementiere ein Repository

Es soll ein Repository `de.osp.springbootworkshop.domain.repository.PetRepository` für das Entity `Pet` umgesetzt werden. 
Dabei soll `PetRepository` als Interface implementiert werden und von dem Interface `CrudRepository<T,ID>` ableiten.

Überarbeite nun die Klasse `PetShopService` und entferne die provisorische Persistierung. Füge nun das neue Repository
`PetRepository` in den Domain-Service ein und passe die vorhandenen Methoden zur Rückgabe aller Pets, zum Speichern eines
neuen Pets und zum Löschen eines Pets an.

**_DOKUMENTATION:_** [Spring Data Repositories](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#repositories)
[CrudRepository Java Doc](https://docs.spring.io/spring-data/commons/docs/current/api/org/springframework/data/repository/CrudRepository.html)


### Aufgabe 4.4: Erweitern von Repository mit eigenen Queries

Das Repository `PetRepository` soll um eine Methode zur Abfrage einer `List<Pet>` anhand deren Geburtstag erweitert werden. 
Wahlweise kann die Umsetzung des Queries durch den Methodennamen oder durch die Annotation `@Query` erfolgen.

**_DOKUMENTATION:_** [Spring Data Defining Query Methods](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#repositories.query-methods.details),
[Spring Data Query Methods Handling Nullability](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#repositories.nullability),

**_HINWEIS:_** Wenn Queries mit der Annotation `@Query` umgesetzt werden, dann wird standardmäßig das Query im Dialekt `JPQL` erwartet. 
Jedoch kann in der Annotation `@Query` die Angabe `nativeQuery = true` gemacht werden, damit das Query mit dem Dialekt 
der verwendeten Datenbank erwartet wird.


### Zusatzaufgabe: Testen von Repository mit Data-JPA-Test

Die Query-Methode zur Abfrage von `List<Pet>` anhand des Geburtstags soll mit einem Data-JPA-Test getestet werden.

**_DOKUMENTATION:_**
[Spring Data JPA Test](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-testing.html#boot-features-testing-spring-boot-applications-testing-autoconfigured-jpa-test)

**_HINWEIS:_** Das Asssertion-Framwork assertJ ist Teil der Abhängigkeit `org.springframework.boot:spring-boot-starter-test`
([assertJ](http://joel-costigliola.github.io/assertj/)).

**_HINWEIS:_** Standardmäßig werden im Test-Scope die SQL-Skripte `scheme.sql` und `data.sql` ausgeführt. Ist dieses Verhalten im 
Test-Scope nicht gewünscht kann es in `src/test/resources/application.properties` deaktiviert werden.
