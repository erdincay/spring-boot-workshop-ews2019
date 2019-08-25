# Spring Boot Workshop 2.1

## Aufgabenkomplex 1

Dieser Aufgabenkomplex befasst sich mit der Initialisierung von Projekten für Spring Boot. 
Ziel ist es, ein Maven-Projekt zu initialisieren, die Anwendung zu starten und den Actuator aufzurufen.

### Aufgabe 1.1: Initialisieren von Spring Boot Projekt

Es soll ein Projekt mittels [Spring initializr](https://start.spring.io/) initialisiert werden. Dabei sollen folgende Angaben verwendet werden:

| Angabe                          | Wert                                                         |
|:--------------------------------|:-------------------------------------------------------------|
| Project                         | Maven Project                                                |
| Language                        | Java                                                         |
| Spring Boot                     | 2.1.7 oder neuer                                                        |
| Project Metadata > Group        | de.osp                                                       |
| Project Metadata > Artifact     | spring-boot-workshop                                         |
| Project Metadata > Name         | **wird automatisch erzeugt**                                 |
| Project Metadata > Description  | **wird automatisch erzeugt**                                 |
| Project Metadata > Package Name | **wird automatisch erzeugt**                                 |
| Project Metadata > Packing      | JAR                                                          |
| Project Metadata > Java Version | 8                                                           |
| Dependencies                    | Web *\[Web\]*, JPA *\[SQL\]* H2 *\[SQL\]* Actuator *\[Ops\]* |

**_HINWEIS:_** Um alle verfügbaren Dependencies anzuzeigen, klick auf den Link **Dependencies > See all** im Spring initialzr.


### Aufgabe 1.2: Mit der Struktur des Projekts vertraut machen

Es soll sich mit dem generierten Projekt vertraut gemacht werden. Dazu soll ein Blick in die `pom.xml` geworfen werden.
Interessant sind hier vor allem die Angaben zu Artefakt, Abhängigkeiten und dem Build-Prozess für Spring Boot. 
Ferner soll ein Blick in die Hauptklasse der Spring Boot Anwendung unter `de.osp.springbootworkshop.SpringBootWorkshopApplication` bzw. 
dem dazu generierten Test unter `de.osp.springbootworkshop.SpringBootWorkshopApplicationTests` geworfen werden. 
Die Konfiguration der Spring Boot Anwendung wird durch `src/main/resources/application.properties` vorgenommen. Diese Datei 
ist zunächst leer und überschreibt damit nicht die Standard-Konfiguration.


### Aufgabe 1.3: Weitere Actuator Endpoints aktivieren

Es sollen für den Actuator die zusätzlichen REST-Endpoints `GET /actuator/metrics` und `GET /actuator/beans` aktiviert werden. 
Dazu muss muss in der `application.properties` folgende Konfiguration hinzugefügt werden:

```properties
management.endpoints.web.exposure.include=health,info,metrics,beans
```

**_DOKUMENTATION:_**
[Spring Boot Actuator](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html),
[common-application-properties](https://docs.spring.io/spring-boot/docs/current/reference/html/common-application-properties.html)


### Aufgabe 1.4: Starten der Spring Boot Anwendung

Wir möchten nun die Anwendung starten, indem wir das Maven goal `mvn spring-boot:run` ausführen. 
Anschließend soll die Übersicht der Actuator REST-Endpunkte mit [http://localhost:8080/actuator](http://localhost:8080/actuator) 
aufgerufen werden.

**_HINWEIS:_** Wenn der Port `8080` belegt ist, kann er in der `application.properties` mit folgender Konfiguration angepasst werden:

```properties
server.port= # port of the server
```
