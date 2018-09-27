# OpenID on JavaFX

Small example how to do the following OAUTH 2.0 grant flows:  
- Authorization Code Grant  
- Client Credentials Grant  
- Refresh Token Grant  

## Building and running the application

### Alternative 1:
1. export JFX_HOME = `**PATH_TO_JFX_11_HOME**`
2. Run `mvn clean install` to build jar file.
3. Run `java --module-path $JFX_HOME/lib --add-modules=javafx.controls -jar target/openidjfx.jar` to run app.

### Alternative 2:
1. export JFX_HOME = `**PATH_TO_JFX_11_HOME**`
2. Run `mvn compile exec:java`


