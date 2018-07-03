package tech.fabricate.openidjfx;

import com.sun.net.httpserver.HttpServer;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.geometry.Orientation;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.FlowPane;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;

import java.net.InetSocketAddress;
import java.util.UUID;

public class OidcApp extends Application {
  private static final int REDIRECT_PORT = 32323;
  private static final String REDIRECT_URL = "http://localhost:" + REDIRECT_PORT + "/oidc";
  private static final String CLIENT_ID = "myclient";
  private static final String AUTH_URL = "https://example.com/openid-connect/auth";
  private static final String TOKEN_URL = "https://example.com/openid-connect/token";

  private Text text;

  public static void main(final String[] args) throws Exception {
    launch(args);
  }

  public void start(final Stage primaryStage) throws Exception {
    runHttpServer();

    final var loginBtn = new Button("Login");
    loginBtn.setOnAction(this::initiateLogin);

    text = new Text("Not logged in, yet!");
    final var pane = new FlowPane(Orientation.VERTICAL, loginBtn, text);
    final var scene = new Scene(pane, 800, 200);

    primaryStage.setTitle("OpenID Connect Login from Desktop app");
    primaryStage.setScene(scene);
    primaryStage.show();
  }

  private void runHttpServer() throws Exception {
    final var httpServer = HttpServer.create(new InetSocketAddress(REDIRECT_PORT), 0);
    httpServer.setExecutor(null); // use system default
    httpServer.createContext("/oidc", exchange -> {

      // Manually parse query parameters.
      final var queryParams = exchange.getRequestURI().getRawQuery().split("&");
      String authCode = null;
      for (final var queryParam : queryParams) {
        if (queryParam.startsWith("code")) {
          authCode = queryParam.split("=")[1];
          break;
        }
      }

      // Do OAuth 2 token requests
      try {
        final var req = OAuthClientRequest
            .tokenLocation(TOKEN_URL)
            .setClientId(CLIENT_ID)
            .setRedirectURI(REDIRECT_URL)
            .setCode(authCode)
            //.setClientSecret("") You could set a secret here, provided you can keep it confidential (local-only app?)
            .setGrantType(GrantType.AUTHORIZATION_CODE)
            .buildBodyMessage();
        final var oauthClient = new OAuthClient(new URLConnectionClient());
        final var res = oauthClient.accessToken(req);

        // Set access token to GUI
        text.setText("Access Token: " + res.getAccessToken());
      } catch (OAuthSystemException | OAuthProblemException e) {
        throw new RuntimeException(e);
      }

      // For niceness, return something back to the browser.
      exchange.sendResponseHeaders(200, 0);

      // Close TCP call.
      exchange.close();
    });

    httpServer.start();
  }

  private void initiateLogin(final ActionEvent actionEvent) {
    final String locationUri;
    try {
      locationUri = OAuthClientRequest
          .authorizationLocation(AUTH_URL)
          .setRedirectURI(REDIRECT_URL)
          .setClientId(CLIENT_ID)
          .setState(UUID.randomUUID().toString())
          .setResponseType("code")
          .setScope("openid profile")
          .buildQueryMessage()
          .getLocationUri();
    } catch (final OAuthSystemException e) {
      throw new RuntimeException(e);
    }

    // Fire up browser
    getHostServices().showDocument(locationUri);
  }
}
