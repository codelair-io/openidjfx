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

import javax.json.JsonObject;
import java.net.InetSocketAddress;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

public class OidcApp extends Application {
  private static final int REDIRECT_PORT = 32323;
  private static final String REDIRECT_URL = "http://localhost:" + REDIRECT_PORT + "/oidc";
  private static final String CLIENT_ID = "myclient";
  private static final String AUTH_URL = "https://example.com/openid-connect/auth";
  private static final String TOKEN_URL = "https://example.com/openid-connect/token";

  private final OidcClient oidcClient = OidcClient.Builder.newBuilder().setRedirectUri(REDIRECT_URL)
      .setAuthUrl(AUTH_URL)
      .setTokenUrl(TOKEN_URL)
      .setClientId(CLIENT_ID)
      .build();

  private Text text;
  private String expectedState;
  private String accessToken;
  private String refreshToken;

  public static void main(final String[] args) throws Exception {
    launch(args);
  }

  public void start(final Stage primaryStage) throws Exception {
    runHttpServer();

    final var loginBtn = new Button("Login");
    loginBtn.setOnAction(this::initiateLogin);

    text = new Text("Not logged in, yet!");
    text.setWrappingWidth(800);
    final var pane = new FlowPane(Orientation.VERTICAL, loginBtn, text);
    final var scene = new Scene(pane, 850, 500);

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
      String state = null;
      for (final var queryParam : queryParams) {
        if (queryParam.startsWith("code")) {
          authCode = queryParam.split("=")[1];
        } else if (queryParam.startsWith("state")) {
          state = queryParam.split("=")[1];
        }
      }

      // For niceness, return something back to the browser.
      exchange.sendResponseHeaders(200, 0);

      // Close TCP call.
      exchange.close();

      // Now get some tokens...
      processRedirectCall(authCode, state);

    });

    httpServer.start();
  }

  private void initiateLogin(final ActionEvent actionEvent) {
    expectedState = UUID.randomUUID().toString();

    // Fire up browser with a generated auth URL.
    getHostServices().showDocument(oidcClient.generateAuthCall(expectedState));
  }

  private void processRedirectCall(final String authCode, final String state) {
    if (!state.equals(expectedState)) {
      throw new IllegalStateException("This redirect-call was not triggered by ourselves!");
    }

    // Do OAuth 2 token requests
    final JsonObject tokenJson = oidcClient.performTokenCall(authCode, OidcClient.TokenType.AUTH);
    long refreshDelay = tokenJson.getInt("expires_in") * 1000L;
    processTokenJson(tokenJson);

    /*
     Now schedule to get new access and refresh tokens based on expiry. CAVEAT EMPTOR: In a real-world application
     you would probably not blindly refresh just because the access token expires. You would implement an algorithm
     that only requests new tokens before the refresh token expires - or; when making an external call and the access
     token has expired (but of course before the refresh token also expired).
      */
    final var timer = new Timer("RefreshTokenTimer", true);
    timer.scheduleAtFixedRate(new TimerTask() {
      @Override
      public void run() {
        final var tokenJson = oidcClient.performTokenCall(refreshToken, OidcClient.TokenType.REFRESH);
        processTokenJson(tokenJson);
      }
    }, refreshDelay, refreshDelay);
  }

  private void processTokenJson(final JsonObject tokenJson) {
    accessToken = tokenJson.getString("access_token");
    refreshToken = tokenJson.getString("refresh_token");
    text.setText("\nAccess Token: " + accessToken
        + "\n\nRefresh Token: " + refreshToken);
  }
}
