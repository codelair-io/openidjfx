package tech.fabricate.openidjfx;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;

public class OidcClient {
  private static final Charset CHARSET = Charset.forName("UTF-8");

  public enum TokenType {
    AUTH,
    REFRESH
  }

  public static class Builder {
    private String tokenUrl;
    private String authUrl;
    private String clientId;
    private String redirectUri;

    public static Builder newBuilder() {
      return new Builder();
    }

    public Builder setTokenUrl(final String tokenUrl) {
      this.tokenUrl = tokenUrl;
      return this;
    }

    public Builder setAuthUrl(final String authUrl) {
      this.authUrl = authUrl;
      return this;
    }

    public Builder setClientId(final String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder setRedirectUri(final String redirectUri) {
      this.redirectUri = redirectUri;
      return this;
    }

    public OidcClient build() {
      if (tokenUrl == null || authUrl == null || clientId == null || redirectUri == null) {
        throw new IllegalArgumentException("All builder setters are mandatory.");
      }

      return new OidcClient(tokenUrl, authUrl, clientId, redirectUri);
    }
  }

  private final String tokenUrl;
  private final String authUrl;
  private final String clientId;
  private final String redirectUri;

  private OidcClient(String tokenUrl, String authUrl, String clientId, String redirectUri) {
    this.tokenUrl = tokenUrl;
    this.authUrl = authUrl;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
  }

  /**
   * Generates a complete URL to the auth-endpoint. It is up to the caller to decide how she or he wants to open a browser.
   *
   * @param state the state to send with the auth-request.
   * @return a complete auth-URL.
   */
  public String generateAuthCall(final String state) {
    return new StringBuilder(authUrl)
        .append("?client_id=")
        .append(URLEncoder.encode(clientId, CHARSET))
        .append("&state=")
        .append(URLEncoder.encode(state, CHARSET))
        .append("&redirect_uri=")
        .append(URLEncoder.encode(redirectUri, CHARSET))
        .append("&response_type=code")
        .append("&scope=")
        .append(URLEncoder.encode("openid profile", CHARSET))
        .toString();
  }

  public JsonObject performTokenCall(final String token, TokenType tokenType) {
    final StringBuilder formBodyBuilder;
    if (tokenType == TokenType.AUTH) {
      formBodyBuilder = new StringBuilder("grant_type=authorization_code")
          .append("&code=")
          .append(URLEncoder.encode(token, CHARSET));
    } else {
      formBodyBuilder = new StringBuilder("grant_type=refresh_token")
          .append("&refresh_token=")
          .append(URLEncoder.encode(token, CHARSET));

    }

    final var formBody = formBodyBuilder
        .append("&redirect_uri=")
        .append(URLEncoder.encode(redirectUri, CHARSET))
        .append("&client_id=")
        .append(URLEncoder.encode(clientId, CHARSET))
        .toString();

    try {
      final var url = new URL(tokenUrl);
      final var cn = (HttpURLConnection) url.openConnection();

      cn.setRequestMethod("POST");
      cn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      cn.setDoOutput(true);

      try (final var os = cn.getOutputStream(); final var osw = new OutputStreamWriter(os, CHARSET)) {
        osw.write(formBody);
      }

      try (final var is = cn.getInputStream()) {
        return Json.createReader(is).readObject();
      }
    } catch (final IOException e) {
      throw new IllegalStateException("Unable to transmit auth token to token-endpoint.", e);
    }
  }
}
