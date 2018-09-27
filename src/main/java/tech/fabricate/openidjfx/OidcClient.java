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

  public enum GrantType {
    AUTHORIZATION_CODE_GRANT,
    REFRESH_TOKEN_GRANT,
    CLIENT_CREDENTIALS_GRANT
  }

  public static class Builder {
    private String tokenUrl;
    private String authUrl;
    private String clientId;
    private String redirectUri;
    private String clientSecret;

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

    public Builder setClientSecret(final String clientSecret){
      this.clientSecret = clientSecret;
      return this;
    }

    public OidcClient build() {
      if (tokenUrl == null || authUrl == null || clientId == null || redirectUri == null) {
        throw new IllegalArgumentException("Following builder setters are mandatory" +
            "\n setAuthUrl" +
            "\n setTokenUrl" +
            "\n setClientId"
        );
      }

      return new OidcClient(tokenUrl, authUrl, clientId, redirectUri, clientSecret);
    }
  }

  private final String tokenUrl;
  private final String authUrl;
  private final String clientId;
  private final String redirectUri;
  private final String clientSecret;

  private OidcClient(String tokenUrl, String authUrl, String clientId, String redirectUri, String clientSecret) {
    this.tokenUrl = tokenUrl;
    this.authUrl = authUrl;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.clientSecret = clientSecret;
  }

  /**
   * Generates a complete URL to the auth-endpoint. It is up to the caller to decide how she or he wants to open a browser.
   * Specific for the Authorization_code grant type
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

  public JsonObject performTokenCall(GrantType grantType){
    return performTokenCall( "", grantType );
  }

  public JsonObject performTokenCall(final String token, GrantType grantType) {
    final StringBuilder formBodyBuilder;

    switch ( grantType ){
      case AUTHORIZATION_CODE_GRANT:
        formBodyBuilder = new StringBuilder("grant_type=authorization_code")
            .append("&code=")
            .append(URLEncoder.encode(token, CHARSET));
        break;
      case CLIENT_CREDENTIALS_GRANT:
        formBodyBuilder = new StringBuilder("grant_type=client_credentials")
            .append("&client_secret=")
            .append(URLEncoder.encode(this.clientSecret, CHARSET));
        break;
      case REFRESH_TOKEN_GRANT:
        formBodyBuilder = new StringBuilder("grant_type=refresh_token")
            .append("&refresh_token=")
            .append(URLEncoder.encode(token, CHARSET));
        break;
      default:
        throw new IllegalArgumentException( "Unsupported/Unknown grant type specified:  " + grantType );
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
