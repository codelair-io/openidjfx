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

  /**
   * Authentication Grant types
   */
  public enum FetchMethod {

    /**
     * A two-step authentication, used by confidential and public clients to exchange authorization code for an access-token.
     * - User identifies itself and is redirected back via a redirect URL with an authorization code. The client then uses the
     * authorization code to request an access-token.
     */
    AUTHORIZATION_CODE_GRANT,

    /**
     * After eventual expiration of an access token. The refresh token, and following grant type is used to request a new
     * access token without the need for user redirection.
     * - Client sends refresh_token, client_id, (possible) client_secret and scope to retrieve access token.
     */
    REFRESH_TOKEN_GRANT,

    /**
     * Suitable for machine-to-machine communication, where a specific users permission to access data is not required.
     * - Client sends POST request with client_id, (possible) client_secret and scope to retrieve access token.
     */
    CLIENT_CREDENTIALS_GRANT,

    IMPLICIT_GRANT
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
            "\n setClientId" +
            "\n setRedirectUri"
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

  public JsonObject performTokenCall(FetchMethod grantType){
    if( grantType != FetchMethod.CLIENT_CREDENTIALS_GRANT &&
        grantType != FetchMethod.IMPLICIT_GRANT )
      throw new UnsupportedOperationException("Unsupported: Must provide token for grant-type:" + grantType.toString());
    return performTokenCall( "", grantType );
  }

  public JsonObject performTokenCall(final String token, FetchMethod grantType) {
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

      case IMPLICIT_GRANT:
        throw new UnsupportedOperationException( "Auth flow not yet implemented" );

      default:
        throw new IllegalArgumentException( "Unsupported/Unknown grant type specified:  " + grantType );
    }

    // Add Client Secret to token-call, if supplied
    if(clientSecret != null)
      formBodyBuilder.append( "&client_secret=" )
          .append( URLEncoder.encode( clientSecret, CHARSET ) );

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
      e.printStackTrace();
      throw new IllegalStateException("Unable to transmit auth token to token-endpoint.", e);
    }
  }
}
