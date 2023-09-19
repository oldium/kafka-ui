package com.provectus.kafka.ui.config.auth.logout;

import com.provectus.kafka.ui.config.auth.OAuthProperties;
import com.provectus.kafka.ui.config.auth.condition.OAuthCondition;
import com.provectus.kafka.ui.model.rbac.provider.Provider;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.util.UriComponents;

@Component
@Conditional(OAuthCondition.class)
public class OAuthLogoutSuccessHandler extends QueryParamsLogoutSuccessHandler {

  enum Attributes {
    CLIENT_ID_KEY("client-id-key"),
    LOGOUT_URL("logout-url"),
    REDIRECT_URL("redirect-url"),
    REDIRECT_URL_KEY("redirect-url-key");

    private final String value;

    Attributes(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }
  }

  final Set<String> ATTRIBUTES = Set.of(Arrays.stream(Attributes.values()).map(Attributes::getValue).toArray(String[]::new));

  @Override
  public boolean isApplicable(String provider, Map<String, String> customParams) {
    // oauth type is used for ACL too, so check if there is any of our attributes
    return (Provider.Name.OAUTH.equalsIgnoreCase(customParams.getOrDefault("type", null))
                || Provider.Name.OAUTH.equalsIgnoreCase(provider))
        && ATTRIBUTES.stream().anyMatch(customParams::containsKey);
  }

  @Override
  protected URI buildRedirect(WebFilterExchange exchange, UriComponents baseUrl,
                              OAuthProperties.OAuth2Provider provider, ClientRegistration clientRegistration) {
    URI logoutUrl = null;

    if (provider.getCustomParams().containsKey(Attributes.LOGOUT_URL.getValue())) {
      logoutUrl = URI.create(provider.getCustomParams().get(Attributes.LOGOUT_URL.getValue()));
    }

    if (logoutUrl == null && clientRegistration != null) {
      Object endSessionEndpoint = clientRegistration.getProviderDetails().getConfigurationMetadata()
          .get("end_session_endpoint");
      if (endSessionEndpoint != null) {
        logoutUrl = URI.create(endSessionEndpoint.toString());
      }
    }

    Assert.notNull(logoutUrl, "Cannot determine logout URL, custom params should contain 'logout-url'");

    var params = new LinkedMultiValueMap<String, String>();

    if (provider.getCustomParams().containsKey(Attributes.CLIENT_ID_KEY.getValue())) {
      params.add(provider.getCustomParams().get(Attributes.CLIENT_ID_KEY.getValue()), provider.getClientId());
    }

    if (provider.getCustomParams().containsKey(Attributes.REDIRECT_URL_KEY.getValue())) {
      if (provider.getCustomParams().containsKey(Attributes.REDIRECT_URL.getValue())) {
        params.add(provider.getCustomParams().get(Attributes.REDIRECT_URL_KEY.getValue()),
            provider.getCustomParams().get(Attributes.REDIRECT_URL.getValue()));
      } else {
        params.add(provider.getCustomParams().get(Attributes.REDIRECT_URL_KEY.getValue()), baseUrl.toString());
      }
    }

    return createRedirectUrl(logoutUrl, params);
  }
}
