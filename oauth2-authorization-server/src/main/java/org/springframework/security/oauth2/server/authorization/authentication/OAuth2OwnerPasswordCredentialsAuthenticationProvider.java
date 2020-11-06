/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Resource Owner Password Credentials Grant.
 * It is no longer recommended
 *
 * @author luamas
 * @since 0.0.1
 * @see OAuth2OwnerPasswordCredentialsAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.3">Resource Owner Password Credentials Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.3.2">Section 4.3.2 Access Token Request</a>
 */
@Deprecated
public class OAuth2OwnerPasswordCredentialsAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2OwnerPasswordCredentialsAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			JwtEncoder jwtEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2OwnerPasswordCredentialsAuthenticationToken clientPasswordAuthenticationToken =
				(OAuth2OwnerPasswordCredentialsAuthenticationToken) authentication;
		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(clientPasswordAuthenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}
		UsernamePasswordAuthenticationToken userPrincipal = null;

		if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(clientPasswordAuthenticationToken.getPrincipal().getClass())) {
			userPrincipal = (UsernamePasswordAuthenticationToken) clientPasswordAuthenticationToken.getPrincipal();
		}
		if (userPrincipal == null || !userPrincipal.isAuthenticated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_user"));
		}

		Set<String> scopes = registeredClient.getScopes();		// Default to configured scopes
		if (!CollectionUtils.isEmpty(clientPasswordAuthenticationToken.getScopes())) {
			Set<String> unauthorizedScopes = clientPasswordAuthenticationToken.getScopes().stream()
					.filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
					.collect(Collectors.toSet());
			if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
				throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE));
			}
			scopes = new LinkedHashSet<>(clientPasswordAuthenticationToken.getScopes());
		}

		Jwt jwt = OAuth2TokenIssuerUtil
				.issueJwtAccessToken(this.jwtEncoder, clientPrincipal.getName(), registeredClient.getClientId(), scopes);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), scopes);

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.tokens(OAuth2Tokens.builder().accessToken(accessToken).build())
				.attribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES, jwt)
				.build();
		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2OwnerPasswordCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
