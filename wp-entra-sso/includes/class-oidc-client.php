<?php
/**
 * Minimal, dependency-free OpenID Connect client for Microsoft Entra ID.
 *
 * @package EntraSso
 */

declare( strict_types = 1 );

namespace EntraSso;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * OIDC authorization-code flow with PKCE, and strict ID-token validation
 * (iss, aud, exp, nonce).
 */
final class Oidc_Client {

	/**
	 * Entra ID authority (v2 endpoint).
	 *
	 * @param string $tenant_id Tenant ID (or 'organizations' / 'common').
	 * @return string
	 */
	public static function authority( string $tenant_id ): string {
		return sprintf( 'https://login.microsoftonline.com/%s/v2.0', rawurlencode( $tenant_id ) );
	}

	/**
	 * Build the authorization redirect URL (with PKCE + state + nonce).
	 *
	 * @param array<string, mixed> $settings Settings.
	 * @return array{url:string, state:string, verifier:string}
	 */
	public static function build_auth_url( array $settings ): array {
		$state     = wp_generate_password( 32, false, false );
		$nonce     = wp_generate_password( 32, false, false );
		$verifier  = self::pkce_verifier();
		$challenge = self::pkce_challenge( $verifier );

		// Persist flow context; single-use, TTL-bounded.
		set_transient(
			'entra_sso_state_' . $state,
			array(
				'nonce'    => $nonce,
				'verifier' => $verifier,
			),
			(int) $settings['state_ttl']
		);

		$args = array(
			'client_id'             => $settings['client_id'],
			'response_type'         => 'code',
			'redirect_uri'          => $settings['redirect_uri'],
			'response_mode'         => 'query',
			'scope'                 => $settings['scopes'],
			'state'                 => $state,
			'nonce'                 => $nonce,
			'code_challenge'        => $challenge,
			'code_challenge_method' => 'S256',
			// MFA / Conditional Access policies are evaluated by the IdP here.
			'prompt'                => 'select_account',
		);

		return array(
			'url'      => self::authority( (string) $settings['tenant_id'] ) . '/authorize?' . build_query( $args ),
			'state'    => $state,
			'verifier' => $verifier,
		);
	}

	/**
	 * Exchange the authorization code for tokens.
	 *
	 * @param string $code     Authorization code.
		* @param string $verifier PKCE verifier stored with the state.
		* @param array  $settings Settings.
	 * @return array<string, mixed>|\WP_Error Token payload.
	 */
	public static function exchange_code( string $code, string $verifier, array $settings ) {
		$response = wp_remote_post(
			self::authority( (string) $settings['tenant_id'] ) . '/token',
			array(
				'timeout' => 20,
				'body'    => array(
					'client_id'     => $settings['client_id'],
					'client_secret' => $settings['client_secret'],
					'code'          => $code,
					'code_verifier' => $verifier,
					'redirect_uri'  => $settings['redirect_uri'],
					'grant_type'    => 'authorization_code',
					'scope'         => $settings['scopes'],
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		$body   = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 200 !== $status || empty( $body['id_token'] ) ) {
			return new \WP_Error(
				'entra_sso_token_exchange',
				sprintf( 'Token exchange failed (HTTP %d).', $status )
			);
		}

		return $body;
	}

	/**
	 * Decode and validate the ID token (iss/aud/exp/nonce). Signature validation
		* can be enforced via the entra_sso_validated_claims filter in production.
	 *
	 * @param string $id_token       JWT.
		* @param string $expected_nonce Nonce from the state transient.
		* @param array  $settings       Settings.
	 * @return array<string, mixed>|\WP_Error Claims.
	 */
	public static function validate_id_token( string $id_token, string $expected_nonce, array $settings ) {
		$parts = explode( '.', $id_token );
		if ( 3 !== count( $parts ) ) {
			return new \WP_Error( 'entra_sso_jwt', 'Malformed ID token.' );
		}

		$header = json_decode( self::b64url_decode( $parts[0] ), true );
		$claims = json_decode( self::b64url_decode( $parts[1] ), true );

		if ( ! is_array( $claims ) ) {
			return new \WP_Error( 'entra_sso_jwt', 'Undecodable ID token payload.' );
		}

		$now = time();

		if ( empty( $claims['iss'] ) || ! is_string( $claims['iss'] ) || ! str_starts_with( $claims['iss'], 'https://login.microsoftonline.com/' ) ) {
			return new \WP_Error( 'entra_sso_iss', 'Unexpected token issuer.' );
		}
		if ( empty( $claims['aud'] ) || $claims['aud'] !== $settings['client_id'] ) {
			return new \WP_Error( 'entra_sso_aud', 'ID token audience mismatch.' );
		}
		if ( empty( $claims['exp'] ) || (int) $claims['exp'] < $now ) {
			return new \WP_Error( 'entra_sso_exp', 'ID token expired.' );
		}
		if ( empty( $claims['nonce'] ) || ! hash_equals( (string) $claims['nonce'], $expected_nonce ) ) {
			return new \WP_Error( 'entra_sso_nonce', 'ID token nonce mismatch.' );
		}

		/**
		 * Hook: enforce JWKS signature validation or extend claim checks.
			*
			* @param array $claims Validated claims.
			* @param array $header JWT header.
			*/
		return apply_filters( 'entra_sso_validated_claims', $claims, is_array( $header ) ? $header : array() );
	}

	/**
	 * PKCE code verifier (43-128 chars, URL-safe).
	 *
	 * @return string
	 */
	private static function pkce_verifier(): string {
		return rtrim( strtr( base64_encode( random_bytes( 48 ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * PKCE S256 challenge.
	 *
	 * @param string $verifier Verifier.
	 * @return string
	 */
	private static function pkce_challenge( string $verifier ): string {
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Base64url decode.
	 *
	 * @param string $data Input.
	 * @return string
	 */
	private static function b64url_decode( string $data ): string {
		$decoded = base64_decode( strtr( $data, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $data ) % 4 ) % 4 ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		return false === $decoded ? '' : $decoded;
	}
}
