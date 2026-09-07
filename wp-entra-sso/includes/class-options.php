<?php
/**
 * Encrypted settings storage for the OIDC client credentials.
 *
 * @package EntraSso
 */

declare( strict_types = 1 );

namespace EntraSso;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Options access. The client secret is stored encrypted (AES-256-GCM) using a
 * key from an environment constant — in production the constant is injected
 * from Azure Key Vault by the deployment pipeline, so no plaintext secret ever
 * lives in the database.
 */
final class Options {

	private const OPTION_KEY = 'entra_sso_settings';

	/**
	 * Settings defaults.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults(): array {
		return array(
			'tenant_id'        => '',
			'client_id'        => '',
			'client_secret'    => '', // Stored encrypted.
			'redirect_uri'     => '',
			'scopes'           => 'openid profile email User.Read',
			// Entra group object ID => WP role slug.
			'group_role_map'   => array(),
			'default_role'     => 'subscriber',
			'provision_users'  => true,
			// Restrict login to these group IDs (empty = any authenticated user).
			'allowed_groups'   => array(),
			// Seconds a state nonce is valid.
			'state_ttl'        => 300,
		);
	}

	/**
	 * Get all settings (secret decrypted).
	 *
	 * @return array<string, mixed>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION_KEY, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$merged = array_merge( self::defaults(), $stored );

		$merged['client_secret'] = self::decrypt( (string) $merged['client_secret'] );

		return $merged;
	}

	/**
	 * Save settings (secret encrypted before it touches the DB).
	 *
	 * @param array<string, mixed> $settings Settings.
	 * @return void
	 */
	public static function save( array $settings ): void {
		if ( ! empty( $settings['client_secret'] ) ) {
			$settings['client_secret'] = self::encrypt( (string) $settings['client_secret'] );
		} else {
			// Keep the existing encrypted value when the field was left blank.
			$existing = get_option( self::OPTION_KEY, array() );
			$settings['client_secret'] = is_array( $existing ) ? ( $existing['client_secret'] ?? '' ) : '';
		}

		update_option( self::OPTION_KEY, $settings, false );
	}

	/**
	 * Encryption key from environment (Key Vault-injected in production).
	 *
	 * @return string
	 */
	private static function key(): string {
		$from_env  = getenv( 'ENTRA_SSO_SECRET_KEY' );
		$from_def  = defined( 'ENTRA_SSO_SECRET_KEY' ) ? (string) constant( 'ENTRA_SSO_SECRET_KEY' ) : '';
		$key       = ( is_string( $from_env ) && '' !== $from_env ) ? $from_env : $from_def;

		// Fall back to wp_salt() for dev environments; production always injects a dedicated key.
		return $key ?: wp_salt( 'auth' );
	}

	/**
	 * AES-256-GCM encrypt.
	 *
	 * @param string $plaintext Plaintext.
	 * @return string Ciphertext, base64 (iv.ciphertext.tag).
	 */
	public static function encrypt( string $plaintext ): string {
		if ( '' === $plaintext ) {
			return '';
		}

		$key    = hash( 'sha256', self::key(), true );
		$iv     = random_bytes( 12 );
		$tag    = '';
		$cipher = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );

		if ( false === $cipher ) {
			return '';
		}

		return base64_encode( $iv . $cipher . $tag ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * AES-256-GCM decrypt.
	 *
	 * @param string $payload Payload from encrypt().
	 * @return string Plaintext, or '' when decryption fails.
	 */
	public static function decrypt( string $payload ): string {
		if ( '' === $payload ) {
			return '';
		}

		$raw = base64_decode( $payload, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return '';
		}

		$key    = hash( 'sha256', self::key(), true );
		$iv     = substr( $raw, 0, 12 );
		$tag    = substr( $raw, -16 );
		$cipher = substr( $raw, 12, -16 );

		$plain = openssl_decrypt( $cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );

		return false === $plain ? '' : $plain;
	}
}
