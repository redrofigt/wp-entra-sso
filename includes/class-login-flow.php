<?php
/**
 * Login flow: button, callback handling, single-use state, secure redirects.
 *
 * @package EntraSso
 */

declare( strict_types = 1 );

namespace EntraSso;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ties the OIDC client and provisioning together on wp-login.php.
 */
final class Login_Flow {

	private const CALLBACK_ACTION = 'entra_sso_callback';

	/**
	 * Hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'login_form', array( self::class, 'render_button' ) );
		add_action( 'login_enqueue_scripts', array( self::class, 'button_styles' ) );
		add_action( 'init', array( self::class, 'handle_callback' ) );
		add_filter( 'authenticate', array( self::class, 'maybe_require_sso' ), 30, 3 );
	}

	/**
	 * Render the "Sign in with Microsoft" button.
	 *
	 * @return void
	 */
	public static function render_button(): void {
		$settings = Options::all();

		if ( empty( $settings['client_id'] ) || empty( $settings['tenant_id'] ) ) {
			return;
		}

		$auth = Oidc_Client::build_auth_url( $settings );

		printf(
			'<a class="entra-sso-btn" href="%s">%s</a>',
			esc_url( $auth['url'] ),
			esc_html__( 'Sign in with Microsoft (SSO)', 'entra-sso' )
		);
	}

	/**
	 * Minimal button styling matching Microsoft identity branding.
	 *
	 * @return void
	 */
	public static function button_styles(): void {
		wp_register_style( 'entra-sso-login', false, array(), ENTRA_SSO_VERSION );
		wp_enqueue_style( 'entra-sso-login' );
		wp_add_inline_style(
			'entra-sso-login',
			'.entra-sso-btn{display:block;margin:12px 0 4px;padding:10px 12px;border:1px solid #8c8c8c;border-radius:4px;'
			. 'text-align:center;font-weight:600;text-decoration:none;background:#fff;color:#1b1b1b;}'
			. '.entra-sso-btn:hover{background:#f3f3f3;}'
		);
	}

	/**
	 * Handle the OIDC redirect back from Entra.
	 *
	 * @return void
	 */
	public static function handle_callback(): void {
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the state parameter IS the nonce; validated below.

		if ( self::CALLBACK_ACTION !== $action ) {
			return;
		}

		$settings = Options::all();

		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$error = isset( $_GET['error_description'] ) ? sanitize_text_field( wp_unslash( $_GET['error_description'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated

		if ( $error ) {
			self::fail( $error );
		}

		if ( ! $code || ! $state ) {
			self::fail( 'Missing code/state in the OIDC callback.' );
		}

		// Single-use, TTL-bounded state lookup (CSRF + replay protection).
		$state_key = 'entra_sso_state_' . $state;
		$context   = get_transient( $state_key );
		delete_transient( $state_key ); // Consume immediately.

		if ( ! is_array( $context ) || empty( $context['nonce'] ) || empty( $context['verifier'] ) ) {
			self::fail( 'Invalid or expired login state. Please try again.' );
		}

		$tokens = Oidc_Client::exchange_code( $code, (string) $context['verifier'], $settings );

		if ( is_wp_error( $tokens ) ) {
			self::fail( $tokens->get_error_message() );
		}

		$claims = Oidc_Client::validate_id_token( (string) $tokens['id_token'], (string) $context['nonce'], $settings );

		if ( is_wp_error( $claims ) ) {
			self::fail( $claims->get_error_message() );
		}

		$user = Provisioning::find_or_create_user( $claims, $settings );

		if ( is_wp_error( $user ) ) {
			self::fail( $user->get_error_message() );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

		// Redirect to a safe, internal URL only (no client-controlled targets).
		$redirect_to = isset( $_GET['redirect_to'] ) ? wp_unslash( $_GET['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated by wp_safe_redirect().
		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Redirect back to the login form with a readable error.
	 *
	 * @param string $message Error message.
	 * @return void
	 */
	private static function fail( string $message ): void {
		wp_safe_redirect(
			add_query_arg(
				array(
					'login'      => 'failed',
					'entra_err'  => rawurlencode( $message ),
				),
				wp_login_url()
			)
		);
		exit;
	}

	/**
	 * Optionally block password logins when SSO-only mode is enabled via filter.
		*
		* @param \WP_User|\WP_Error|null $user     Auth result.
		* @param string                  $username Username.
		* @param string                  $password Password.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function maybe_require_sso( $user, string $username, string $password ) {
		if ( ! apply_filters( 'entra_sso_sso_only', false ) || '' === $username ) {
			return $user;
		}

		return new \WP_Error(
			'entra_sso_only',
			__( 'This intranet uses single sign-on. Please use \'Sign in with Microsoft\'.', 'entra-sso' )
		);
	}
}
