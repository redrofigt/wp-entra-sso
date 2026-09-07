<?php
/**
 * Plugin Name:       Entra SSO for WordPress
 * Plugin URI:        https://github.com/redrofigt/wp-entra-sso
 * Description:       OpenID Connect single sign-on with Microsoft Entra ID. MFA-aware, automatic user provisioning, security-group-to-WordPress-role mapping, and graceful fallback to local login.
 * Version:           1.0.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            redrofigt
 * License:           GPL-2.0-or-later
 * Text Domain:       entra-sso
 *
 * @package EntraSso
 */

declare( strict_types = 1 );

namespace EntraSso;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'ENTRA_SSO_VERSION', '1.0.0' );
define( 'ENTRA_SSO_PATH', plugin_dir_path( __FILE__ ) );

require_once ENTRA_SSO_PATH . 'includes/class-options.php';
require_once ENTRA_SSO_PATH . 'includes/class-oidc-client.php';
require_once ENTRA_SSO_PATH . 'includes/class-provisioning.php';
require_once ENTRA_SSO_PATH . 'includes/class-login-flow.php';
require_once ENTRA_SSO_PATH . 'includes/class-settings-page.php';

/**
 * Bootstrap.
 *
 * @return void
 */
function boot(): void {
	Login_Flow::init();
	Settings_Page::init();
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\boot' );
