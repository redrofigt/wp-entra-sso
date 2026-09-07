<?php
/**
 * Admin settings page for the OIDC connection and group->role mapping.
 *
 * @package EntraSso
 */

declare( strict_types = 1 );

namespace EntraSso;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings UI under Settings → Entra SSO. Capability: manage_options.
 */
final class Settings_Page {

	/**
	 * Hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_init', array( self::class, 'save' ) );
	}

	/**
	 * Register the submenu page.
	 *
	 * @return void
	 */
	public static function menu(): void {
		add_options_page(
			__( 'Entra SSO', 'entra-sso' ),
			__( 'Entra SSO', 'entra-sso' ),
			'manage_options',
			'entra-sso',
			array( self::class, 'render' )
		);
	}

	/**
	 * Handle POST (nonce + capability checked).
	 *
	 * @return void
	 */
	public static function save(): void {
		if ( empty( $_POST['entra_sso_save'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'entra-sso' ) );
		}

		check_admin_referer( 'entra_sso_settings' );

		$settings = Options::all();

		$settings['tenant_id']       = sanitize_text_field( wp_unslash( $_POST['tenant_id'] ?? '' ) );
		$settings['client_id']       = sanitize_text_field( wp_unslash( $_POST['client_id'] ?? '' ) );
		$settings['redirect_uri']    = esc_url_raw( wp_unslash( $_POST['redirect_uri'] ?? '' ) );
		$settings['default_role']    = sanitize_key( wp_unslash( $_POST['default_role'] ?? 'subscriber' ) );
		$settings['provision_users'] = ! empty( $_POST['provision_users'] );

		// A blank secret keeps the existing encrypted one (see Options::save()).
		if ( ! empty( $_POST['client_secret'] ) ) {
			$settings['client_secret'] = sanitize_text_field( wp_unslash( $_POST['client_secret'] ) );
		}

		// Group -> role mapping arrives as parallel arrays.
		$group_ids = array_map( 'sanitize_text_field', (array) wp_unslash( $_POST['map_group'] ?? array() ) );
		$roles     = array_map( 'sanitize_key', (array) wp_unslash( $_POST['map_role'] ?? array() ) );

		$map = array();
		foreach ( $group_ids as $i => $gid ) {
			if ( $gid && ! empty( $roles[ $i ] ) ) {
				$map[ $gid ] = $roles[ $i ];
			}
		}
		$settings['group_role_map'] = $map;

		$settings['allowed_groups'] = array_values(
			array_filter( array_map( 'trim', explode( ',', (string) wp_unslash( $_POST['allowed_groups'] ?? '' ) ) ) )
		);

		Options::save( $settings );

		add_action( 'admin_notices', static function () {
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved. The client secret was encrypted at rest.', 'entra-sso' ) . '</p></div>';
		} );
	}

	/**
	 * Render the settings screen.
	 *
	 * @return void
	 */
	public static function render(): void {
		$s = Options::all();
		$map = array_values( (array) $s['group_role_map'] );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Entra SSO — OpenID Connect', 'entra-sso' ); ?></h1>

			<form method="post">
				<?php wp_nonce_field( 'entra_sso_settings' ); ?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="tenant_id"><?php esc_html_e( 'Tenant (directory) ID', 'entra-sso' ); ?></label></th>
						<td><input name="tenant_id" id="tenant_id" type="text" class="regular-text" value="<?php echo esc_attr( $s['tenant_id'] ); ?>" placeholder="00000000-0000-0000-0000-000000000000" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="client_id"><?php esc_html_e( 'Application (client) ID', 'entra-sso' ); ?></label></th>
						<td><input name="client_id" id="client_id" type="text" class="regular-text" value="<?php echo esc_attr( $s['client_id'] ); ?>" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="client_secret"><?php esc_html_e( 'Client secret', 'entra-sso' ); ?></label></th>
						<td>
							<input name="client_secret" id="client_secret" type="password" class="regular-text" autocomplete="new-password" value="" />
							<p class="description"><?php esc_html_e( 'Stored AES-256-GCM encrypted. Leave blank to keep the current value. In production the encryption key is injected from Azure Key Vault.', 'entra-sso' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="redirect_uri"><?php esc_html_e( 'Redirect URI', 'entra-sso' ); ?></label></th>
						<td><input name="redirect_uri" id="redirect_uri" type="url" class="regular-text code" value="<?php echo esc_attr( $s['redirect_uri'] ); ?>" placeholder="<?php echo esc_attr( home_url( '/wp-login.php?action=entra_sso_callback' ) ); ?>" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="default_role"><?php esc_html_e( 'Default role (no group match)', 'entra-sso' ); ?></label></th>
						<td>
							<select name="default_role" id="default_role">
								<?php foreach ( wp_roles()->get_names() as $role_slug => $role_label ) : ?>
									<option value="<?php echo esc_attr( $role_slug ); ?>" <?php selected( $s['default_role'], $role_slug ); ?>><?php echo esc_html( $role_label ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Provision users automatically', 'entra-sso' ); ?></th>
						<td><label><input type="checkbox" name="provision_users" value="1" <?php checked( $s['provision_users'] ); ?> /> <?php esc_html_e( 'Create the WordPress account on first SSO login', 'entra-sso' ); ?></label></td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Security group → role mapping', 'entra-sso' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Paste Entra security-group Object IDs and the WordPress role each group should receive. Matched roles replace the default. Roles are re-synced on every login.', 'entra-sso' ); ?></p>

				<table class="widefat striped" style="max-width:640px">
					<thead><tr><th><?php esc_html_e( 'Group Object ID', 'entra-sso' ); ?></th><th><?php esc_html_e( 'WordPress role', 'entra-sso' ); ?></th></tr></thead>
					<tbody>
						<?php for ( $i = 0; $i < max( 3, count( $map ) + 1 ); $i++ ) : ?>
							<tr>
								<td><input name="map_group[]" type="text" class="regular-text" value="" placeholder="00000000-0000-0000-0000-000000000000" /></td>
								<td><input name="map_role[]" type="text" class="regular-text" value="" placeholder="editor" /></td>
							</tr>
						<?php endfor; ?>
					</tbody>
				</table>

				<h2><?php esc_html_e( 'Restrict access to groups (optional)', 'entra-sso' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Comma-separated group Object IDs. Only members of these groups may sign in. Empty = any authenticated company account.', 'entra-sso' ); ?></p>
				<input name="allowed_groups" type="text" class="regular-text" value="<?php echo esc_attr( implode( ', ', (array) $s['allowed_groups'] ) ); ?>" />

				<?php submit_button( __( 'Save settings', 'entra-sso' ), 'primary', 'entra_sso_save' ); ?>
			</form>
		</div>
		<?php
	}
}
