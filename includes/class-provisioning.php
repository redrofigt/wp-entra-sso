<?php
/**
 * Automatic user provisioning and security-group-to-role mapping.
 *
 * @package EntraSso
 */

declare( strict_types = 1 );

namespace EntraSso;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns validated ID-token claims into (or updates) a WordPress user, and maps
 * Entra security groups to WordPress roles.
 */
final class Provisioning {

	/**
	 * Create or update the WP user from ID-token claims, then assign the mapped roles.
	 *
	 * @param array<string, mixed> $claims   Validated claims.
		* @param array<string, mixed> $settings Settings.
	 * @return \WP_User|\WP_Error
	 */
	public static function find_or_create_user( array $claims, array $settings ) {
		$oid  = (string) ( $claims['oid'] ?? '' ); // Entra object ID — stable across renames.
		$upn  = (string) ( $claims['preferred_username'] ?? $claims['upn'] ?? '' );
		$mail = (string) ( $claims['email'] ?? $upn );

		if ( '' === $oid || '' === $mail ) {
			return new \WP_Error( 'entra_sso_claims', 'ID token is missing oid/email claims.' );
		}

		// Group authorization first: reject users outside allowed groups.
		$groups = isset( $claims['groups'] ) && is_array( $claims['groups'] ) ? $claims['groups'] : array();

		$allowed = array_filter( array_map( 'strval', (array) ( $settings['allowed_groups'] ?? array() ) ) );
		if ( $allowed && ! array_intersect( $allowed, array_map( 'strval', $groups ) ) ) {
			return new \WP_Error(
				'entra_sso_not_authorized',
				'Your account is not a member of a group allowed to access the intranet.'
			);
		}

		// Look up by our stable _entra_oid user meta first, then by email.
		$users = get_users(
			array(
				'meta_key'   => '_entra_oid', // phpcs:ignore WordPress.DB.SlowDBQuery
				'meta_value' => $oid, // phpcs:ignore WordPress.DB.SlowDBQuery
				'number'     => 1,
			)
		);

		$user = $users[0] ?? null;

		if ( ! $user instanceof \WP_User ) {
			$user = get_user_by( 'email', $mail ) ?: null;
		}

		$provision = (bool) $settings['provision_users'];

		if ( ! $user instanceof \WP_User && ! $provision ) {
			return new \WP_Error( 'entra_sso_no_user', 'No local account is linked to this identity.' );
		}

		if ( ! $user instanceof \WP_User ) {
			$user_id = wp_insert_user(
				array(
					'user_login'   => sanitize_user( (string) strtok( $mail, '@' ), true ) . '_' . substr( md5( $oid ), 0, 6 ),
					'user_email'   => $mail,
					'first_name'   => (string) ( $claims['given_name'] ?? '' ),
					'last_name'    => (string) ( $claims['family_name'] ?? '' ),
					'display_name' => (string) ( $claims['name'] ?? $mail ),
					'user_pass'    => wp_generate_password( 32, true, true ), // Never used; SSO only.
					'role'         => 'subscriber',
				)
			);

			if ( is_wp_error( $user_id ) ) {
				return $user_id;
			}

			$user = new \WP_User( $user_id );
		}

		// Bind the Entra identity to this account (stable re-link on next login).
		update_user_meta( $user->ID, '_entra_oid', sanitize_text_field( $oid ) );
		update_user_meta( $user->ID, '_entra_upn', sanitize_text_field( $upn ) );

		// --- Role mapping from security groups --------------------------------
		$map     = (array) ( $settings['group_role_map'] ?? array() );
		$matched = array();

		foreach ( $map as $group_id => $role ) {
			if ( in_array( (string) $group_id, array_map( 'strval', $groups ), true ) && get_role( (string) $role ) ) {
				$matched[] = (string) $role;
			}
		}

		/**
		 * Filter the resolved roles before they are applied.
			*
			* @param string[] $matched Roles resolved from group mapping.
			* @param array    $claims  ID token claims.
			*/
		$matched = apply_filters( 'entra_sso_mapped_roles', $matched, $claims );

		// Directory-driven sync: replace roles with the mapped set on every login.
		if ( $matched ) {
			$user->remove_all_caps();
			foreach ( $matched as $role ) {
				$user->add_role( $role );
			}
		} else {
			$user->set_role( (string) $settings['default_role'] );
		}

		return $user;
	}
}
