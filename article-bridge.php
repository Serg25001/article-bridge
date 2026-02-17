<?php
/**
 * Plugin Name: Article Bridge
 * Plugin URI: https://github.com/Serg25001/article-bridge
 * Description: Securely import posts, media, categories, tags, and featured images into WordPress via a REST API using token-based authentication.
 * Version: 2.2.0
 * Author: Serg25001
 * Author URI: https://github.com/Serg25001
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: article-bridge
 * Domain Path: /languages
 */

defined('ABSPATH') || exit;

final class Article_Bridge {

    const OPTION_TOKEN_HASH = 'ab_token_hash';
    const SYSTEM_USER_LOGIN = 'article_bridge';

    /* ================= INIT ================= */

    public static function init() {
        add_action('rest_api_init', [self::class, 'register_routes']);
        add_action('admin_menu', [self::class, 'admin_menu']);
    }

    /* ================= ACTIVATION ================= */

    public static function activate() {
        if (!get_option(self::OPTION_TOKEN_HASH)) {
            self::generate_token();
        }
    }

    /* ================= TOKEN ================= */

    private static function generate_token(): string {
        $token = bin2hex(random_bytes(32));
        update_option(self::OPTION_TOKEN_HASH, hash('sha256', $token), false);
        return $token;
    }

    private static function validate_token(string $token): bool {
        $stored = get_option(self::OPTION_TOKEN_HASH);
        return $stored && hash_equals($stored, hash('sha256', $token));
    }

    /* ================= AUTH ================= */

    public static function permission_callback(\WP_REST_Request $request) {

        $header = $request->get_header('authorization');

        if (!$header || strpos($header, 'Bearer ') !== 0) {
            return new \WP_Error(
                'ab_unauthorized',
                __('Missing token', 'article-bridge'),
                ['status' => 401]
            );
        }

        if (!self::validate_token(substr($header, 7))) {
            return new \WP_Error(
                'ab_forbidden',
                __('Invalid token', 'article-bridge'),
                ['status' => 403]
            );
        }

        return true;
    }

    /* ================= SYSTEM USER ================= */

    private static function ensure_system_user(): int {

        $user = get_user_by('login', self::SYSTEM_USER_LOGIN);

        if (!$user) {
            $user_id = wp_create_user(
                self::SYSTEM_USER_LOGIN,
                wp_generate_password(32),
                'noreply@localhost'
            );

            if (is_wp_error($user_id)) {
                return get_current_user_id();
            }

            $user = get_user_by('id', $user_id);
            $user->set_role('editor');
        }

        wp_set_current_user($user->ID);
        return (int) $user->ID;
    }

    /* ================= ROUTES ================= */

    public static function register_routes() {

        register_rest_route('article-bridge/v1', '/post', [
            'methods'  => \WP_REST_Server::CREATABLE,
            'callback' => [self::class, 'create_post'],
            'permission_callback' => [self::class, 'permission_callback'],
        ]);

        register_rest_route('article-bridge/v1', '/media', [
            'methods'  => \WP_REST_Server::CREATABLE,
            'callback' => [self::class, 'upload_media'],
            'permission_callback' => [self::class, 'permission_callback'],
        ]);

        register_rest_route('article-bridge/v1', '/category', [
            'methods'  => \WP_REST_Server::CREATABLE,
            'callback' => [self::class, 'create_category'],
            'permission_callback' => [self::class, 'permission_callback'],
        ]);

        register_rest_route('article-bridge/v1', '/tag', [
            'methods'  => \WP_REST_Server::CREATABLE,
            'callback' => [self::class, 'create_tag'],
            'permission_callback' => [self::class, 'permission_callback'],
        ]);

        register_rest_route('article-bridge/v1', '/set-thumbnail', [
            'methods'  => \WP_REST_Server::CREATABLE,
            'callback' => [self::class, 'set_thumbnail'],
            'permission_callback' => [self::class, 'permission_callback'],
        ]);
    }

    /* ================= POST ================= */

    public static function create_post(\WP_REST_Request $r) {

        self::ensure_system_user();

        $data = $r->get_json_params();

        if (empty($data['title']) || empty($data['content'])) {
            return new \WP_Error('ab_bad_request', 'Title and content required', ['status' => 400]);
        }

        $post_id = wp_insert_post([
            'post_title'   => wp_strip_all_tags($data['title']),
            'post_content' => $data['content'],
            'post_status'  => $data['status'] ?? 'publish',
            'post_type'    => 'post',
            'post_author'  => get_current_user_id(),
            'post_date'    => $data['date'] ?? current_time('mysql'),
        ], true);

        if (is_wp_error($post_id)) {
            return $post_id;
        }

        if (!empty($data['categories'])) {
            wp_set_post_terms($post_id, array_map('intval', $data['categories']), 'category');
        }

        if (!empty($data['tags'])) {
            wp_set_post_terms($post_id, array_map('intval', $data['tags']), 'post_tag');
        }

        return ['post_id' => (int) $post_id];
    }

    /* ================= MEDIA ================= */

    public static function upload_media(\WP_REST_Request $r) {

        self::ensure_system_user();

        if (empty($_FILES['file'])) {
            return new \WP_Error('ab_no_file', 'No file', ['status' => 400]);
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/media.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';

        $upload = wp_handle_upload($_FILES['file'], ['test_form' => false]);

        if (isset($upload['error'])) {
            return new \WP_Error('ab_upload', $upload['error'], ['status' => 400]);
        }

        $id = wp_insert_attachment([
            'post_mime_type' => $upload['type'],
            'post_title'     => basename($upload['file']),
            'post_status'    => 'inherit',
        ], $upload['file']);

        wp_update_attachment_metadata($id, wp_generate_attachment_metadata($id, $upload['file']));

        return [
            'attachment_id' => (int) $id,
            'url' => wp_get_attachment_url($id),
        ];
    }

    /* ================= TAXONOMY ================= */

    public static function create_category(\WP_REST_Request $r) {
        self::ensure_system_user();
        $term = wp_insert_term(sanitize_text_field($r['name']), 'category');
        return is_wp_error($term) ? $term : ['id' => $term['term_id']];
    }

    public static function create_tag(\WP_REST_Request $r) {
        self::ensure_system_user();
        $term = wp_insert_term(sanitize_text_field($r['name']), 'post_tag');
        return is_wp_error($term) ? $term : ['id' => $term['term_id']];
    }

    /* ================= THUMBNAIL ================= */

    public static function set_thumbnail(\WP_REST_Request $r) {
        self::ensure_system_user();
        set_post_thumbnail((int)$r['post_id'], (int)$r['attachment_id']);
        return ['ok' => true];
    }

    /* ================= ADMIN ================= */

    public static function admin_menu() {
        add_options_page(
            'Article Bridge',
            'Article Bridge',
            'manage_options',
            'article-bridge',
            [self::class, 'admin_page']
        );
    }

    public static function admin_page() {

        if (!current_user_can('manage_options')) return;

        if (isset($_POST['regenerate'])) {
            check_admin_referer('ab_regenerate');
            $token = self::generate_token();
            echo '<div class="notice notice-success"><p><strong>Save token now:</strong></p><code>' . esc_html($token) . '</code></div>';
        }
        ?>
        <div class="wrap">
            <h1>Article Bridge</h1>
            <form method="post">
                <?php wp_nonce_field('ab_regenerate'); ?>
                <button class="button button-primary" name="regenerate">Generate new token</button>
            </form>
            <p><code><?php echo esc_html(rest_url('article-bridge/v1/')); ?></code></p>
        </div>
        <?php
    }
}

/* ================= BOOTSTRAP ================= */

register_activation_hook(__FILE__, ['Article_Bridge', 'activate']);
Article_Bridge::init();
