=== Article Bridge ===
Contributors: your_wp_username
Donate link: https://example.com
Tags: rest-api, import, posts, media, automation
Requires at least: 5.8
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 2.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Article Bridge allows secure importing of posts and media into WordPress via a custom REST API using token-based authentication.

== Description ==

Article Bridge is a developer-oriented plugin designed for automated content importing into WordPress websites.

It provides a custom REST API that allows external systems to create posts, upload media files, assign categories and tags, and set featured images using a secure token-based authentication mechanism.

The plugin is especially useful for:
* Content migration from external systems
* Automated publishing pipelines
* Headless or hybrid CMS setups
* Scheduled or bulk article imports

All operations are performed using WordPress core functions and follow WordPress coding and security standards.

= Key Features =

* Secure REST API with Bearer token authentication
* Create posts programmatically
* Upload media files and attach them to posts
* Assign categories and tags
* Set featured images
* Automatic system user handling
* No external services or tracking
* No ads, no upsells, no paid features

== Installation ==

1. Upload the `article-bridge` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the “Plugins” menu in WordPress.
3. Go to **Settings → Article Bridge**.
4. Generate a new access token and save it securely.
5. Use the REST API endpoints to import content.

== Usage ==

After activation, the plugin registers the following REST API endpoints:



POST /wp-json/article-bridge/v1/post
POST /wp-json/article-bridge/v1/media
POST /wp-json/article-bridge/v1/category
POST /wp-json/article-bridge/v1/tag
POST /wp-json/article-bridge/v1/set-thumbnail


All requests must include the HTTP header:



Authorization: Bearer YOUR_TOKEN


== Authentication ==

Article Bridge uses token-based authentication.

* Tokens are generated manually by site administrators.
* Only a hashed version of the token is stored in the database.
* Tokens are never exposed after generation.
* No WordPress user credentials are required for API access.

== Frequently Asked Questions ==

= Is this plugin secure? =

Yes. Article Bridge uses a hashed token-based authentication mechanism and WordPress core APIs. No plaintext tokens are stored.

= Does this plugin create users automatically? =

A system user is created only when required to perform REST operations. This user is not created on plugin activation.

= Does this plugin use external services? =

No. The plugin does not send data to external services and does not perform tracking.

= Can I use this plugin for bulk imports? =

Yes. The plugin is suitable for automated and bulk content imports.

= Is this plugin suitable for non-developers? =

This plugin is primarily intended for developers or advanced users familiar with REST APIs.

== Screenshots ==

1. Plugin settings page with token generation
2. Example REST API usage

== Changelog ==

= 2.2.0 =
* Stable release
* Secure token-based REST API
* Media upload support
* Category and tag creation
* Featured image assignment

== Upgrade Notice ==

= 2.2.0 =
Initial public release.