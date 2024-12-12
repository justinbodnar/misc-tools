#!/bin/bash

# Hardcoded webroot dir
webroot="/var/www/html/"

setup_isolated_website() {
	local SITE_DIR="$1"
	SITE_DIR="${SITE_DIR//\/\//\/}"

	# Validate input directory
	if [[ ! -d "$SITE_DIR" ]]; then
		echo "Error: $SITE_DIR does not exist or is not a directory."
		exit 1
	fi

	# Ensure directory is under /var/www/html
	if [[ $SITE_DIR != /var/www/html/* ]]; then
		echo "Error: The directory must reside under /var/www/html."
		exit 1
	fi

	local DOMAIN
	DOMAIN="$(basename "$SITE_DIR")"

	# Verify domain contains a period
	if [[ $DOMAIN != *.* ]]; then
		echo "Error: The website directory name must contain a period."
		exit 1
	fi

	# Extract username from domain (before final period)
	local USERNAME
	USERNAME="$(echo "$DOMAIN" | sed 's/\.[^.]*$//')"

	# Hardcode the PHP version
	PHP_VERSION="8.4"
	local POOL_DIR="/etc/php/${PHP_VERSION}/fpm/pool.d"
	local POOL_FILE="${POOL_DIR}/${USERNAME}.conf"

	# Prepare PHP-FPM pool config with open_basedir restriction
	POOL_CONFIG=$(cat <<EOF
[${USERNAME}]
user = ${USERNAME}
group = ${USERNAME}
listen = /run/php/${USERNAME}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
chdir = /
php_admin_value[open_basedir] = ${SITE_DIR}:/tmp
EOF
)

	FILESMATCH_BLOCK=$(cat <<EOF
<FilesMatch "\\.php\$">
    SetHandler "proxy:unix:/run/php/${USERNAME}.sock|fcgi://localhost"
</FilesMatch>
EOF
)

	VHOST_FILES=$(ls /etc/apache2/sites-available/${DOMAIN}* 2>/dev/null || true)

	echo "Directory: $SITE_DIR"
	echo "Proposed user/group: $USERNAME"
	echo "The script will:"
	echo "1. Ensure the system user and group '$USERNAME' exist."
	echo "2. Add 'www-data' to the '$USERNAME' group."
	echo "3. Recursively set $SITE_DIR ownership to $USERNAME:$USERNAME."
	echo "4. Set directories to 0750 and files to 0640."
	echo "5. Create/update PHP-FPM pool for '$USERNAME' at $POOL_FILE with open_basedir enforced."
	echo "---------------------------------------------------"
	echo "$POOL_CONFIG"
	echo "---------------------------------------------------"
	echo "6. Restart PHP-FPM and Apache."
	echo "7. For Apache vhost files that match '${DOMAIN}*' in /etc/apache2/sites-available,"
	echo "   if their DocumentRoot matches '$SITE_DIR', remove any existing handler lines"
	echo "   for this user and re-insert the FilesMatch block."
	echo "8. Enable 'proxy_fcgi' if not enabled, and reload Apache."
	echo "9. Set /var/www/html to 751 to prevent directory listing outside the basedir."
	echo
	read -p "Proceed with all these changes? (y/n): " FINAL_CONFIRM
	if [[ "$FINAL_CONFIRM" != "y" ]]; then
		echo "Skipping $SITE_DIR."
		return
	fi

	# Ensure user and group exist
	if ! id "$USERNAME" &>/dev/null; then
		echo "Creating system user '$USERNAME'..."
		useradd --system --no-create-home --shell /usr/sbin/nologin "$USERNAME"
	else
		echo "User '$USERNAME' already exists, continuing..."
	fi

	if ! getent group "$USERNAME" &>/dev/null; then
		echo "Group '$USERNAME' does not exist; creating..."
		groupadd "$USERNAME"
		usermod -g "$USERNAME" "$USERNAME"
	else
		echo "Group '$USERNAME' already exists, continuing..."
	fi

	# Add www-data to the group regardless
	usermod -aG "$USERNAME" www-data

	echo "Changing ownership of $SITE_DIR to $USERNAME:$USERNAME..."
	chown -R "$USERNAME":"$USERNAME" "$SITE_DIR"

	echo "Setting directory permissions to 0750 and file permissions to 0640 in $SITE_DIR..."
	find "$SITE_DIR" -type d -exec chmod 0750 {} \;
	find "$SITE_DIR" -type f -exec chmod 0640 {} \;

	# Ensure PHP-FPM pool directory
	if [[ ! -d "$POOL_DIR" ]]; then
		echo "Error: Could not find pool.d directory at $POOL_DIR for PHP $PHP_VERSION."
		exit 1
	fi

	# Write the pool config (overwrite if exists)
	echo "$POOL_CONFIG" > "$POOL_FILE"
	echo "Wrote PHP-FPM pool config to $POOL_FILE"

	echo "Restarting PHP-FPM and Apache..."
	systemctl restart php${PHP_VERSION}-fpm
	systemctl reload apache2

	# Update vhost files without relying on complicated sed insertions
	if [[ -n "$VHOST_FILES" ]]; then
		echo "Checking vhost files:"
		for f in $VHOST_FILES; do
			TMP_FILE=$(mktemp)
			MATCHED_DOCROOT=0

			while IFS= read -r line; do
				if [[ $line =~ ^[[:space:]]*DocumentRoot[[:space:]]+$SITE_DIR[[:space:]]*$ ]]; then
					MATCHED_DOCROOT=1
					echo "$line" >> "$TMP_FILE"
					echo "$FILESMATCH_BLOCK" >> "$TMP_FILE"
					continue
				fi

				if [[ $line =~ SetHandler.*${USERNAME}\.sock ]]; then
					continue
				fi

				echo "$line" >> "$TMP_FILE"
			done < "$f"

			if [[ $MATCHED_DOCROOT -eq 1 ]]; then
				mv "$TMP_FILE" "$f"
				echo "Ensured the PHP-FPM handler block in $f"
			else
				rm "$TMP_FILE"
				echo "$f does not have DocumentRoot set to $SITE_DIR; skipping."
			fi
		done
	else
		echo "No vhost files found matching ${DOMAIN}* in /etc/apache2/sites-available."
	fi

	a2enmod proxy_fcgi >/dev/null 2>&1
	systemctl reload apache2
	chmod 751 /var/www/html

	echo "Setup complete for $SITE_DIR."
	echo "Open_basedir enforced, vhost updated, directory permissions adjusted."
	echo "Remove any testing shells after verifying isolation."
}

if [ ! -d "$webroot" ]; then
	echo "Error: The directory $webroot does not exist."
	exit 1
fi

for DIR in "$webroot"/*; do
	if [ -d "$DIR" ]; then
		echo "Found directory: $DIR"
		read -p "Do you want to isolate website on this directory? (y/n) " confirm
		confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')

		if [ "$confirm" = "y" ]; then
			setup_isolated_website "$DIR"
		else
			echo "Skipping $DIR."
		fi
	fi
done
