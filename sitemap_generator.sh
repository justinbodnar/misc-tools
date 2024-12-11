#!/bin/bash

	# Hardcoded variable to enable or disable scanning for images
	scan_images=true

	# Prompt the user for the domain name
	read -p "Enter your domain name (e.g., example.com or https://example.com): " domain

	# Add https:// if not already included
	if [[ "$domain" != http*://* ]]; then
		domain="https://$domain"
	fi

	# Set the base filename
	base="sitemap"
	ext=".xml"
	filename="${base}${ext}"

	# Increment filename if it already exists
	counter=1
	while [ -e "$filename" ]; do
		counter=$((counter + 1))
		filename="${base}_${counter}${ext}"
	done

	# Start the sitemap XML structure
	echo '<?xml version="1.0" encoding="UTF-8"?>' > "$filename"
	echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">' >> "$filename"

	# Define file types to include
	if $scan_images; then
		find . -type f \( -name "*.html" -o -name "*.php" -o -name "*.jpg" -o -name "*.png" -o -name "*.gif" \) | while read -r file; do
			# Get the URL path by removing the leading './'
			url_path="${file#./}"
			url_path="${url_path// /%20}"

			# Add the URL entry
			echo "  <url>" >> "$filename"
			echo "    <loc>${domain}/${url_path}</loc>" >> "$filename"

			# Add image-specific tags if enabled and the file is an image
			if [[ "$file" =~ \.(jpg|png|gif)$ ]]; then
				echo "    <image:image>" >> "$filename"
				echo "      <image:loc>${domain}/${url_path}</image:loc>" >> "$filename"
				echo "    </image:image>" >> "$filename"
			fi

			# Add lastmod and other metadata
			echo "    <lastmod>$(date -r "$file" +"%Y-%m-%d")</lastmod>" >> "$filename"
			echo "    <changefreq>monthly</changefreq>" >> "$filename"
			echo "    <priority>0.5</priority>" >> "$filename"
			echo "  </url>" >> "$filename"
		done
	else
		find . -type f \( -name "*.html" -o -name "*.php" \) | while read -r file; do
			# Get the URL path by removing the leading './'
			url_path="${file#./}"
			url_path="${url_path// /%20}"

			# Add the URL entry
			echo "  <url>" >> "$filename"
			echo "    <loc>${domain}/${url_path}</loc>" >> "$filename"

			# Add lastmod and other metadata
			echo "    <lastmod>$(date -r "$file" +"%Y-%m-%d")</lastmod>" >> "$filename"
			echo "    <changefreq>monthly</changefreq>" >> "$filename"
			echo "    <priority>0.5</priority>" >> "$filename"
			echo "  </url>" >> "$filename"
		done
	fi

	# Close the sitemap XML structure
	echo '</urlset>' >> "$filename"

	# Notify the user
	echo "Sitemap generated: $filename"
