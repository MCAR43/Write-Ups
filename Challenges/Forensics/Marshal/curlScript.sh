API_DEV='afe55507f70952d3708f101cab882911'
API_USER='ed67c1aec48d47270dd002d0baa29814'
API_CODE='rLqy9iXC'
API_OPTION='show_paste'
PASTES=('rLqy9iXC' 'dsDhyVZU' 'cUjmHRYK')

for paste_option in "${PASTES[@]}"; do
	curl -d "api_option=$API_OPTION&api_user_key="$API_USER"&api_dev_key=$API_DEV&api_paste_key="$paste_option"" 'https://pastebin.com/api/api_raw.php'
done
