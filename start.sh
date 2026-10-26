docker compose down --remove-orphans
docker compose up -d
curl -s http://127.0.0.1:18166/
python3 poc.py --url http://127.0.0.1:18166/ --image php:8.5.11-fpm-alpine3.23 --php-path /usr/local/bin/php