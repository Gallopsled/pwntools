#!/bin/sh
docker run \
    --name pwntools-test-nginx-cache \
    --rm \
    -v ./libcdb_nginx_cache.conf:/etc/nginx/nginx.conf:ro \
    -p 3000:3000 \
    -p 3001:3001 \
    -p 3002:3002 \
    -p 3003:3003 \
    nginx

# curl -v localhost:3000/buildid/8e9fd827446c24067541ac5390e6f527fb5947bb/debuginfo
# curl -v localhost:3003/libcdb/libcdb/raw/master/hashes/build_id/fe136e485814fee2268cf19e5c124ed0f73f4400
# curl -v localhost:3003/libcdb/libcdb/raw/master/libc/libc6-i386-2.18-6/lib32/libc-2.18.so
# curl -v localhost:3003/libcdb/libcdb/raw/master/hashes/build_id/XX
