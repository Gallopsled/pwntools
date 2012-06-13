#!/bin/sh
echo wpxlc7BG > log/1339253868.log
export REQUEST_METHOD="GET"
export REMOTE_ADDR=127.0.0.1
export REMOTE_PORT=4242
export HTTP_USER_AGENT=awesome
export QUERY_STRING='q=sent&t_s=133925386800000000000000000000009&v=wpxlc7BG000000000000000000000000xxxxxxxxxxxxxxxxxxxxxxxx1'
#./captcha.cgi
gdbserver --once localhost:23946 ./captcha.cgi
#./handle_sent
