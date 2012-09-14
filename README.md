# Nginx Fluentd Module 

##Installation

    $ ./configure --add-module=/path/to/nginx-fluentd-module

##Synopsis

    server {
    
        [...]
        
        log_format  fluentd '"ra":"$remote_addr", "uri":"$request_uri", "st":$status, "ref":"$http_referer", "ua":"$http_user_agent","rt":$request_time, "bs":$bytes_sent';
        
        fluentd_tag  $host;
        access_fluentd 127.0.0.1:8000 fluentd;
        
        [...]
    }

## Description

This module send access logs to [fluentd][1] via [fluent-udp-plugin][2]
Log format is important and required because output is in JSON format.

## Directives

   fluentd_tag
    syntax: *fluentd_tag tag

    default: *fluentd_tag nginx*

    context: *main, server, location*

    description: Set tag for fluentd match directive

   access_fluentd
    syntax: *access_fluentd address:port log_format | off*

    default: *access_fluentd off*

    context: *main, server, location, if, limit_access*

    description: Enable logging to fluentd
    
## Authors
    Yasar Semih Alev *semihalev at gmail dot com*
    
    
[1]: http://fluentd.org
[2]: https://github.com/parolkar/fluentd-plugin-udp
