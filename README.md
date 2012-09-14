# Nginx Fluent Module 

##Installation

    $ ./configure --add-module=/path/to/nginx-fluent-module

##Synopsis

    server {
    
        [...]
        
        log_format  fluent '"ra":"$remote_addr", "uri":"$request_uri", "st":$status, "ref":"$http_referer", "ua":"$http_user_agent","rt":$request_time, "bs":$bytes_sent';
        
        fluent_tag  $host;
        access_fluent 127.0.0.1:8000 fluent;
        
        [...]
    }

## Description

This module send access logs to [fluentd][1] via [fluent-udp-plugin][2]
Log format is important and required because output is in JSON format.

## Directives

   fluent_tag
    syntax: *fluent_tag tag

    default: *fluent_tag nginx*

    context: *main, server, location*

    description: Set tag for fluent match directive

   access_fluent
    syntax: *access_fluent address:port log_format | off*

    default: *access_fluent off*

    context: *main, server, location, if, limit_access*

    description: Enable logging to fluent
    
## Authors
    Yasar Semih Alev *semihalev at gmail dot com*
    
    
[1]: http://fluentd.org
[2]: https://github.com/parolkar/fluent-plugin-udp