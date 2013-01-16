/*
 * Copyright (C) 2012 Yasar Semih Alev
 *
 */


/*
 * NOTE: Some functions copied from nginx-udplog-module.
 * Copyright (C) 2010 Valery Kholodkov
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if defined nginx_version && nginx_version >= 8021
typedef ngx_addr_t ngx_fluentd_addr_t;
#else
typedef ngx_peer_addr_t ngx_fluentd_addr_t;
#endif

typedef struct ngx_http_log_op_s  ngx_http_log_op_t;

typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


struct ngx_http_log_op_s {
    size_t                      len;
    ngx_http_log_op_getlen_pt   getlen;
    ngx_http_log_op_run_pt      run;
    uintptr_t                   data;
};

typedef struct {
    ngx_str_t                   name;
#if defined nginx_version && nginx_version >= 7018
    ngx_array_t                *flushes;
#endif
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;

typedef struct {
    ngx_str_t                value;
    ngx_array_t             *lengths;
    ngx_array_t             *values;
} ngx_http_log_tag_template_t;

typedef struct {
    ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;

typedef struct {
    ngx_fluentd_addr_t         peer_addr;
    ngx_udp_connection_t      *udp_connection;
} ngx_udp_endpoint_t;

typedef struct {
    ngx_udp_endpoint_t       *endpoint;
    ngx_http_log_fmt_t       *format;
} ngx_http_fluentd_t;

typedef struct {
    ngx_array_t                *endpoints;
    ngx_uint_t                  collector_max;
} ngx_http_fluentd_main_conf_t;

typedef struct {
    ngx_array_t                 *logs;       /* array of ngx_http_fluentd_t */
    unsigned                     off;
    ngx_http_log_tag_template_t *tag;
} ngx_http_fluentd_conf_t;

ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);

static void ngx_fluentd_cleanup(void *data);
static ngx_int_t ngx_http_fluentd_send(ngx_udp_endpoint_t *l, u_char *buf, size_t len);

static void *ngx_http_fluentd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_fluentd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_fluentd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fluentd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_fluentd_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_fluentd_set_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_fluentd_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_fluentd_commands[] = {

    { ngx_string("access_fluentd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_TAKE123,
      ngx_http_fluentd_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fluentd_collector_max"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_fluentd_main_conf_t, collector_max),
      NULL },

    { ngx_string("fluentd_tag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fluentd_set_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fluentd_conf_t, tag),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_fluentd_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_fluentd_init,                 /* postconfiguration */

    ngx_http_fluentd_create_main_conf,     /* create main configuration */
    ngx_http_fluentd_init_main_conf,       /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_fluentd_create_loc_conf,      /* create location configration */
    ngx_http_fluentd_merge_loc_conf        /* merge location configration */
};

extern ngx_module_t  ngx_http_log_module;

ngx_module_t  ngx_http_fluentd_module = {
    NGX_MODULE_V1,
    &ngx_http_fluentd_module_ctx,          /* module context */
    ngx_http_fluentd_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_fluentd_handler(ngx_http_request_t *r)
{
    u_char                   *line, *p;
    size_t                    len;
    ngx_uint_t                i, l;
    ngx_str_t                 tag;
    ngx_http_fluentd_t       *log;
    ngx_http_log_op_t        *op;
    ngx_http_fluentd_conf_t  *flcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http fluentd handler");

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fluentd_module);

    if(flcf->off || flcf->logs == NULL) {
        return NGX_OK;
    }

    if(flcf->tag != NULL)
    {
        if(flcf->tag->lengths == NULL) {
            tag = flcf->tag->value;
        }
        else{
            if (ngx_http_script_run(r, &tag, flcf->tag->lengths->elts, 0, flcf->tag->values->elts)
                == NULL)
            {
                return NGX_ERROR;
            }
        }
    }
    else {
        tag.data = (u_char*)"nginx";
        tag.len = sizeof("nginx") - 1;
    }

    log = flcf->logs->elts;

    for (l = 0; l < flcf->logs->nelts; l++) {

#if defined nginx_version && nginx_version >= 7018
        ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);
#endif

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        len += 1 + sizeof("\"tag\":") - 1 + 1 + tag.len + 1 + 1 + 1 + 1; /* '{"tag":"value", }' */

#if defined nginx_version && nginx_version >= 7003
        line = ngx_pnalloc(r->pool, len);
#else
        line = ngx_palloc(r->pool, len);
#endif
        if (line == NULL) {
            return NGX_ERROR;
        }

        /*
         * JSON Style message
         */
        p = ngx_sprintf(line, "{\"tag\":\"%V\", ", &tag);

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

	*p++ = '}';

        ngx_http_fluentd_send(log[l].endpoint, line, p - line);
    }

    return NGX_OK;
}

static ngx_int_t ngx_fluentd_init_endpoint(ngx_conf_t *cf, ngx_udp_endpoint_t *endpoint) {
    ngx_pool_cleanup_t    *cln;
    ngx_udp_connection_t  *uc;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if(cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_fluentd_cleanup;
    cln->data = endpoint;

    uc = ngx_calloc(sizeof(ngx_udp_connection_t), cf->log);
    if (uc == NULL) {
        return NGX_ERROR;
    }

    endpoint->udp_connection = uc;

    uc->sockaddr = endpoint->peer_addr.sockaddr;
    uc->socklen = endpoint->peer_addr.socklen;
    uc->server = endpoint->peer_addr.name;
#if defined nginx_version && ( nginx_version >= 7054 && nginx_version < 8055 )
    uc->log = cf->cycle->new_log;
#else
    uc->log = cf->cycle->new_log;
#if defined nginx_version && nginx_version >= 8032
    uc->log.handler = NULL;
    uc->log.data = NULL;
    uc->log.action = "logging";
#endif
#endif

    return NGX_OK;
}

static void
ngx_fluentd_cleanup(void *data)
{
    ngx_udp_endpoint_t  *e = data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "cleanup fluentd");

    if(e->udp_connection) {
        if(e->udp_connection->connection) {
            ngx_close_connection(e->udp_connection->connection);
        }

        ngx_free(e->udp_connection);
    }
}

static void ngx_http_fluentd_dummy_handler(ngx_event_t *ev)
{
}

static ngx_int_t
ngx_http_fluentd_send(ngx_udp_endpoint_t *l, u_char *buf, size_t len)
{
    ssize_t                n;
    ngx_udp_connection_t  *uc;

    uc = l->udp_connection;

    if (uc->connection == NULL) {
        if(ngx_udp_connect(uc) != NGX_OK) {
            if(uc->connection != NULL) {
                ngx_free_connection(uc->connection);
                uc->connection = NULL;
            }

            return NGX_ERROR;
        }

        uc->connection->data = l;
        uc->connection->read->handler = ngx_http_fluentd_dummy_handler;
        uc->connection->read->resolver = 0;
    }

    n = ngx_send(uc->connection, buf, len);

    if (n == -1) {
        return NGX_ERROR;
    }

    if ((size_t) n != (size_t) len) {
#if defined nginx_version && nginx_version >= 8032
        ngx_log_error(NGX_LOG_CRIT, &uc->log, 0, "send() incomplete");
#else
        ngx_log_error(NGX_LOG_CRIT, uc->log, 0, "send() incomplete");
#endif
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_http_fluentd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_fluentd_main_conf_t  *fmcf;

    fmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fluentd_main_conf_t));
    if (fmcf == NULL) {
        return NULL;
    }

    fmcf->collector_max = NGX_CONF_UNSET_UINT;

    return fmcf;
}

static char *
ngx_http_fluentd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_fluentd_main_conf_t *fmcf = conf;

    if (fmcf->collector_max == NGX_CONF_UNSET_UINT) {
        fmcf->collector_max = 16;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_fluentd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fluentd_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fluentd_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_fluentd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fluentd_conf_t *prev = parent;
    ngx_http_fluentd_conf_t *conf = child;

    if(conf->tag == NULL) {
        conf->tag = prev->tag;
    }

    if(conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    return NGX_CONF_OK;
}

static ngx_udp_endpoint_t *
ngx_http_fluentd_add_endpoint(ngx_conf_t *cf, ngx_fluentd_addr_t *peer_addr)
{
    ngx_http_fluentd_main_conf_t   *fmcf;
    ngx_udp_endpoint_t             *endpoint;

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_fluentd_module);

    if (fmcf->endpoints == NULL) {
        fmcf->endpoints = ngx_array_create(cf->pool, fmcf->collector_max, sizeof(ngx_udp_endpoint_t));
        if (fmcf->endpoints == NULL) {
            return NULL;
        }
    }

    if (fmcf->endpoints->nelts > fmcf->collector_max) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "fluentd collector count out of range, increase the fluentd_collector_max");
        return NULL;
    }

    endpoint = ngx_array_push(fmcf->endpoints);
    if (endpoint == NULL) {
        return NULL;
    }

    endpoint->peer_addr = *peer_addr;

    return endpoint;
}

static char *
ngx_http_fluentd_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fluentd_conf_t     *flcf = conf;

    ngx_uint_t                      i;
    ngx_str_t                      *value, name;
    ngx_http_fluentd_t             *log;
    ngx_http_log_fmt_t             *fmt;
    ngx_http_log_main_conf_t       *lmcf;
    ngx_http_fluentd_main_conf_t   *fmcf;
    ngx_url_t                       u;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        flcf->off = 1;
        return NGX_CONF_OK;
    }

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_fluentd_module);

    if (fmcf->collector_max == NGX_CONF_UNSET_UINT) {
        fmcf->collector_max = 16;
    }

    if (flcf->logs == NULL) {
        flcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_fluentd_t));
        if (flcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if(lmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "fluentd module requires log module to be compiled in");
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(flcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_http_fluentd_t));

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 8765;
    u.no_resolve = 0;

    if(ngx_parse_url(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V: %s", &u.host, u.err);
        return NGX_CONF_ERROR;
    }

    log->endpoint = ngx_http_fluentd_add_endpoint(cf, &u.addrs[0]);

    if(log->endpoint == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts >= 3) {
        name = value[2];

        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }
    } else {
        name.len = sizeof("combined") - 1;
        name.data = (u_char *) "combined";
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            goto done;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown log format \"%V\"", &name);
    return NGX_CONF_ERROR;

done:

    return NGX_CONF_OK;
}

static char *
ngx_http_fluentd_set_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                    n;
    ngx_str_t                   *value;
    ngx_http_script_compile_t    sc;
    ngx_http_log_tag_template_t **field, *h;

    field = (ngx_http_log_tag_template_t**) (((u_char*)conf) + cmd->offset);

    value = cf->args->elts;

    if (*field == NULL) {
        *field = ngx_palloc(cf->pool, sizeof(ngx_http_log_tag_template_t));
        if (*field == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = *field;

    h->value = value[1];
    h->lengths = NULL;
    h->values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);

    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &h->lengths;
        sc.values = &h->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_fluentd_init(ngx_conf_t *cf)
{
    ngx_int_t                     rc;
    ngx_uint_t                    i;
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_fluentd_main_conf_t *fmcf;
    ngx_http_handler_pt          *h;
    ngx_udp_endpoint_t           *e;

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_fluentd_module);

    if(fmcf->endpoints != NULL) {
        e = fmcf->endpoints->elts;
        for(i = 0;i < fmcf->endpoints->nelts;i++) {
            rc = ngx_fluentd_init_endpoint(cf, e + i);

            if(rc != NGX_OK) {
                return NGX_ERROR;
            }
        }

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = ngx_http_fluentd_handler;
    }

    return NGX_OK;
}
