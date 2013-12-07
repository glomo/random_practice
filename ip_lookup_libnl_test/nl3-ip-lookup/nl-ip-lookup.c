/*
 * src/nl-route-get.c     Get Route Attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2009 Thomas Graf <tgraf@suug.ch>
 */

#include <netinet/in.h>

#include <netlink/cli/utils.h>
#include <netlink/cli/route.h>
#include <netlink/cli/link.h>

struct ip_lookup_res {
        uint32_t        dstaddr;
        int             oif;
        char            oifname[IFNAMSIZ];
        uint32_t        nh_addr;
};

static void print_usage(void)
{
	printf("Usage: nl-ip-lookup <addr>\n");
	exit(1);
}

void nexthop_parse_cb(struct rtnl_nexthop *nh, void *arg)
{
        struct nl_addr *addr;
        struct ip_lookup_res *res = (struct ip_lookup_res*) arg;
	struct nl_cache *link_cache;
	char buf[64];

	link_cache = nl_cache_mngt_require("route/link");

        addr = rtnl_route_nh_get_gateway(nh);
        if (addr) { 
                printf("via %s ", nl_addr2str(addr, buf, sizeof(buf)));
                res->nh_addr = *(uint32_t*) nl_addr_get_binary_addr(addr);
        }
        else {
                res->nh_addr = 0;
        }
        res->oif = rtnl_route_nh_get_ifindex(nh);
        printf("dev %s ", rtnl_link_i2name(link_cache, res->oif,
                                         buf, sizeof(buf)));
        rtnl_link_i2name(link_cache, res->oif, res->oifname, 
                        sizeof(res->oifname));

}

static void route_parse_cb(struct nl_object *obj, void *arg)
{

	struct nl_dump_params params = {
		.dp_fd = stdout,
		.dp_type = NL_DUMP_DETAILS,
	};

	nl_object_dump(obj, &params);


        struct ip_lookup_res *res = (struct ip_lookup_res*) arg;
	struct rtnl_route *route = (struct rtnl_route *) obj;
        struct nl_addr *addr;
        struct rtnl_nexthop *nh;
        int prefix_len;
        int oif;
	char buf[64];

        addr = rtnl_route_get_dst(route);
        if (addr) {
		printf("%s ", nl_addr2str(addr, buf, sizeof(buf)));
                res->dstaddr = *(uint32_t *) nl_addr_get_binary_addr(addr);
        }

        addr = rtnl_route_get_src(route);
        if (addr) 
		printf("src %s ", nl_addr2str(addr, buf, sizeof(buf)));

        addr = rtnl_route_get_pref_src(route);
        if (addr)
		printf("preferred src %s ", nl_addr2str(addr, buf, sizeof(buf)));

        rtnl_route_foreach_nexthop(route, nexthop_parse_cb, res);
                
        printf("\n");

}

static int cb(struct nl_msg *msg, void *arg)
{
	int err;

	if ((err = nl_msg_parse(msg, &route_parse_cb, arg)) < 0)
		nl_cli_fatal(err, "Unable to parse object: %s", nl_geterror(err));

	return 0;
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *link_cache, *route_cache;
	struct nl_addr *dst;
        struct ip_lookup_res res;
	int err = 1;

	if (argc < 2 || !strcmp(argv[1], "-h"))
		print_usage();

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_ROUTE);
	link_cache = nl_cli_link_alloc_cache(sock);
	route_cache = nl_cli_route_alloc_cache(sock, 0);

	dst = nl_cli_addr_parse(argv[1], AF_INET);

	{
		struct nl_msg *m;
		struct rtmsg rmsg = {
			.rtm_family = nl_addr_get_family(dst),
			.rtm_dst_len = nl_addr_get_prefixlen(dst),
		};

		m = nlmsg_alloc_simple(RTM_GETROUTE, 0);
		nlmsg_append(m, &rmsg, sizeof(rmsg), NLMSG_ALIGNTO);
		nla_put_addr(m, RTA_DST, dst);

		err = nl_send_auto_complete(sock, m);
		nlmsg_free(m);
		if (err < 0)
			nl_cli_fatal(err, "%s", nl_geterror(err));

                memset(&res, 0, sizeof(res));
		nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, cb, &res);

		if (nl_recvmsgs_default(sock) < 0)
			nl_cli_fatal(err, "%s", nl_geterror(err));

                printf("ip lookup result: oif idx: %d oif name %s ",
                        res.oif, res.oifname);
                if (res.nh_addr) {
                        char buf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &res.nh_addr, buf, sizeof(buf));
                        printf("via %s", buf);
                }
                printf ("\n");
	}

	return 0;
}
