/*
 * src/nl-route-get.c     Get Route Attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#include <net/if.h>
#include <netinet/in.h>

#include "utils.h"

struct ip_lookup_res {
        uint32_t        dstaddr;
        int             oif;
        char            oifname[IFNAMSIZ];
        uint32_t        nh_addr;
};

void print_usage(void)
{
	printf("Usage: nl1-ip-lookup <addr>\n");
	exit(1);
}

static void route_proc_cb(struct nl_object *c, void *arg)
{
        struct ip_lookup_res *res = (struct ip_lookup_res*) arg;
	struct rtnl_route *route = (struct rtnl_route *) c;
	struct nl_cache *link_cache;
        struct nl_addr *addr;
        struct rtnl_nexthop *nh;
        int prefix_len;
        int oif;
	char buf[64];

	link_cache = nl_cache_mngt_require("route/link");

        addr = rtnl_route_get_dst(route);
        if (addr) {
		printf("%s", nl_addr2str(addr, buf, sizeof(buf)));
                res->dstaddr = *(uint32_t *) nl_addr_get_binary_addr(addr);
        }

        prefix_len = rtnl_route_get_dst_len(route);
        if (prefix_len)
                printf("/%d ", prefix_len);
        else
                printf("default ");

        addr = rtnl_route_get_src(route);
        if (addr) 
		printf("src %s ", nl_addr2str(addr, buf, sizeof(buf)));

        addr = rtnl_route_get_pref_src(route);
        if (addr)
		printf("preferred src %s ", nl_addr2str(addr, buf, sizeof(buf)));

        addr = rtnl_route_get_gateway(route);
        if (addr) { 
		printf("via %s ", nl_addr2str(addr, buf, sizeof(buf)));
                res->nh_addr = *(uint32_t*) nl_addr_get_binary_addr(addr);
        }
        else {
                res->nh_addr = 0;
        }

        oif = rtnl_route_get_oif(route);
        res->oif = oif;
        if (oif != RTNL_LINK_NOT_FOUND && link_cache) {
	        printf("dev %s ", rtnl_link_i2name(link_cache, oif,
						 buf, sizeof(buf)));
                rtnl_link_i2name(link_cache, oif, res->oifname, sizeof(res->oifname));
        }
        
        /* Declaration of rtnl_route_nh_get_gateway() is missing from 
         * include/netlink/route/nexthop.h, there is no way to inspect
         * each nexthop for gateway information, will just use gateway 
         * info stored in rtnl_route struct. The probem is only present
         * libnl 1 */
        /*
        nl_list_for_each_entry(nh, rtnl_route_get_nexthops(route), rtnh_list) {

        }
        */
                
        printf("\n");

}

static int cb(struct nl_msg *msg, void *arg)
{
	nl_cache_parse_and_add(arg, msg);

        return 0;
}

int main(int argc, char *argv[])
{
	struct nl_handle *nlh;
	struct nl_cache *link_cache, *route_cache;
	struct nl_addr *dst;
	struct rtnl_route *route;
        struct ip_lookup_res res;
	struct nl_dump_params params = {
		.dp_fd = stdout,
		.dp_type = NL_DUMP_FULL
	};
	int err = 1;

	if (argc < 2 || !strcmp(argv[1], "-h"))
		print_usage();

	if (nltool_init(argc, argv) < 0)
		goto errout;

	nlh = nltool_alloc_handle();
	if (!nlh)
		goto errout;

	route = rtnl_route_alloc();
	if (!route)
		goto errout_free_handle;

	if (nltool_connect(nlh, NETLINK_ROUTE) < 0)
		goto errout_free_route;

	link_cache = nltool_alloc_link_cache(nlh);
	if (!link_cache)
		goto errout_close;

	dst = nltool_addr_parse(argv[1]);
	if (!dst)
		goto errout_link_cache;

	route_cache = nltool_alloc_route_cache(nlh);
	if (!route_cache)
		goto errout_addr_put;

	{
		struct nl_msg *m;
		struct rtmsg rmsg = {
			.rtm_family = nl_addr_get_family(dst),
			.rtm_dst_len = nl_addr_get_prefixlen(dst),
		};

		m = nlmsg_alloc_simple(RTM_GETROUTE, 0);
		nlmsg_append(m, &rmsg, sizeof(rmsg), NLMSG_ALIGNTO);
		nla_put_addr(m, RTA_DST, dst);

		if ((err = nl_send_auto_complete(nlh, m)) < 0) {
			nlmsg_free(m);
			fprintf(stderr, "%s\n", nl_geterror());
			goto errout_route_cache;
		}

		nlmsg_free(m);

		nl_socket_modify_cb(nlh, NL_CB_VALID, NL_CB_CUSTOM, cb,
				 route_cache);

		if (nl_recvmsgs_default(nlh) < 0) {
			fprintf(stderr, "%s\n", nl_geterror());
			goto errout_route_cache;
		}
	}

        rtnl_route_set_dst(route, dst);
	nl_cache_dump_filter(route_cache, &params, (struct nl_object *) route);
        memset(&res, 0, sizeof(res));
        nl_cache_foreach_filter(route_cache, (struct nl_object *) route, route_proc_cb,
                                &res);

        printf("ip lookup result: oif idx: %d oif name %s ",
                res.oif, res.oifname);
        if (res.nh_addr) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &res.nh_addr, buf, sizeof(buf));
                printf("via %s", buf);
        }
        printf ("\n");

	err = 0;
errout_route_cache:
	nl_cache_free(route_cache);
errout_addr_put:
	nl_addr_put(dst);
errout_link_cache:
	nl_cache_free(link_cache);
errout_close:
	nl_close(nlh);
errout_free_route:
        rtnl_route_put(route);
errout_free_handle:
	nl_handle_destroy(nlh);
errout:
	return err;
}
