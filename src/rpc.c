/* The srvsvc pipe on IPC$: how Explorer lists the shares when it is given only \\<console>.
 *
 * libdcerpc's server runtime (BSD-2-Clause, from the pinned libsmb2 tree) does BIND, fragments and faults and
 * decodes and encodes with its generated srvsvc coders; the three calls Explorer makes are answered here. */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <dcerpc/dcerpc.h>
#include <dcerpc/server.h>
#include <dcerpc/srvsvc.h>

#include "smbd.h"

/* share types (MS-SRVS 2.2.2.4) and the Win32 errors these calls return */
#define STYPE_DISKTREE 0x00000000u
#define STYPE_IPC 0x00000003u
#define STYPE_SPECIAL 0x80000000u
#define ERROR_INVALID_LEVEL 124u
#define NERR_NET_NAME_NOT_FOUND 2310u

static struct dcerpc_server *g_srv;
static char g_remarks[8][64];

static int share_count(void)
{
	return smbd_share_count + 1; /* and IPC$ */
}

static void share_at(int i, const char **name, uint32_t *type, const char **remark)
{
	if (i < smbd_share_count) {
		snprintf(g_remarks[i], sizeof(g_remarks[i]), "%s %s", smbd_name, smbd_shares[i].root);
		*name = smbd_shares[i].name;
		*type = STYPE_DISKTREE;
		*remark = g_remarks[i];
	} else {
		*name = "IPC$";
		*type = STYPE_IPC | STYPE_SPECIAL;
		*remark = "Remote IPC";
	}
}

/* NetrShareEnum (opnum 15), levels 0 and 1 */
static int share_enum(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, void *req_p, void *rep_p)
{
	struct srvsvc_NetrShareEnum_req *req = req_p;
	struct srvsvc_NetrShareEnum_rep *rep = rep_p;
	int n = share_count();

	(void)dce;
	rep->InfoStruct.Level = req->InfoStruct.Level;
	rep->TotalEntries = (uint32_t)n;
	rep->ResumeHandle = 0;
	if (req->InfoStruct.Level == 0) {
		struct srvsvc_SHARE_INFO_0 *b = dcerpc_alloc_data(pdu, sizeof(*b) * (size_t)n);

		if (!b)
			return -1;
		for (int i = 0; i < n; i++) {
			uint32_t type;
			const char *name, *remark;

			share_at(i, &name, &type, &remark);
			b[i].NetName = (char *)name;
		}
		rep->InfoStruct.ShareInfo.Level0.EntriesRead = (uint32_t)n;
		rep->InfoStruct.ShareInfo.Level0.Buffer = b;
	} else if (req->InfoStruct.Level == 1) {
		struct srvsvc_SHARE_INFO_1 *b = dcerpc_alloc_data(pdu, sizeof(*b) * (size_t)n);

		if (!b)
			return -1;
		for (int i = 0; i < n; i++) {
			uint32_t type;
			const char *name, *remark;

			share_at(i, &name, &type, &remark);
			b[i].NetName = (char *)name;
			b[i].Type = type;
			b[i].Remark = (char *)remark;
		}
		rep->InfoStruct.ShareInfo.Level1.EntriesRead = (uint32_t)n;
		rep->InfoStruct.ShareInfo.Level1.Buffer = b;
	} else {
		smbd_log("srvsvc: share list level %u not answered", req->InfoStruct.Level);
		rep->TotalEntries = 0;
		rep->status = ERROR_INVALID_LEVEL;
		return 0;
	}
	rep->status = 0;
	if (smbd_trace)
		smbd_log("srvsvc: share list (level %u, %d shares)", req->InfoStruct.Level, n);
	return 0;
}

/* NetrShareGetInfo (opnum 16), levels 0 and 1 */
static int share_get_info(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, void *req_p, void *rep_p)
{
	struct srvsvc_NetrShareGetInfo_req *req = req_p;
	struct srvsvc_NetrShareGetInfo_rep *rep = rep_p;

	(void)dce;
	(void)pdu;
	for (int i = 0; i < share_count(); i++) {
		uint32_t type;
		const char *name, *remark;

		share_at(i, &name, &type, &remark);
		if (!req->NetName || strcasecmp(req->NetName, name))
			continue;
		if (req->Level == 0) {
			rep->InfoStruct.ShareInfo0.NetName = (char *)name;
		} else if (req->Level == 1) {
			rep->InfoStruct.ShareInfo1.NetName = (char *)name;
			rep->InfoStruct.ShareInfo1.Type = type;
			rep->InfoStruct.ShareInfo1.Remark = (char *)remark;
		} else {
			rep->status = ERROR_INVALID_LEVEL;
			return 0;
		}
		rep->status = 0;
		return 0;
	}
	rep->status = NERR_NET_NAME_NOT_FOUND;
	return 0;
}

/* NetrServerGetInfo (opnum 21), levels 100 and 101 */
static int server_get_info(struct dcerpc_context *dce, struct dcerpc_pdu *pdu, void *req_p, void *rep_p)
{
	struct srvsvc_NetrServerGetInfo_req *req = req_p;
	struct srvsvc_NetrServerGetInfo_rep *rep = rep_p;

	(void)dce;
	(void)pdu;
	if (req->Level == 100) {
		rep->InfoStruct.ServerInfo100.PlatformId = 500; /* PLATFORM_ID_NT */
		rep->InfoStruct.ServerInfo100.Name = smbd_name;
	} else if (req->Level == 101) {
		rep->InfoStruct.ServerInfo101.PlatformId = 500;
		rep->InfoStruct.ServerInfo101.Name = smbd_name;
		rep->InfoStruct.ServerInfo101.VersionMajor = 10;
		rep->InfoStruct.ServerInfo101.VersionMinor = 0;
		/* SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_SERVER_NT */
		rep->InfoStruct.ServerInfo101.Type = 0x00000001u | 0x00000002u | 0x00008000u;
		rep->InfoStruct.ServerInfo101.Comment = "ps5-smbd";
	} else {
		rep->status = ERROR_INVALID_LEVEL;
		return 0;
	}
	rep->status = 0;
	return 0;
}

static const struct dcerpc_stub srvsvc_stubs[] = {
	{SRVSVC_NETRSHAREENUM, "NetrShareEnum", share_enum},
	{SRVSVC_NETRSHAREGETINFO, "NetrShareGetInfo", share_get_info},
	{SRVSVC_NETRSERVERGETINFO, "NetrServerGetInfo", server_get_info},
	{-1, NULL, NULL},
};

static void rpc_log(void *private_data, int level, const char *msg)
{
	(void)private_data;
	if (level == DCERPC_SERVER_LOG_ERROR || smbd_trace)
		smbd_log("srvsvc: %s", msg);
}

int rpc_init(void)
{
	g_srv = dcerpc_server_create("srvsvc");
	if (!g_srv)
		return -1;
	dcerpc_server_set_log(g_srv, DCERPC_SERVER_LOG_INFO, rpc_log, NULL);
	if (dcerpc_server_add_interface(g_srv, &srvsvc_interface, srvsvc_procs, srvsvc_stubs, DCERPC_SERVER_ALL_NDR)) {
		dcerpc_server_destroy(g_srv);
		g_srv = NULL;
		return -1;
	}
	return 0;
}

/* The pipe names this server answers on IPC$ ("srvsvc", "\PIPE\srvsvc"). */
int rpc_is_pipe(const char *name)
{
	if (!name)
		return 0;
	while (*name == '\\' || *name == '/')
		name++;
	if (!strncasecmp(name, "PIPE\\", 5) || !strncasecmp(name, "PIPE/", 5))
		name += 5;
	return g_srv && !strcasecmp(name, "srvsvc");
}

void *rpc_pipe_open(void)
{
	return g_srv ? dcerpc_server_pipe_create(g_srv, NULL) : NULL;
}

void rpc_pipe_close(void *pipe)
{
	if (pipe)
		dcerpc_server_pipe_destroy(pipe);
}

int rpc_pipe_write(void *pipe, const uint8_t *buf, size_t len)
{
	return dcerpc_server_pipe_write(pipe, buf, len);
}

size_t rpc_pipe_read(void *pipe, uint8_t *buf, size_t max, int *more)
{
	return dcerpc_server_pipe_read(pipe, buf, max, more);
}
