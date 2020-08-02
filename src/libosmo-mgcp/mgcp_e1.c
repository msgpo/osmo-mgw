/* E1 traffic handling */

/*
 * (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/mgcp/mgcp_internal.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/core/msgb.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/abis.h>

#include <osmocom/trau/trau_sync.h>
#include <osmocom/trau/trau_frame.h>
#include <osmocom/trau/trau_rtp.h>
#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/netif/rtp.h>
#include <osmocom/mgcp/debug.h>
#include <osmocom/mgcp/mgcp_e1.h>
#include <osmocom/codec/codec.h>

#define DEBUG_BITS_MAX 1000
#define DEBUG_BYTES_MAX 50
#define E1_TS_BYTES 160

#define HACK_NON_STOP_SENDING 1

/* FIXME: create mgcp_network.h, put this in a common place */
#define RTP_BUF_SIZE		4096

static struct mgcp_config *cfg;

static const struct e1inp_line_ops dummy_e1_line_ops = {
	.sign_link_up = NULL,
	.sign_link_down = NULL,
	.sign_link = NULL,
};

static void e1_i460_mux_empty_cb(void *user_data)
{
	struct mgcp_endpoint *endp = user_data;
	struct msgb *msg = msgb_alloc(RTP_BUF_SIZE, "E1-idle-tx");
	uint8_t *ptr;
	uint8_t *ptr_dummy;

//                                           ==== C-BITS ===
//                                                    111111
//                                           123456789012345
//                                                      !
/* IDLE */
	char tf_dummy1[] = "10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010";
/* EFR FRAME */
	char tf_dummy2[] = "00000000000000001110100000001000110000100001011111010110100100101000111110010101101011010110000010011111000111011000011000011000100011110110110010011000100001011100000010000000101001000000001010101010110000001000000000000000100000000000000010000000000011101110101100000000100000000000000010000000000000001000111011111111";
/* IDLE FR DL */
	char tf_dummy3[] = "00000000000000001111000000001000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000001011111111";
/* IDLE EFR */
	char tf_dummy4[] = "00000000000000001110100000001000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010000000000000001000001011111111";

	if (endp->e1.trau_valid)
		/* In sync and running. */
		ptr_dummy = tf_dummy2;
	else
		/* Before the call */
		ptr_dummy = tf_dummy4;

	unsigned int i;
	ptr = msgb_put(msg, 320);

	for(i=0;i<320;i++)
	        ptr[i] = ptr_dummy[i] & 1;

	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-IDLE-TX: enquing %u trau frame bits: %s ...\n", msg->len,
		 osmo_ubit_dump(msgb_data(msg), msg->len > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : msg->len));

	osmo_i460_mux_enqueue(endp->e1.schan, msg);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-IDLE-TX: %u bits of audio enqued for E1 tx\n", msg->len);
}

/* called by I.460 de-multeiplexer; feed output of I.460 demux into TRAU frame sync */
static void e1_i460_demux_bits_cb(void *user_data, const ubit_t * bits, unsigned int num_bits)
{
	struct mgcp_endpoint *endp = user_data;
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-RX: receiving %u bits from subslot: %s ...\n", num_bits,
		 osmo_ubit_dump(bits, num_bits > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : num_bits));
	OSMO_ASSERT(endp->e1.sync_fi);
	osmo_trau_sync_rx_ubits(endp->e1.sync_fi, bits, num_bits);
}

/* called for each synchronized TRAU frame received; decode frame + convert to RTP
 * (the resulting frame will be prepended with an all-zero (12-byte) rtp header) */
static void sync_frame_out_cb(void *user_data, const ubit_t * bits, unsigned int num_bits)
{
	struct msgb *msg = msgb_alloc(RTP_BUF_SIZE, "E1-RTP-rx");
	unsigned int rtp_hdr_len = sizeof(struct rtp_hdr);
	struct mgcp_endpoint *endp = user_data;
	struct mgcp_conn *conn_dst;
	struct osmo_trau_frame fr;
	int rc;

	if (!bits) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: frame synchronization error, no bits received\n");
		goto skip;
	}
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-RX: receiving %u bits (syncronized) from E1 subslot: %s ...\n",
		 num_bits, osmo_ubit_dump(bits, num_bits > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : num_bits));

	endp->e1.trau_valid = true;

	/* Decode TRAU frame */
	switch (endp->e1.scd.rate) {
	case OSMO_I460_RATE_8k:
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: decoding 8k trau frame...\n");
		rc = osmo_trau_frame_decode_8k(&fr, bits, OSMO_TRAU_DIR_UL);
		break;
	case OSMO_I460_RATE_16k:
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: decoding 16k trau frame...\n");
		rc = osmo_trau_frame_decode_16k(&fr, bits, OSMO_TRAU_DIR_UL);
		break;
	case OSMO_I460_RATE_32k:
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: cannot decode 32k trau frame, rate not supported!\n");
		goto skip;
		break;
	case OSMO_I460_RATE_64k:
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: cannot decode 64k trau frame, rate not supported!\n");
		goto skip;
		break;
	default:
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: cannot decode trau frame, invalid rate set!\n");
		goto skip;
		break;
	}
	if (rc != 0) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: unable to decode trau frame\n");
		goto skip;
	}

	/* Check if the payload type is supported and what the expected lenth
	 * of the RTP payload will be. */
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-RX: decoded trau frame type: %s\n",
		 osmo_trau_frame_type_name(fr.type));

	/* Convert decoded trau frame to RTP frame */
	struct osmo_trau2rtp_state t2rs = {
		.type = fr.type,
	};
	rc = osmo_trau2rtp(msgb_data(msg) + rtp_hdr_len, msg->data_len - rtp_hdr_len, &fr, &t2rs);
	if (rc <= 0) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-RX: unable to convert trau frame to RTP audio\n");
		goto skip;
	}
	msgb_put(msg, rtp_hdr_len + rc);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-RX: encoded %u bytes of RTP audio: %s\n", rc,
		 osmo_hexdump(msgb_data(msg) + rtp_hdr_len, msg->len - rtp_hdr_len));

	/* Forward RTP data to IP */
	conn_dst = llist_first_entry(&endp->conns, struct mgcp_conn, entry);
	if (!conn_dst) {
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-i460-RX: unable to forward RTP audio data from E1: no connection to forward an incoming RTP packet to\n");
		goto skip;
	}
	if (conn_dst->type != MGCP_CONN_TYPE_RTP) {
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-i460-RX: unable to forward RTP audio data from E1: unable to find suitable destination conn\n");
		goto skip;
	}
	mgcp_send(endp, 1, NULL, msg, &conn_dst->u.rtp, &conn_dst->u.rtp);

skip:
	msgb_free(msg);
	return;
}

/* Function to handle outgoing E1 traffic */
void e1_send(struct e1inp_ts *ts, struct mgcp_trunk *trunk)
{
	struct msgb *msg = msgb_alloc(RTP_BUF_SIZE, "E1-tx");
	uint8_t *ptr;
	int rc;

	/* Get E1 frame from i460 multiplexer */
	ptr = msgb_put(msg, E1_TS_BYTES);
	rc = osmo_i460_mux_out(&trunk->e1.i460_ts[ts->num - 1], ptr, E1_TS_BYTES);
	if (rc < 0) {
		LOGP(DE1, LOGL_ERROR, "E1-TX: (trunk:%u, ts:%u) no data to transmit!\n", trunk->trunk_nr, ts->num);
		goto skip;
	}
	if (rc != E1_TS_BYTES) {
		LOGP(DE1, LOGL_ERROR,
		     "E1-TX: (trunk:%u, ts:%u) expected to get %u bytes of data, got %u bytes instead!\n",
		     trunk->trunk_nr, ts->num, E1_TS_BYTES, rc);
		goto skip;
	}

	/* Hand data over to the E1 stack */
	LOGP(DE1, LOGL_DEBUG, "E1-TX: (trunk:%u, ts:%u) sending %u bytes: %s ...\n", trunk->trunk_nr, ts->num, msg->len,
	     osmo_hexdump_nospc(msg->data, msg->len > DEBUG_BYTES_MAX ? DEBUG_BYTES_MAX : msg->len));

//      MUST NOT FLIP HERE!
//	osmo_revbytebits_buf(msg->data, msg->len);
	msgb_enqueue(&ts->raw.tx_queue, msg);
	return;
skip:
	msgb_free(msg);
}

/* Callback function to handle incoming E1 traffic */
void e1_recv_cb(struct e1inp_ts *ts, struct msgb *msg)
{
	struct mgcp_trunk *trunk;

	/* Find associated trunk */
	trunk = mgcp_trunk_by_line_num(cfg, ts->line->num);
	if (!trunk) {
		LOGP(DE1, LOGL_ERROR, "E1-RX: unable to find a trunk for E1-line %u!\n", ts->line->num);
		return;
	}

	/* Check if the incoming data looks sane */
	if (ts->num <= 0 || ts->num > 31) {
		LOGP(DE1, LOGL_ERROR, "E1-RX: (trunk:%u) E1 timeslot number (%u) out of range!\n", trunk->trunk_nr,
		     ts->num);
		return;
	}
	if (msg->len != E1_TS_BYTES) {
		LOGP(DE1, LOGL_ERROR,
		     "E1-RX: (trunk:%u, ts:%u) receiving bad, expected length is %u, actual length is %u!\n",
		     trunk->trunk_nr, ts->num, E1_TS_BYTES, msg->len);
		return;
	}

	LOGP(DE1, LOGL_DEBUG, "E1-RX: (trunk:%u, ts:%u) receiving %u bytes: %s ...\n", trunk->trunk_nr, ts->num,
	     msg->len, osmo_hexdump_nospc(msg->data, msg->len > DEBUG_BYTES_MAX ? DEBUG_BYTES_MAX : msg->len));

	/* Hand data over to the I640 demultiplexer. */
	//BUG: THE LOWER LAYER SHOULD FLIP BY ITSSELF!
	osmo_revbytebits_buf(msg->data, msg->len);
	osmo_i460_demux_in(&trunk->e1.i460_ts[ts->num - 1], msg->data, msg->len);

	/* Trigger sending of pending E1 traffic */
	e1_send(ts, trunk);
}

/*! Find an endpoint by its name on a specified trunk.
 *  \param[in] trunk trunk configuration.
 *  \param[in] ts_nr E1 timeslot number.
 *  \returns -EINVAL on failure, 0 on success. */
int mgcp_e1_init(struct mgcp_trunk *trunk, uint8_t ts_nr)
{
	/*! Each timeslot needs only to be configured once. The Timeslot then
	 *  stays open and permanently receives data. It is then up to the
	 *  I640 demultiplexer to add/remove subchannels as needed. It is
	 *  allowed to call this function multiple times since we check if the
	 *  timeslot is already configured. */

	struct e1inp_line *e1_line;
	int rc;

	OSMO_ASSERT(ts_nr > 0 || ts_nr < 32);
	cfg = trunk->cfg;

	if (trunk->e1.ts_in_use[ts_nr - 1]) {
		LOGP(DE1, LOGL_DEBUG, "(trunk:%u) E1 timeslot %u already set up, skipping...\n", trunk->trunk_nr,
		     ts_nr);
		return 0;
	}

	/* Get E1 line */
	if (!trunk->e1.line) {
		e1_line = e1inp_line_find(trunk->e1.vty_line_nr);
		if (!e1_line) {
			LOGP(DE1, LOGL_DEBUG, "(trunk:%u) no such E1 line %u - check VTY config!\n", trunk->trunk_nr,
			     trunk->e1.vty_line_nr);
			return -EINVAL;
		}
		e1inp_line_bind_ops(e1_line, &dummy_e1_line_ops);
	} else
		e1_line = trunk->e1.line;
	if (!e1_line)
		return -EINVAL;

	/* Configure E1 timeslot */
	rc = e1inp_ts_config_raw(&e1_line->ts[ts_nr - 1], e1_line, e1_recv_cb);
	if (rc < 0)
		return -EINVAL;
	e1inp_line_update(e1_line);
	if (rc < 0)
		return -EINVAL;

	LOGP(DE1, LOGL_DEBUG, "(trunk:%u) E1 timeslot %u set up successfully.\n", trunk->trunk_nr, ts_nr);
	trunk->e1.ts_in_use[ts_nr - 1] = true;

	return 0;
}

/* Equip E1 endpoint with i460 mux resources */
int mgcp_e1_endp_equip(struct mgcp_endpoint *endp, uint8_t ts, uint8_t ss, uint8_t offs)
{
	int rc;

	OSMO_ASSERT(ts != 0);
	OSMO_ASSERT(ts != 0xFF);
	OSMO_ASSERT(ss != 0xFF);
	OSMO_ASSERT(offs != 0xFF);

#if HACK_NON_STOP_SENDING == 1
	/* Prevent multiple initalizations! */
	if (endp->e1.schan)
		return 0;
#endif

	/* Set up E1 line / timeslot */
	rc = mgcp_e1_init(endp->trunk, ts);
	if (rc != 0)
		return -EINVAL;

	/* Set up i460 mux */
	switch (e1_rates[ss]) {
	case 64:
		endp->e1.scd.rate = OSMO_I460_RATE_64k;
		endp->e1.scd.demux.num_bits = 160 * 8;
		break;
	case 32:
		endp->e1.scd.rate = OSMO_I460_RATE_32k;
		endp->e1.scd.demux.num_bits = 80 * 8;
		break;
	case 16:
		endp->e1.scd.rate = OSMO_I460_RATE_16k;
		endp->e1.scd.demux.num_bits = 40 * 8;
		break;
	case 8:
		endp->e1.scd.rate = OSMO_I460_RATE_8k;
		endp->e1.scd.demux.num_bits = 20 * 8;
		break;
	}
	endp->e1.scd.bit_offset = offs;
	endp->e1.scd.demux.out_cb_bits = e1_i460_demux_bits_cb;
	endp->e1.scd.demux.out_cb_bytes = NULL;
	endp->e1.scd.demux.user_data = endp;
	endp->e1.scd.mux.in_cb_queue_empty = e1_i460_mux_empty_cb;
	endp->e1.scd.mux.user_data = endp;

	LOGPENDP(endp, DE1, LOGL_DEBUG, "adding i640 subchannel: ts=%u, bit_offset=%u, rate=%uk, num_bits=%lu\n", ts,
		 offs, e1_rates[ss], endp->e1.scd.demux.num_bits);
	endp->e1.sync_fi = osmo_trau_sync_alloc(endp, "trau-sync", sync_frame_out_cb, OSMO_TRAU_SYNCP_16_FR_EFR, endp);
	if (!endp->e1.sync_fi) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "adding i640 trau frame sync: failed!\n");
		return -EINVAL;
	}
	endp->e1.schan = osmo_i460_subchan_add(endp, &endp->trunk->e1.i460_ts[ts - 1], &endp->e1.scd);
	if (!endp->e1.schan) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "adding i640 subchannel: failed!\n");
		return -EINVAL;
	}

	return 0;
}

/* Remove E1 resources from endpoint */
void mgcp_e1_endp_release(struct mgcp_endpoint *endp)
{

	/* This does not work since any valid idle pattern from the BTS
	 * will set this back when the function is called before traffic
	 * from the BTS stops (this is the case!) */
	endp->e1.trau_valid = false;

#if HACK_NON_STOP_SENDING == 1
	/* Prevent de-initalization! */
	return;
#endif

	LOGPENDP(endp, DE1, LOGL_DEBUG, "removing i460 subchannel and sync...\n");

	if (endp->e1.schan)
		osmo_i460_subchan_del(endp->e1.schan);
	if (endp->e1.sync_fi)
		osmo_fsm_inst_term(endp->e1.sync_fi, OSMO_FSM_TERM_REGULAR, NULL);

	memset(&endp->e1.scd, 0, sizeof(endp->e1.scd));
	endp->e1.schan = NULL;
	endp->e1.sync_fi = NULL;
}

/*! Accept RTP message buffer with RTP data and enqueue voice data for E1 transmit.
 *  \param[in] endp related endpoint (does not take ownership).
 *  \param[in] codec configuration.
 *  \param[in] msg RTP message buffer (including RTP header).
 *  \returns 0 on success, -1 on ERROR. */
int mgcp_e1_send_rtp(struct mgcp_endpoint *endp, struct mgcp_rtp_codec *codec, struct msgb *msg)
{
	struct msgb *msg_tf = msgb_alloc(RTP_BUF_SIZE, "E1-trau-frame");
	unsigned int rtp_hdr_len = sizeof(struct rtp_hdr);
	struct osmo_trau2rtp_state st;
	struct osmo_trau_frame tf;
	uint8_t amr_ft;
	int rc;

	/* FIXME: Make this depended on the negotiated codecs */
	if (codec) {
		if (strcmp(codec->subtype_name, "GSM") == 0)
			st.type = OSMO_TRAU16_FT_FR;
		else if (strcmp(codec->subtype_name, "GSM-EFR") == 0)
			st.type = OSMO_TRAU16_FT_EFR;
		else if (strcmp(codec->subtype_name, "GSM-HR-08") == 0)
			st.type = OSMO_TRAU16_FT_HR;
		else if (strcmp(codec->subtype_name, "AMR") == 0) {
			st.type = OSMO_TRAU16_FT_AMR;
			if (endp->e1.scd.rate == OSMO_I460_RATE_8k) {
				amr_ft = (msgb_data(msg)[rtp_hdr_len + 1] >> 3) & 0xf;
				switch (amr_ft) {
				case AMR_4_75:
				case AMR_5_15:
				case AMR_5_90:
					st.type = OSMO_TRAU8_AMR_LOW;
					break;
				case AMR_6_70:
					st.type = OSMO_TRAU8_AMR_6k7;
					break;
				case AMR_7_40:
					st.type = OSMO_TRAU8_AMR_7k4;
					break;
				default:
					LOGPENDP(endp, DE1, LOGL_ERROR,
						 "E1-i460-TX: unsupported or illegal AMR frame type: %u\n", amr_ft);
					goto skip;
				}
			}
		} else {
			LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-TX: unsupported or illegal codec subtype name: %s\n",
				 codec->subtype_name);
			goto skip;

		}
	} else {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-TX: no codec info provided, assuming GSM (fullrate)\n");
		st.type = OSMO_TRAU16_FT_EFR;
	}
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-TX: using trau frame type: %s\n", osmo_trau_frame_type_name(st.type));

	/* Convert from RTP to TRAU format */
	if (msg->len <= rtp_hdr_len) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-TX: short rtp payload\n");
		goto skip;
	}
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-TX: enqueue %u bytes of RTP audio: %s\n", msg->len,
		 osmo_hexdump(msgb_data(msg) + rtp_hdr_len, msg->len - rtp_hdr_len));
	memset(&tf, 0, sizeof(tf));
	tf.dir = OSMO_TRAU_DIR_DL;
	rc = osmo_rtp2trau(&tf, msgb_data(msg) + rtp_hdr_len, msg->len - rtp_hdr_len, &st);
	if (rc < 0) {
		LOGPENDP(endp, DE1, LOGL_ERROR,
			 "E1-i460-TX: failed to convert from RTP payload format to TRAU format\n");
		goto skip;
	}

	rc = osmo_trau_frame_encode(msg_tf->data, msg_tf->data_len, &tf);
	if (rc < 0) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-TX: failed to encode TRAU frame\n");
		goto skip;
	}
	msgb_put(msg_tf, rc);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-TX: enquing %u trau frame bits: %s ...\n", msg_tf->len,
		 osmo_ubit_dump(msgb_data(msg_tf), msg_tf->len > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : msg_tf->len));

	/* Enqueue data to i460 multiplexer */
	if (!endp->e1.schan) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-TX: subchannel multiplexer missing\n");
		goto skip;
	}
	if (!endp->e1.sync_fi) {
		LOGPENDP(endp, DE1, LOGL_ERROR, "E1-i460-TX: subchannel sync missing\n");
		goto skip;
	}

	osmo_i460_mux_enqueue(endp->e1.schan, msg_tf);
	LOGPENDP(endp, DE1, LOGL_DEBUG, "E1-i460-TX: %u bits of audio enqued for E1 tx\n", msg_tf->len);

	return 0;
skip:
	msgb_free(msg_tf);
	return -1;
}
