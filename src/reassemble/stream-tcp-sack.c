#include "decode/decode.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"

RB_GENERATE(TCPSACK, StreamTcpSackRecord, rb, TcpSackCompare);

int TcpSackCompare(struct StreamTcpSackRecord *a, struct StreamTcpSackRecord *b)
{
    if (SEQ_GT(a->le, b->le))
        return 1;
    else if (SEQ_LT(a->le, b->le))
        return -1;
    else {
        if (SEQ_EQ(a->re, b->re))
            return 0;
        else if (SEQ_GT(a->re, b->re))
            return 1;
        else
            return -1;
    }
}

static inline void StreamTcpSackRecordFree(StreamTcpSackRecord *rec)
{
    free(rec);
    StreamTcpDecrMemuse((uint64_t)sizeof(*rec));
}

void StreamTcpSackPruneList(TcpStream *stream)
{
    StreamTcpSackRecord *rec = NULL, *safe = NULL;
    RB_FOREACH_SAFE(rec, TCPSACK, &stream->sack_tree, safe) {
        if (SEQ_LT(rec->re, stream->last_ack)) {
            SCLogDebug("removing le %u re %u", rec->le, rec->re);
            stream->sack_size -= (rec->re - rec->le);
            TCPSACK_RB_REMOVE(&stream->sack_tree, rec);

            StreamTcpSackRecordFree(rec);
            if(NULL != rec){
                free(rec);
            }
        } else if (SEQ_LT(rec->le, stream->last_ack)) {
            SCLogDebug("adjusting record to le %u re %u", rec->le, rec->re);
            /* last ack inside this record, update */
            stream->sack_size -= (rec->re - rec->le);
            rec->le = stream->last_ack;
            stream->sack_size += (rec->re - rec->le);
            break;
        } else {
            SCLogDebug("record beyond last_ack, nothing to do. Bailing out.");
            break;
        }
    }
    return;
}

static inline StreamTcpSackRecord *StreamTcpSackRecordAlloc(void)
{
    if (StreamTcpCheckMemcap((uint32_t)sizeof(StreamTcpSackRecord)) == 0)
        return NULL;

    StreamTcpSackRecord *rec = malloc(sizeof(*rec));
    if (unlikely(rec == NULL))
        return NULL;

    StreamTcpIncrMemuse((uint64_t)sizeof(*rec));
    return rec;
}

static inline void ConsolidateFwd(TcpStream *stream, struct TCPSACK *tree, struct StreamTcpSackRecord *sa)
{
    struct StreamTcpSackRecord *tr, *s = sa;
    RB_FOREACH_FROM(tr, TCPSACK, s) {
        if (sa == tr)
            continue;
        SCLogDebug("-> (fwd) tr %p %u/%u", tr, tr->le, tr->re);

        if (SEQ_LT(sa->re, tr->le))
            break; // entirely before

        if (SEQ_GEQ(sa->le, tr->le) && SEQ_LEQ(sa->re, tr->re)) {
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->re = tr->re;
            sa->le = tr->le;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (fwd) tr %p %u/%u REMOVED ECLIPSED2", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
            /*
                sa: [         ]
                tr: [         ]
                sa: [         ]
                tr:    [      ]
                sa: [         ]
                tr:    [   ]
            */
        } else if (SEQ_LEQ(sa->le, tr->le) && SEQ_GEQ(sa->re, tr->re)) {
            SCLogDebug("-> (fwd) tr %p %u/%u REMOVED ECLIPSED", tr, tr->le, tr->re);
            stream->sack_size -= (tr->re - tr->le);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
            /*
                sa: [         ]
                tr:      [         ]
                sa: [       ]
                tr:         [       ]
            */
        } else if (SEQ_LT(sa->le, tr->le) && // starts before
                   SEQ_GEQ(sa->re, tr->le) && SEQ_LT(sa->re, tr->re) // ends inside
                ) {
            // merge
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->re = tr->re;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (fwd) tr %p %u/%u REMOVED MERGED", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        }
    }
}

static inline void ConsolidateBackward(TcpStream *stream,
                                       struct TCPSACK *tree, struct StreamTcpSackRecord *sa)
{
    struct StreamTcpSackRecord *tr, *s = sa;
    RB_FOREACH_REVERSE_FROM(tr, TCPSACK, s) {
        if (sa == tr)
            continue;
        SCLogDebug("-> (bwd) tr %p %u/%u", tr, tr->le, tr->re);

        if (SEQ_GT(sa->le, tr->re))
            break; // entirely after
        if (SEQ_GEQ(sa->le, tr->le) && SEQ_LEQ(sa->re, tr->re)) {
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->re = tr->re;
            sa->le = tr->le;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (bwd) tr %p %u/%u REMOVED ECLIPSED2", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
            /*
                sa: [         ]
                tr: [         ]
                sa:    [      ]
                tr: [         ]
                sa:    [   ]
                tr: [         ]
            */
        } else if (SEQ_LEQ(sa->le, tr->le) && SEQ_GEQ(sa->re, tr->re)) {
            SCLogDebug("-> (bwd) tr %p %u/%u REMOVED ECLIPSED", tr, tr->le, tr->re);
            stream->sack_size -= (tr->re - tr->le);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
            /*
                sa:     [   ]
                tr: [   ]
                sa:    [    ]
                tr: [   ]
            */
        } else if (SEQ_GT(sa->le, tr->le) && SEQ_GT(sa->re, tr->re) && SEQ_LEQ(sa->le,tr->re)) {
            // merge
            stream->sack_size -= (tr->re - tr->le);
            stream->sack_size -= (sa->re - sa->le);
            sa->le = tr->le;
            stream->sack_size += (sa->re - sa->le);
            SCLogDebug("-> (bwd) tr %p %u/%u REMOVED MERGED", tr, tr->le, tr->re);
            TCPSACK_RB_REMOVE(tree, tr);
            StreamTcpSackRecordFree(tr);
        }
    }
}

static int Insert(TcpStream *stream, struct TCPSACK *tree, uint32_t le, uint32_t re)
{
    SCLogDebug("* inserting: %u/%u\n", le, re);

    struct StreamTcpSackRecord *sa = StreamTcpSackRecordAlloc();
    if (unlikely(sa == NULL))
        return -1;
    sa->le = le;
    sa->re = re;
    struct StreamTcpSackRecord *res = TCPSACK_RB_INSERT(tree, sa);
    if (res) {
        // exact overlap
        SCLogDebug("* insert failed: exact match in tree with %p %u/%u", res, res->le, res->re);
        StreamTcpSackRecordFree(sa);
        return 0;
    }
    stream->sack_size += (re - le);
    ConsolidateBackward(stream, tree, sa);
    ConsolidateFwd(stream, tree, sa);
    return 0;
}

static int StreamTcpSackInsertRange(TcpStream *stream, uint32_t le, uint32_t re)
{
    SCLogDebug("le %u, re %u", le, re);

    /* if to the left of last_ack then ignore */
    if (SEQ_LT(re, stream->last_ack)) {
        SCLogDebug("too far left. discarding");
        return 0;
    }
    /* if to the right of the tcp window then ignore */
    if (SEQ_GT(le, (stream->last_ack + stream->window))) {
        SCLogDebug("too far right. discarding");
        return 0;
    }

    if (Insert(stream, &stream->sack_tree, le, re) < 0)
        return -1;

    return 0;
}

int StreamTcpSackUpdatePacket(TcpStream *stream, Packet *p)
{
    const int records = TCP_GET_SACK_CNT(p);
    const uint8_t *data = TCP_GET_SACK_PTR(p);

    if (records == 0 || data == NULL)
        return 0;

    TCPOptSackRecord rec[records], *sack_rec = rec;
    memcpy(&rec, data, sizeof(TCPOptSackRecord) * records);

    for (int record = 0; record < records; record++) {
        const uint32_t le = SCNtohl(sack_rec->le);
        const uint32_t re = SCNtohl(sack_rec->re);

        SCLogDebug("%p last_ack %u, left edge %u, right edge %u", sack_rec,stream->last_ack, le, re);

        if (SEQ_LEQ(re, stream->last_ack)) {
            SCLogDebug("record before last_ack");
            goto next;
        }

        if (SEQ_GT(re, stream->next_win)) {
            SCLogDebug("record %u:%u beyond next_win %u",
                       le, re, stream->next_win);
            goto next;
        }

        if (SEQ_GEQ(le, re)) {
            SCLogDebug("invalid record: le >= re");
            goto next;
        }

        if (StreamTcpSackInsertRange(stream, le, re) == -1) {
            return -1;
        }

        next:
        sack_rec++;
    }
    StreamTcpSackPruneList(stream);
    return 0;
}