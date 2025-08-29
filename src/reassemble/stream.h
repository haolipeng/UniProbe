#ifndef __STREAM_H__
#define __STREAM_H__

#define STREAM_START        BIT_U8(0)
#define STREAM_EOF          BIT_U8(1)
#define STREAM_TOSERVER     BIT_U8(2)
#define STREAM_TOCLIENT     BIT_U8(3)
#define STREAM_GAP          BIT_U8(4)   /**< data gap encountered */
#define STREAM_DEPTH        BIT_U8(5)   /**< depth reached */
#define STREAM_MIDSTREAM    BIT_U8(6)
#define STREAM_FLUSH        BIT_U8(7)

#endif /* __STREAM_H__ */
