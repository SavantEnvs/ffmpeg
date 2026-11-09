/*
 * libFuzzer harness for the DVB subtitle encoder, through the public API:
 * avcodec_find_encoder(AV_CODEC_ID_DVB_SUBTITLE) + avcodec_open2() + avcodec_encode_subtitle().
 *
 * The encoder takes an AVSubtitle of bitmap rects. Each rect owns a w*h palettized bitmap and an
 * nb_colors-entry palette, exactly as a caller (e.g. the ffmpeg CLI, whose output buffer is 1 MiB) provides.
 *
 * Input layout (little endian); the bytes after the headers are cycled as bitmap and palette content:
 *   u8  flags       bits 0-1: min_bpp option {2,4,8,3}; bits 2-3: number of rects (0..3)
 *   u16 width, u16 height   AVCodecContext display size (0 = unset)
 *   u16 out_units   output buffer is out_units*64 bytes
 *   per rect: u8 kind (bits 0-1: width class, bits 2-3: height class), u32 w_raw, u16 h_raw, u16 colors_raw
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "libavcodec/avcodec.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"

#define HDR_LEN       7
#define RECT_HDR_LEN  9
#define MAX_RECTS     3
#define MALLOC_LIMIT  (1u << 20)
/* A bitmap bigger than this cannot be provided by the harness; such inputs are rejected. */
#define BITMAP_LIMIT  (1ull << 34)

typedef struct Bitmap {
    uint8_t *p;
    size_t   len;
    int      mapped;
} Bitmap;

static void bitmap_free(Bitmap *b)
{
    if (b->mapped)
        munmap(b->p, b->len);
    else
        free(b->p);
    b->p = NULL;
}

static int bitmap_alloc(Bitmap *b, uint64_t len, const uint8_t *fill, size_t fill_len)
{
    if (len < 1)
        len = 1;
    if (len > BITMAP_LIMIT)
        return -1;
    b->len = len;
    if (len <= MALLOC_LIMIT) {
        b->mapped = 0;
        b->p = malloc(len);
        if (!b->p)
            return -1;
        for (size_t i = 0; i < len; i++)
            b->p[i] = fill_len ? fill[i % fill_len] : 0;
    } else {
        /* Untouched pages are zero and read-only-mapped, so a wide rect costs address space, not memory. */
        void *m = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (m == MAP_FAILED)
            return -1;
        b->mapped = 1;
        b->p = m;
        memcpy(b->p, fill, FFMIN(fill_len, len));
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const int min_bpp_tab[4] = { 2, 4, 8, 3 };
    const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_DVB_SUBTITLE);
    AVCodecContext *avctx = NULL;
    AVSubtitle sub = { 0 };
    Bitmap bitmaps[MAX_RECTS] = { { 0 } };
    uint32_t *palettes[MAX_RECTS] = { NULL };
    uint8_t *out = NULL;
    const uint8_t *fill, *p;
    size_t fill_len, out_size;
    int nb_rects, i, ret = -1;

    if (!codec || size < HDR_LEN)
        return -1;

    nb_rects = (data[0] >> 2) & 3;
    if (nb_rects > MAX_RECTS || size < HDR_LEN + (size_t)nb_rects * RECT_HDR_LEN)
        return -1;

    avctx = avcodec_alloc_context3(codec);
    if (!avctx)
        return -1;
    avctx->width  = data[1] | data[2] << 8;
    avctx->height = data[3] | data[4] << 8;
    avctx->time_base = (AVRational){ 1, 1000 };
    if (av_opt_set_int(avctx->priv_data, "min_bpp", min_bpp_tab[data[0] & 3], 0) < 0 ||
        avcodec_open2(avctx, codec, NULL) < 0)
        goto end;

    out_size = (size_t)(data[5] | data[6] << 8) * 64;
    out = malloc(out_size ? out_size : 1);
    if (!out)
        goto end;

    p        = data + HDR_LEN;
    fill     = p + nb_rects * RECT_HDR_LEN;
    fill_len = size - (fill - data);
    if (fill_len > 4096)
        fill_len = 4096;

    sub.rects = av_calloc(nb_rects ? nb_rects : 1, sizeof(*sub.rects));
    if (!sub.rects)
        goto end;
    sub.num_rects = nb_rects;

    for (i = 0; i < nb_rects; i++, p += RECT_HDR_LEN) {
        uint32_t w_raw = p[1] | p[2] << 8 | p[3] << 16 | (uint32_t)p[4] << 24;
        uint32_t h_raw = p[5] | p[6] << 8;
        int nb_colors  = (p[7] | p[8] << 8) % 300;
        int w, h;
        AVSubtitleRect *r;

        switch (p[0] & 3) {
        case 0:  w = 1 + w_raw % 512;          break;
        case 1:  w = 1 + w_raw % 0x20000;      break;
        case 2:  w = w_raw & 0x7fffffff;       break;
        default: w = 65530 + w_raw % 12;       break;
        }
        switch ((p[0] >> 2) & 3) {
        case 0:  h = h_raw % 9;                break;
        case 1:  h = h_raw % 0x20000;          break;
        case 2:  h = h_raw;                    break;
        default: h = 65530 + h_raw % 12;       break;
        }

        r = av_mallocz(sizeof(*r));
        if (!r)
            goto end;
        sub.rects[i] = r;
        r->type      = SUBTITLE_BITMAP;
        r->x         = w_raw >> 3;
        r->y         = h_raw;
        r->w         = w;
        r->h         = h;
        r->nb_colors = nb_colors;
        r->linesize[0] = w;

        if (bitmap_alloc(&bitmaps[i], (uint64_t)w * h, fill, fill_len) < 0)
            goto end;
        r->data[0] = bitmaps[i].p;

        palettes[i] = malloc(sizeof(uint32_t) * (nb_colors ? nb_colors : 1));
        if (!palettes[i])
            goto end;
        for (int c = 0; c < nb_colors; c++)
            palettes[i][c] = fill_len ? fill[(4 * c) % fill_len] * 0x01010101u ^ c : c;
        r->data[1] = (uint8_t *)palettes[i];
    }

    avcodec_encode_subtitle(avctx, out, out_size, &sub);
    ret = 0;

end:
    for (i = 0; i < nb_rects; i++) {
        bitmap_free(&bitmaps[i]);
        free(palettes[i]);
        if (sub.rects)
            av_free(sub.rects[i]);
    }
    av_free(sub.rects);
    free(out);
    avcodec_free_context(&avctx);
    return ret;
}
