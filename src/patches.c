//
// Copyright 2023 Olivier Huguenot, Vadim Kindl
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the “Software”),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Script bug fixes, applied at load on an exact byte match. Findings and
// byte-level notes for each fix are in docs/scripts/.

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include "sys/sys.h"
#include "alis.h"
#include "debug.h"
#include "patches.h"
#include "platform.h"

typedef struct {
    s32 uid;
    const char *what;
    u8 len;
    const u8 *le_old, *be_old, *le_new, *be_new;
    u8 call_fix;
    u8 call_at;
    u8 call_to;
} sScriptFix;

// Ishar 1 SOS: the save name was built from all 8 key slots, so a previous longer
// name leaked in (12345 then ABC -> ABC45.SAV). Build it from the typed slots only:
// count loc.b[0x19] down, prepending chr$(loc.wt[0x11c][i]) to main.s[0x4220].
static const u8 ishar1_sav_le_old[48] = {
    0x1e,0x00,0x00,0x12,0x19, 0x1e,0x38,0x12,0x19,0x10,0x1c,0x01,0x3a,0x08,0x3c,0x01,
    0x1e,0x38,0x08,0x3c,0x01,0x9e,0x3a,0x0a,0x0a,0x01, 0x20,0x0a,0x0a,0x01,0x22,0x20,0x42,
    0x20,0x00,0x01,0x12,0x19, 0x1f,0x38,0x12,0x19,0x4e,0x00,0x07,0x3a, 0x15,0xd5 };
static const u8 ishar1_sav_be_old[48] = {
    0x1e,0x00,0x00,0x12,0x19, 0x1e,0x38,0x12,0x19,0x10,0x01,0x1c,0x3a,0x08,0x01,0x3c,
    0x1e,0x38,0x08,0x01,0x3c,0x9e,0x3a,0x0a,0x01,0x0a, 0x20,0x0a,0x01,0x0a,0x22,0x42,0x20,
    0x20,0x00,0x01,0x12,0x19, 0x1f,0x38,0x12,0x19,0x4e,0x00,0x07,0x3a, 0x15,0xd5 };
static const u8 ishar1_sav_le_new[48] = {
    0x21,0x00,0x01,0x12,0x19,                                   // csub   loc.b[0x19] += -1
    0x1e,0x38,0x12,0x19,0x10,0x1c,0x01,0x9e,0x88,0x22,0x20,0x42,0x3a,0x22,0x20,0x42,
                                                                // cstore main.s = chr$(tab[i]) + main.s
    0x1f,0x12,0x19,                                             // ceval  loc.b[0x19]
    0x15,0xe6,                                                  // cbnz8  loop
    0x08,0x14 };                                                // cjmp8  past the old bytes
static const u8 ishar1_sav_be_new[48] = {
    0x21,0x00,0x01,0x12,0x19,
    0x1e,0x38,0x12,0x19,0x10,0x01,0x1c,0x9e,0x88,0x22,0x42,0x20,0x3a,0x22,0x42,0x20,
    0x1f,0x12,0x19,
    0x15,0xe6,
    0x08,0x14 };

// Ishar 1 FRISE: the health bar is x = 4300 / (max * 100 / cur) - 5, and max * 100
// wraps at max HP 328 (16-bit), moving the bar off its slot. Both sites now call
// one routine, exact below 328: s = max / 328 + 1, x = 4300 / ((max/s*100) / (cur/s)) - 5.
static const u8 ishar1_bar1_le_old[110] = {
    0x1f,0x38,0x12,0x22,0x28,0x42,0x15,0x54,0x00,0x00,0x40,0x12,0x22,0x26,0x64,0x16,
    0x4c,0x00,0xff,0x42,0x36,0x3a,0x14,0x27,0x00,0x00,0x1e,0x38,0x12,0x22,0x28,0x5a,
    0x15,0x5e,0x00,0x64,0x40,0x12,0x22,0x28,0x42,0x15,0x5c,0x36,0x3a,0x14,0xcc,0x1e,
    0x38,0x02,0xcc,0x10,0x5c,0x14,0xcc,0x58,0x00,0x05,0x3a,0x14,0xd0,0x0a,0x05,0x00,
    0x00,0x1e,0x00,0xfb,0x14,0xd0,0x49,0x38,0x14,0xd0,0x40,0x12,0x22,0x5e,0x00,0x40,
    0x56,0x36,0x3a,0x38,0x00,0x15,0x40,0x12,0x22,0x5e,0x00,0x0a,0x56,0x36,0x3a,0x00,
    0x0c,0x00,0x03,0x38,0x12,0x22,0x56,0x00,0x13,0x3a,0x0a,0x24,0x00,0x00 };
static const u8 ishar1_bar1_be_old[110] = {
    0x1f,0x38,0x12,0x22,0x28,0x15,0x42,0x54,0x00,0x00,0x40,0x12,0x22,0x26,0x16,0x64,
    0x4c,0x00,0xff,0x42,0x36,0x3a,0x14,0x00,0x00,0x27,0x1e,0x38,0x12,0x22,0x28,0x15,
    0x5a,0x5e,0x00,0x64,0x40,0x12,0x22,0x28,0x15,0x42,0x5c,0x36,0x3a,0x14,0xcc,0x1e,
    0x38,0x02,0x10,0xcc,0x5c,0x14,0xcc,0x58,0x00,0x05,0x3a,0x14,0xd0,0x0a,0x00,0x00,
    0x05,0x1e,0x00,0xfb,0x14,0xd0,0x49,0x38,0x14,0xd0,0x40,0x12,0x22,0x5e,0x00,0x40,
    0x56,0x36,0x3a,0x38,0x00,0x15,0x40,0x12,0x22,0x5e,0x00,0x0a,0x56,0x36,0x3a,0x00,
    0x0c,0x00,0x03,0x38,0x12,0x22,0x56,0x00,0x13,0x3a,0x0a,0x00,0x00,0x24 };
static const u8 ishar1_bar1_le_new[110] = {
    0x05,0x27,                                                  // cjsr8   bar
    0x49,0x38,0x14,0xd0,0x40,0x12,0x22,0x5e,0x00,0x40,0x56,0x36,0x3a,0x38,0x00,0x15,
    0x40,0x12,0x22,0x5e,0x00,0x0a,0x56,0x36,0x3a,0x00,0x0c,0x00,0x03,0x38,0x12,0x22,
    0x56,0x00,0x13,0x3a,                                        // cputnat (moved up)
    0x08,0x6a,                                                  // cjmp8   0x1a6
    0x00,
    0x1e,0x00,0xfb,0x14,0xd0,                                   // bar: cstore x = -5
    0x1e,0x38,0x12,0x22,0x28,0x5a,0x15,0x5c,0x02,0x48,0x01,0x56,0x00,0x01,0x3a,0x14,0xcc,
                                                                // cstore s = max / 328 + 1
    0x1f,0x38,0x12,0x22,0x28,0x42,0x15,0x50,0x14,0xcc,0x3a,     // ceval   cur >= s
    0x12,0x21,                                                  // cbz8    ret
    0x20,0x38,0x02,0xcc,0x10,0x40,0x12,0x22,0x28,0x5a,0x15,0x5c,0x14,0xcc,0x5e,0x00,0x64,
    0x40,0x12,0x22,0x28,0x42,0x15,0x5c,0x14,0xcc,0x5c,0x36,0x5c,0x36,0x3a,0x14,0xd0,
                                                                // cadd    x += 4300 / (max/s*100 / (cur/s))
    0x11 };                                                     // ret: cret
static const u8 ishar1_bar1_be_new[110] = {
    0x05,0x27,
    0x49,0x38,0x14,0xd0,0x40,0x12,0x22,0x5e,0x00,0x40,0x56,0x36,0x3a,0x38,0x00,0x15,
    0x40,0x12,0x22,0x5e,0x00,0x0a,0x56,0x36,0x3a,0x00,0x0c,0x00,0x03,0x38,0x12,0x22,
    0x56,0x00,0x13,0x3a,
    0x08,0x6a,
    0x00,
    0x1e,0x00,0xfb,0x14,0xd0,
    0x1e,0x38,0x12,0x22,0x28,0x15,0x5a,0x5c,0x02,0x01,0x48,0x56,0x00,0x01,0x3a,0x14,0xcc,
    0x1f,0x38,0x12,0x22,0x28,0x15,0x42,0x50,0x14,0xcc,0x3a,
    0x12,0x21,
    0x20,0x38,0x02,0x10,0xcc,0x40,0x12,0x22,0x28,0x15,0x5a,0x5c,0x14,0xcc,0x5e,0x00,0x64,
    0x40,0x12,0x22,0x28,0x15,0x42,0x5c,0x14,0xcc,0x5c,0x36,0x5c,0x36,0x3a,0x14,0xd0,
    0x11 };
static const u8 ishar1_bar2_le_old[59] = {
    0x1f,0x38,0x12,0x22,0x28,0x42,0x15,0x54,0x00,0x00,0x3a,0x14,0x27,0x00,0x00,0x1e,
    0x38,0x12,0x22,0x28,0x5a,0x15,0x5e,0x00,0x64,0x40,0x12,0x22,0x28,0x42,0x15,0x5c,
    0x36,0x3a,0x14,0xcc,0x1e,0x38,0x02,0xcc,0x10,0x5c,0x14,0xcc,0x58,0x00,0x05,0x3a,
    0x14,0xd0,0x0a,0x05,0x00,0x00,0x1e,0x00,0xfb,0x14,0xd0 };
static const u8 ishar1_bar2_be_old[59] = {
    0x1f,0x38,0x12,0x22,0x28,0x15,0x42,0x54,0x00,0x00,0x3a,0x14,0x00,0x00,0x27,0x1e,
    0x38,0x12,0x22,0x28,0x15,0x5a,0x5e,0x00,0x64,0x40,0x12,0x22,0x28,0x15,0x42,0x5c,
    0x36,0x3a,0x14,0xcc,0x1e,0x38,0x02,0x10,0xcc,0x5c,0x14,0xcc,0x58,0x00,0x05,0x3a,
    0x14,0xd0,0x0a,0x00,0x00,0x05,0x1e,0x00,0xfb,0x14,0xd0 };
static const u8 ishar1_bar2_new[59] = {
    0x06,0x00,0x00,                                             // cjsr16  bar (set at load)
    0x08,0x36 };                                                // cjmp8   past the old bytes

static const sScriptFix script_fixes[] = {
    { EGameIshar_1, "save name keeps old characters", 48,
      ishar1_sav_le_old, ishar1_sav_be_old, ishar1_sav_le_new, ishar1_sav_be_new },
    { EGameIshar_1, "health bar overflow (redraw)", 110,
      ishar1_bar1_le_old, ishar1_bar1_be_old, ishar1_bar1_le_new, ishar1_bar1_be_new },
    { EGameIshar_1, "health bar overflow (update)", 59,
      ishar1_bar2_le_old, ishar1_bar2_be_old, ishar1_bar2_new, ishar1_bar2_new, 2, 1, 41 },
};

// Ishar 3 boot options (Silmarils' own shortcut): MAIN.IO sets the language
// main.b[0x3dc4] = 0xff, then shows the flag screen only if it is still 0xff.
// Storing the chosen language there instead skips the flags (0 fr, 1 en, 2 de, 3 es).
s32 opt_lang = -1;
static const u8 ishar3_lang_le[14] = { 0x1e,0x00,0xff,0x06,0xc4,0x3d, 0x1f,0x38,0x06,0xc4,0x3d,0x4a,0x00,0xff };

// --skip-intro: MAIN.IO loads logosnd.IO (logo film), then introsnd.IO (intro film), then
// reaches "ceval main.b[0x42e1]; cbz24; cjsr24; cload scomb.IO; cjsr24; cload param.IO".
// The logo's cload becomes a cjmp24 to that ceval, so the title screen comes right away.
s32 opt_skip_intro = 0;
static const u8 ishar3_logo_le[14] = { 0x45,0xca,0x00,'l','o','g','o','s','n','d','.','I','O',0x00 };
static const u8 ishar3_param_le[12] = { 0x45,0x15,0x00,'p','a','r','a','m','.','I','O',0x00 };
static const u8 ishar3_after_intro_le[8] = { 0x1f,0x06,0xe1,0x42,0x14,0x10,0x00,0x00 };   // 0x1c bytes before param's cload

// --passersby: town passersby (vperso1-5.IO, started by affpv.IO) as in the floppy release.
// On a zone change, the CD MAIN.IO kills affpv.IO and eaff.IO, preloads the zone's vperso
// scripts, then restarts them (affpv only in town, Cont 1-2), but only when main.b[0x42e1]
// is set, which happens only for omodel 6000; ALIS reports 2000 on PC, so the town stays
// empty. Both tests become "ceval 1" (oimmw 1, same length); main.b[0x42e1] itself is
// left alone, since about 30 other CD paths read it. The floppy MAIN.IO starts affpv.IO
// unconditionally and has neither test.
s32 opt_passersby = 0;
static const u8 ishar3_pv_kill_le[14]  = { 0x1f,0x06,0xe1,0x42,0x14,0x2f,0x00,0x00, 0x94,0x9f,0x00,0x08,0xd0,0x3d };   // if: cfindtyp affpv
static const u8 ishar3_pv_start_le[13] = { 0x1f,0x06,0xe1,0x42,0x14,0x32,0x00,0x00, 0x1f,0x38,0x06,0xb9,0x14 };        // if: if Cont 1|2, clive affpv

static s32 find_bytes(const u8 *data, u32 data_sz, const u8 *pat, u32 len)
{
    for (u32 i = 0; i + len <= data_sz; i++)
        if (!memcmp(data + i, pat, len))
            return (s32)i;
    return -1;
}

// --no-manual-check: the copy checks ("le mot M de la ligne L de la page P").
// Seen in typhus.IO (time gates) and in the theatre in town; every script is scanned for the routine.
// Both read the word into loc.tc[0xce] (upper case, 0-terminated); after Enter they run
// the same check routine (cjsr24 to the length/repeat counter, then compare each letter
// with loc.tc[0x5e][q][i] + K, q = loc.b[0x114], until that table cell is 0), with
// K = 0x24 in typhus and 0x57 in coffre. When the script reaches that routine,
// manual_check_hook() copies the expected answer into the typed word, so the game sees
// a right answer and everything derived from the word (length, repeats) is consistent.
s32 opt_no_manual_check = 0;
static const u8 manual_chk_head[12] = { 0x07,0,0,0, 0x1e,0x00,0x00,0x08,0x1a,0x01,0x1f,0x38 };   // cjsr24 ?, cstore 0 -> loc.w[0x11a], ...
static const u8 manual_chk_tail[14] = { 0x1a,0xce,0x40,0x06,0x14,0x01,0x40,0x08,0x1a,0x01,0x1a,0x5e,0x56,0x00 };  // ... tc[0xce][i] vs tc[0x5e][q][i] + K

// Offset of the check routine in a script's code (-1 if absent); *k receives K.
static s32 manual_chk_find(const u8 *code, u32 sz, u8 *k)
{
    for (u32 t = 0; t + sizeof(manual_chk_tail) < sz; t++)
    {
        if (memcmp(code + t, manual_chk_tail, sizeof(manual_chk_tail)))
            continue;
        for (u32 h = t >= 24 ? t - 24 : 0; h + sizeof(manual_chk_head) <= t; h++)
            if (code[h] == manual_chk_head[0] && !memcmp(code + h + 4, manual_chk_head + 4, sizeof(manual_chk_head) - 4))
            {
                *k = code[t + sizeof(manual_chk_tail)];
                return (s32)h;
            }
    }
    return -1;
}

// Address of a byte-table cell, as tabchar() computes it (pre-v6 layout): `outer` holds
// the indexes the script pushes before the last one.
static u32 manual_tab_cell(u32 addr, const s16 *outer, int nouter, s16 last)
{
    u32 result = addr + last;
    s8 length = (s8)xread8(--addr);
    --addr;
    int k = 0;
    if (length < 0)
    {
        result = xread32(xread32(addr + 2)) + last;
        length &= 0xf;
        for (s32 i = 0; i < length; i++, k++)
            result += xread32((addr -= 4)) * (k < nouter ? outer[k] : 0);
    }
    else
    {
        length &= 0xf;
        for (s32 i = 0; i < length; i++, k++)
            result += (u16)xread16((addr -= 2)) * (k < nouter ? outer[k] : 0);
    }
    return result;
}

void manual_check_hook(void)
{
    // Scripts already scanned (code start and size identify them): routine offset and K.
    static struct { u32 org, sz; s32 off; u8 k; } seen[64];
    static int nseen, last = -1;
    sAlisScriptData *d = alis.script->data;
    u32 org = alis.script->pc_org;
    if (last < 0 || seen[last].org != org || seen[last].sz != d->sz)
    {
        last = -1;
        for (int i = 0; i < nseen; i++)
            if (seen[i].org == org && seen[i].sz == d->sz) { last = i; break; }
        if (last < 0)
        {
            last = nseen < 64 ? nseen++ : (int)(org % 64);
            seen[last].org = org;
            seen[last].sz = d->sz;
            seen[last].off = manual_chk_find(alis.mem + org, d->sz, &seen[last].k);
            if (seen[last].off >= 0)
                ALIS_DEBUG(EDebugInfo, "\n### manual check routine in %s at 0x%x (K 0x%x)\n", alis.script->name, seen[last].off, seen[last].k);
        }
    }
    if (seen[last].off < 0 || alis.script->pc - org != (u32)seen[last].off)
        return;
    u32 vram = alis.script->vram_org;
    s16 q = xread8(vram + 0x114);
    for (s16 i = 0; i < 13; i++)
    {
        s8 e = (s8)xread8(manual_tab_cell(vram + 0x5e, &q, 1, i));
        xwrite8(manual_tab_cell(vram + 0xce, NULL, 0, i), e ? (u8)(e + seen[last].k) : 0);
        if (!e)
            break;
    }
}

static void script_options(const char *name, u8 *data, u32 data_sz)
{
    if (alis.platform.uid != EGameIshar_3 || !alis.platform.is_little_endian)
        return;
    if (opt_skip_intro)
    {
        s32 logo = find_bytes(data, data_sz, ishar3_logo_le, sizeof(ishar3_logo_le));
        s32 param = find_bytes(data, data_sz, ishar3_param_le, sizeof(ishar3_param_le));
        s32 to = param - 0x1c;
        if (logo >= 0 && param >= 0x1c && to > logo && !memcmp(data + to, ishar3_after_intro_le, sizeof(ishar3_after_intro_le)))
        {
            s32 off = to - (logo + 4);                     // cjmp24: 16-bit LE offset, then high byte
            data[logo] = 0x0a;
            data[logo + 1] = (u8)off;
            data[logo + 2] = (u8)(off >> 8);
            data[logo + 3] = (u8)(off >> 16);
            ALIS_DEBUG(EDebugInfo, "Boot option in %s at 0x%x: intro skipped\n", name, logo);
        }
    }
    if (opt_passersby)
    {
        s32 kill = find_bytes(data, data_sz, ishar3_pv_kill_le, sizeof(ishar3_pv_kill_le));
        s32 start = find_bytes(data, data_sz, ishar3_pv_start_le, sizeof(ishar3_pv_start_le));
        if (kill >= 0 && start >= 0)
        {
            static const u8 always[4] = { 0x1f,0x02,0x01,0x00 };   // ceval oimmw 1
            memcpy(data + kill, always, sizeof(always));
            memcpy(data + start, always, sizeof(always));
            ALIS_DEBUG(EDebugInfo, "Boot option in %s at 0x%x/0x%x: town passersby on\n", name, kill, start);
        }
    }
    if (opt_lang >= 0)
        for (u32 i = 0; i + sizeof(ishar3_lang_le) <= data_sz; i++)
            if (!memcmp(data + i, ishar3_lang_le, sizeof(ishar3_lang_le)))
            {
                data[i + 2] = (u8)opt_lang;
                ALIS_DEBUG(EDebugInfo, "Boot option in %s at 0x%x: language %d\n", name, i, opt_lang);
                break;
            }
}

// --load=a3: load a save from the title screen, without clicks. One-shot jumps
// taken by alis_loop() when a script reaches a known instruction:
//  1. accueil.IO menu loop, "cstore (main.w[0x254] + 5) / 10" (hovered row): jump to the
//     "Ishar 3" action of the load submenu (clive io.IO; io.b[0x4c] = 1).
//  2. io.IO slot menu loop, "cstore main.w[0x252] / 80": set loc.b[0x8c4] to the
//     slot (rank in BACK.INF) and jump to the code run after a click on it
//     (save name from loc.tp[0x860], file read into MAIN, csend 0x12 to MAIN).
char opt_load[16] = {0};
s32 boot_load_state = 0;
static s32 boot_slot = -1;
static const u8 accueil_btn_le[14] = { 0x1e,0x38,0x20,0x54,0x02,0x56,0x00,0x05,0x5c,0x00,0x0a,0x3a,0x14,0x52 };
static const u8 accueil_ishar3_le[14] = { 0x40,0x13,0x00,0x08,0x8a,0x01,0x1e,0x00,0x01,0x2a,0x8a,0x01,0x4c,0x00 };
static const u8 io_loop_le[12] = { 0x1e,0x38,0x20,0x52,0x02,0x5c,0x00,0x50,0x3a,0x06,0xc2,0x08 };
static const u8 io_pick_le[12] = { 0x1e,0x38,0x06,0xc4,0x08,0x0c,0x60,0x08,0x3a,0x22,0x38,0x3b };

static s32 find_in_script(const u8 *pat, u32 len)
{
    sAlisScriptData *d = alis.script->data;
    for (u32 a = alis.script->pc_org; d && a + len <= alis.script->pc_org + d->sz; a++)
        if (!memcmp(alis.mem + a, pat, len))
            return (s32)a;
    return -1;
}

static s32 back_inf_slot(const char *want)
{
    char path[kPathMaxLen] = {0};
    snprintf(path, sizeof(path), "%sBACK.INF", alis.platform.path);
    FILE *f = sys_fopen(path, "rb");
    if (!f)
        return -1;
    u8 b[14 * 4] = {0};
    size_t n = fread(b, 1, sizeof(b), f);
    fclose(f);
    size_t wl = strlen(want);
    for (int i = 0; i < 4 && (size_t)(i + 1) * 14 <= n; i++)
    {
        const char *e = (const char *)b + i * 14;
        if (!strncasecmp(e, want, wl) && (e[wl] == 0 || !strncasecmp(e + wl, ".sav", 4)))
            return i;
    }
    return -1;
}

void boot_load_hook(void)
{
    const char *name = alis.script->name;
    if (boot_load_state == 1 && name && !strncasecmp(name, "accueil", 7))
    {
        static s32 btn = -2, act = -2;
        if (btn == -2)
        {
            btn = find_in_script(accueil_btn_le, sizeof(accueil_btn_le));
            act = find_in_script(accueil_ishar3_le, sizeof(accueil_ishar3_le));
            boot_slot = back_inf_slot(opt_load);
            ALIS_DEBUG(EDebugInfo, "\n### boot load: menu 0x%x, action 0x%x, slot %d\n", btn, act, boot_slot);
            if (btn < 0 || act < 0 || boot_slot < 0)
            {
                ALIS_DEBUG(EDebugWarning, "--load=%s: %s\n", opt_load, boot_slot < 0 ? "save not in BACK.INF" : "title menu not recognized");
                boot_load_state = 0;
                return;
            }
        }
        if ((s32)alis.script->pc == btn)
        {
            alis.script->pc = act;
            boot_load_state = 2;
        }
    }
    else if (boot_load_state == 2 && name && !strncasecmp(name, "io.", 3))
    {
        // io.IO has this slot loop more than once (load and save menus): act on the one it
        // is running, and take the first "after click" code that follows it.
        u32 pc = alis.script->pc, end = alis.script->pc_org + alis.script->data->sz;
        if (pc + sizeof(io_loop_le) > end || memcmp(alis.mem + pc, io_loop_le, sizeof(io_loop_le)))
            return;
        for (u32 a = pc; a + sizeof(io_pick_le) <= end && a < pc + 0x200; a++)
            if (!memcmp(alis.mem + a, io_pick_le, sizeof(io_pick_le)))
            {
                ALIS_DEBUG(EDebugInfo, "\n### boot load: slot loop 0x%x, pick 0x%x\n", pc, a);
                xwrite8(alis.script->vram_org + 0x8c4, (u8)boot_slot);
                alis.script->pc = a;
                break;
            }
        boot_load_state = 0;
    }
}

void script_fix(const char *name, u8 *data, u32 data_sz)
{
    script_options(name, data, data_sz);
    enum { kFixes = sizeof(script_fixes) / sizeof(script_fixes[0]) };
    s32 at[kFixes];
    for (u32 f = 0; f < kFixes; f++)
    {
        const sScriptFix *x = &script_fixes[f];
        at[f] = -1;
        if (x->uid != alis.platform.uid)
            continue;
        if (x->call_fix && at[x->call_fix - 1] < 0)
            continue;                                   // call target not in this script
        const u8 *old = alis.platform.is_little_endian ? x->le_old : x->be_old;
        const u8 *rep = alis.platform.is_little_endian ? x->le_new : x->be_new;
        for (u32 i = 0; i + x->len <= data_sz; i++)
        {
            if (memcmp(data + i, old, x->len))
                continue;
            memcpy(data + i, rep, x->len);              // unused tail is zero (never reached)
            if (x->call_fix)
            {
                s32 off = at[x->call_fix - 1] + x->call_to - (s32)(i + x->call_at + 2);
                u8 *p = data + i + x->call_at;
                if (alis.platform.is_little_endian)
                {
                    p[0] = (u8)off;
                    p[1] = (u8)(off >> 8);
                }
                else
                {
                    p[0] = (u8)(off >> 8);
                    p[1] = (u8)off;
                }
            }

            at[f] = (s32)i;
            ALIS_DEBUG(EDebugInfo, "Script fix in %s at 0x%x: %s\n", name, i, x->what);
            break;
        }
    }
}


// First aid without the UI (Ishar 3). frise.IO handles the "Premiers soins" icon of the Act. menu:
// after the wounded portrait is picked, its routine reads the healer from dir 0x57 and the wounded
// member from dir 0x59 (party slots 0-4), then applies the game rules: refusal when sympathy
// main.tc[0x3522][healer][wounded] < 5, once per hit (main.tc[0x35c6][w][w]), success when
// rnd(100) < skill main.tc[0x3630][healer], heal = max vitality / 10, sympathy changes.
// em_first_aid(h, w) queues a call to that routine; it runs when frise.IO is back in its idle
// main loop (where it checks for a click on the panel), as a subroutine returning there.
static volatile s32 aid_h = -1, aid_w = -1;
static const u8 aid_sig[] = { 0x4b, 0x00, 0x0d, 0x4b, 0x00, 0x07, 0x07, 0xff, 0xff, 0x00,
                              0x1f, 0x38, 0x12, 0x59, 0x4c, 0x00, 0xff, 0x3a, 0x14, 0xff, 0xff, 0x00,
                              0x1f, 0x38, 0x12, 0x59, 0x28, 0xe0, 0x16 };   // 0xff = any byte
static const u8 idle_sig[] = { 0x1f, 0x38, 0x1e, 0x56, 0x02, 0x4a, 0x00, 0x01, 0x40, 0x20, 0x8e, 0x16,
                               0x4c, 0x00, 0xfa, 0x42, 0x36, 0x3a, 0x14 };   // main loop: "left click on the panel?"
static s32 sig_find(const u8 *data, u32 sz, const u8 *sig, u32 len)
{
    for (u32 i = 0; i + len <= sz; i++)
    {
        u32 k = 0;
        while (k < len && (sig[k] == 0xff || data[i + k] == sig[k]))
            k++;
        if (k == len)
            return (s32)i;
    }
    return -1;
}
void first_aid_hook(void)
{
    static u32 org, sz;
    static s32 entry = -1, idle = -1;
    if (strncasecmp(alis.script->name, "frise", 5))
        return;
    sAlisScriptData *d = alis.script->data;
    if (org != alis.script->pc_org || sz != d->sz)
    {
        org = alis.script->pc_org;
        sz = d->sz;
        entry = sig_find(alis.mem + org, sz, aid_sig, sizeof(aid_sig));
        idle = sig_find(alis.mem + org, sz, idle_sig, sizeof(idle_sig));
        if (entry >= 0)
            entry += 10;                                // skip the menu erase and the portrait pick
        ALIS_DEBUG(EDebugInfo, "\n### first aid routine 0x%x, idle loop 0x%x\n", entry, idle);
    }
    if (entry < 0 || idle < 0)
    {
        aid_h = aid_w = -1;                             // not this release: drop the request
        return;
    }
    if (alis.script->pc - org != (u32)idle)
        return;
    xwrite8(alis.script->vram_org + 0x57, (u8)aid_h);
    xwrite8(alis.script->vram_org + 0x59, (u8)aid_w);
    xpush32(idle);                                      // cret comes back to the idle loop
    alis.script->pc = org + entry;
    aid_h = aid_w = -1;
}
s32 first_aid_pending(void) { return aid_w >= 0; }
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
// Queue a first aid by party slot (0-4); returns 0 when one is already waiting.
EMSCRIPTEN_KEEPALIVE int em_first_aid(int h, int w)
{
    if (aid_w >= 0 || h < 0 || h > 4 || w < 0 || w > 4 || h == w)
        return 0;
    aid_h = h;
    aid_w = w;
    return 1;
}
EMSCRIPTEN_KEEPALIVE int em_first_aid_pending(void) { return aid_w >= 0; }
#endif
