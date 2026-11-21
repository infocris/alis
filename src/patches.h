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
// Script bug fixes applied at load (patches.c).

#pragma once

#include "config.h"

void script_fix(const char *name, u8 *data, u32 data_sz);
extern s32 opt_lang;
extern s32 opt_skip_intro;
extern s32 opt_passersby;        // Ishar 3: --passersby starts the town passersby (CD release)
extern s32 opt_no_manual_check;   // Ishar 3: --no-manual-check accepts any answer at the gates
void manual_check_hook(void);     // runs before each instruction while --no-manual-check is on
extern char opt_load[16];      // Ishar 3: --load=a3 loads that save from the title screen
extern s32 boot_load_state;    // 1 = waiting for the title menu, 2 = waiting for the slot menu
void boot_load_hook(void);     // Ishar 3: --skip-intro goes straight to the title screen           // Ishar 3: --lang=fr|en|de|es skips the flag screen
s32 first_aid_pending(void);     // Ishar 3: em_first_aid() request waiting for frise.IO
void first_aid_hook(void);       // runs before each instruction while a request waits
