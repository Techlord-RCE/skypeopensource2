/*\
|*|
|*| Skype 4142 Decompression v1.0 by Sean O'Neil.
|*| Copyright (c) 2004-2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
\*/

#include "skype_basics.h"
#pragma warning(disable:4311 4312)

u8 unpack_42_CF2848[8] = {0, 0, 0, 0, '%', 's', 0, 0};

extern void * malloc_719490(void * *the_ptr, u32 bytes);
extern u32 pack_42_find_code_76A070(u32 *code_array, u32 look_for);
extern u32 pack_42_init_769FB0(u32 ctx);
extern u32 pack_42_thing1_E3B7F4[];
extern u16 pack_42_word_E3B7A0[];
extern u32 pack_42_thing2_E3B804[];
extern u16 * pack_42_word_off_E3B748[];

u8 *unpack_42_off_E3B054[11] =
{
	"",
	"tdmhkpcgwbzfvjq",
	"eaiouy",
	"nrlsx",
	"0216345789",
	"SMTBRLNPKCDHGJWFVZXQ",
	"AEIOUY",
	" ",
	"\x82\x99\xB8\xB3\xA9\x81\xBC\x9C\x85\x95\xA1\x9B\xA8\x84\xB0\x90\x80\xB6\x94\xA4\x91\xBA\x9E\x9A\xA0\xB5\xBD\xBE\xA7\x9D\x97\xA5\x9F\xAA\xB1\x83\x8C\x93\xB2\x98\xA6\xA2\xBB\x88\xAD\x96\x8F\xB4\xA3\x92\xBF\x87\xB7\x8B\x8D\xB9\x89\x8A\x8E\xAE\x86\xAC\xAB\xAF",
	"\xD7\xC3\xD0\xC5\xE5\xC4\xE3\xD1\xE6\xE7\xEC\xE4\xE8\xEF\xE9\xD9\xD8\xEB\xEA\xE2\xC2\xE0\xED\xC6\xDB\xE1\xCE\xCF\xC0\xC1\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xD2\xD3\xD4\xD5\xD6\xDA\xDC\xDD\xDE\xDF\xEE\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
	"\x2E\x2D\x2F\x5F\x21\x2B\x2C\x29\x3A\x28\x2A\x3F\x0D\x0A\x27\x26\x22\x3D\x3B\x7E\x40\x3E\x3C\x7C\x5E\x5D\x5B\x5C\x23\x60\x24\x25\x7B\x7D\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F"
};

u8 Load_Byte(u32 ctx)
{
  u32 *bytes; // eax@1
  u8 b; // al@4
  u8 **byte_ptr; // ecx@5

  bytes = *(u32 **)(ctx + 0x1FA);
  if ( *bytes )
  {
    --*bytes;
    byte_ptr = *(u8 ***)(ctx + 0x1F6);
    b = *(*byte_ptr)++;
  }
  else
  {
    ++*(u32 *)(ctx + 0x1FE);
    if ( *(u32 *)(ctx + 0x1FE) > 3 ) *(u32 *)(ctx + 0x202) = 1;
    b = 0;
  }
  return b;
}

void unpack_42_769E50(u32 ctx)
{
  u32 v2; // al@2

  for ( ; *(u32 *)(ctx + 8) <= 0x800000; *(u8 *)(ctx + 12) = (u8)v2 )
  {
    *(u32 *)(ctx + 4) = (2 * *(u32 *)(ctx + 4) | *(u8 *)(ctx + 12) & 1) << 7;
    v2 = Load_Byte(ctx);
    *(u32 *)(ctx + 8) <<= 8;
    *(u32 *)(ctx + 4) |= v2 >> 1;
  }
}

u32 pack_42_bits_769F30(u32 ctx, u8 bits)
{
  u32 result; // eax@1
  u32 v4; // edi@1

  unpack_42_769E50(ctx);
  v4 = *(u32 *)(ctx + 8) >> bits;
  result = *(u32 *)(ctx + 4) / v4;
  if ( result >> bits ) result = (1 << bits) - 1;
  *(u32 *)(ctx + 4) -= v4 * result;
  if ( (result + 1) >> bits ) *(u32 *)(ctx + 8) -= v4 * result; else *(u32 *)(ctx + 8) = v4;
  return result;
}

u32 unpack_42_769EA0(u32 ctx, u16 *word_array)
{
  u32 v2; // ecx@1
  u32 v3; // ebx@1
  u32 v6; // eax@3
  u32 result; // eax@5
  u32 v8; // ecx@5
  u32 v9; // ebp@5

  unpack_42_769E50(ctx);
  v3 = *(u32 *)(ctx + 8) >> 12;
  v2 = *(u32 *)(ctx + 4) / v3;
  if ( v2 & 0xFFFFF000 ) v2 = 0xFFF;
  v6 = 1;
  if ( word_array[1] <= v2 ) while ( word_array[++v6] <= v2 );
  v8 = word_array[v6];
  v9 = word_array[v6-1];
  result = v6 - 1;
  *(u32 *)(ctx + 4) -= v3 * v9;
  if ( v8 & 0xFFFFF000 ) *(u32 *)(ctx + 8) -= v3 * v9;
  else *(u32 *)(ctx + 8) = v3 * (v8 - v9);
  return result;
}

u32 unpack_42_769F30(u32 ctx, u32 bits)
{
  u32 result; // eax@1
  u32 v4; // edi@1

  unpack_42_769E50(ctx);
  v4 = *(u32 *)(ctx + 8) >> bits;
  result = *(u32 *)(ctx + 4) / v4;
  if ( (u32)result >> bits ) result = (1 << bits) - 1;
  *(u32 *)(ctx + 4) -= v4 * result;
  if ( (u32)(result + 1) >> bits ) *(u32 *)(ctx + 8) -= v4 * result;
  else *(u32 *)(ctx + 8) = v4;
  return result;
}

u32 unpack_42_dword_76ADE0(u32 ctx, u32 *word_ptr, u32 a3)
{
  u32 result; // eax@1
  u32 v5;
  u32 v6; // esi@2
  u32 v7; // eax@4
  u32 v8; // edi@4
  u32 v9; // ebp@7
  u32 v10; // edi@7
  u32 v11; // esi@7
  u32 v15; // ebx@11
  u32 v16; // edx@11

  result = unpack_42_769EA0(ctx, (u16 *)word_ptr[3]);
  if ( result >= ((u32)1 << word_ptr[1]) )
  {
    v6 = result - word_ptr[2];
    if ( v6 >= word_ptr[0] )
    {
      if ( a3 || (v7 = unpack_42_dword_76ADE0(ctx, word_ptr, 1), v8 = word_ptr[0], v7 > 32 - v8) )
      {
        *(u32 *)(ctx + 0x202) = 1;
        return 0;
      }
      v6 = v8 + v7;
    }
    v11 = v6 - 1;
    v9 = 1 << v11;
    v10 = 0;
    if ( v6 > 1 )
    {
      v5 = 16;
      do
      {
		v15 = __min ( v11 - v10, 16 );
        v16 = (u16)unpack_42_769F30(ctx, v15) << (u8)v10;
        v10 += v15;
        v9 += v16;
      }
      while ( v10 < v11 );
    }
    result = v9;
  }
  return result;
}

u32 unpack_42_76AEA0(u32 a1, u32 ctx)
{
  u32 v2; // eax@1
  u32 result; // eax@2

  v2 = *(u32 *)(ctx + 0x20E);
  if ( *(u32 *)v2 >= a1 )
  {
    *(u32 *)v2 -= a1;
    result = 1;
  }
  else
  {
    *(u32 *)(ctx + 0x202) = 1;
    result = 0;
  }
  return result;
}

void unpack_42_from_9944D0(u32 *where_from)
{
  u32 v3, *where_to; // eax@2

  v3 = where_from[65] + 1;
  if ( v3 > where_from[66] )
  {
    v3 = where_from[65] + 32;
    where_from[66] = v3;
    if ( where_from[64] == (u32)where_from ) where_from[64] = 0;
    where_to = (u32 *)where_from[64];
    malloc_719490((void * *)&where_to, 8 * v3);
    if ( !where_from[64] ) memcpy(where_to, where_from, 8 * where_from[65]);
    where_from[64] = (u32)where_to;
  }
}

u32 *unpack_42_from_951460(u32 *where_from)
{
  u32 *result; // eax@3

  if ( where_from[65] >= where_from[66] ) unpack_42_from_9944D0(where_from);
  result = (u32 *) (where_from[64] + 8 * where_from[65]);
  where_from[65]++;
  if ( result )
  {
    result[0] = 0;
    result[1] = 0;
  }
  return result;
}

void unpack_42_inc_85BEE0(u32 increment, u32 ctx)
{
  u32 v3; // eax@1
  u32 v4; // eax@2
  u32 v5; // esi@4
  u32 v7; // [sp+0h] [bp-4h]@1

  v3 = increment + *(u32 *)(ctx + 0x204);
  if ( (u32)v3 > *(u32 *)(ctx + 0x208) )
  {
    v4 = v3 + 0x1FF;
    *(u32 *)(ctx + 0x208) = v4;
    if (*(u32 *)(ctx + 0x200) == ctx) *(u32 *)(ctx + 0x200) = 0;
    v7 = *(u32 *)(ctx + 0x200);
    malloc_719490((void * *)&v7, v4);
    v5 = v7;
    if ( !*(u32 *)(ctx + 0x200) ) memcpy((void *)v7, (void *)ctx, *(u32 *)(ctx + 0x204));
    *(u32 *)(ctx + 0x200) = v5;
  }
}

u32 unpack_42_byte_85BDC0(u32 ctx, u32 the_byte)
{
  u32 str; // eax@3
  u32 v4; // ecx@3
  u32 v5; // eax@3

  if ( *(u32 *)(ctx + 0x204) >= *(u32 *)(ctx + 0x208) ) unpack_42_inc_85BEE0(1, ctx);
  v4 = *(u32 *)(ctx + 0x204);
  v5 = *(u32 *)(ctx + 0x200);
  str = v4 + v5;
  *(u32 *)(ctx + 0x204) = v4 + 1;
  if (str) *(u8 *)str = *(u8 *)the_byte;
  return str;
}

void unpack_42_inc_76AD90(u32 ctx, u32 increment)
{
  u32 v2; // ecx@1

  v2 = *(u32 *)(ctx + 0x1FA);
  *(u32 *)(ctx + 0x206) += increment;
  if ( *(u32 *)v2 < increment )
  {
    *(u32 *)(ctx + 0x1FE) += increment - *(u32 *)v2;
    **(u32 **)(ctx + 0x1F6) += *(u32 *)v2 - increment;
    **(u32 **)(ctx + 0x1FA) = 0;
    if ( *(u32 *)(ctx + 0x1FE) > 3 ) *(u32 *)(ctx + 0x202) = 1;
  }
  else
  {
    *(u32 *)v2 -= increment;
  }
}

u32 *unpack_41_dword_715D70(u32 *a1, u32 a3)
{
  u32 v3; // eax@1
  u32 v6; // edi@3
  u32 *result; // eax@6
  u32 *v8; // eax@6

  v3 = a1[2];
  if ( v3 >= a1[1] )
  {
    if ( v3 >= 8 ) v6 = (((v3 >= 32) - 1) & -24) + 32; else v6 = 4;
    malloc_719490((void * *)a1, 16 * (v6 + v3));
    a1[1] += v6;
  }
  memcpy((void *) (16 * a3 + a1[0] + 16), (void *) (16 * a3 + a1[0]), 16 * (a1[2] - a3));
  v8 = (u32 *)a1[0];
  ++a1[2];
  result = v8 + 4 * a3;
  if ( result )
  {
    result[0] = 0;
    result[1] = 0;
    result[2] = 0;
  }
  return result;
}

u32 *unpack_42_dword_714540(u32 *a1, u32 a3, u32 a4)
{
  u32 *result; // eax@1

  result = unpack_41_dword_715D70(a1 + 1, a1[3]);
  result[0] = 0;
  result[1] = a3;
  result[2] = a4;
  return result;
}

u32 *unpack_42_5_7147B0(u32 * a1, u32 a3)
{
  u32 *the_thing; // eax@1
  u32 *v4; // esi@1
  u32 *v5; // eax@1

  v5 = unpack_41_dword_715D70(a1 + 1, a1[3]);
  v4 = v5;
  v5[0] = 5;
  v5[1] = a3;
  the_thing = (u32 *)malloc(16);
  if ( the_thing )
  {
    the_thing[0] = -1;
    the_thing[1] = 0;
    the_thing[2] = 0;
    the_thing[3] = 0;
    v4[2] = (u32)the_thing;
  }
  else
  {
    the_thing = 0;
    v4[2] = 0;
  }
  return the_thing;
}

u32 *unpack_42_3_7145D0(u32 *a1, const u8 *a2, u32 skype_id, u32 a5)
{
  u32 *v5; // eax@1
  u32 *v8; // esi@1
  u8 *v9; // eax@4

  v5 = unpack_41_dword_715D70(a1 + 1, *(a1 + 3));
  v8 = v5;
  v5[0] = 3;
  v5[1] = skype_id;
  if ( !a2 ) a2 = unpack_42_CF2848;
  v5[3] = a5 + 1;
  if ( a5 )
  {
    v9 = memchr(a2, 0, a5);
    if ( v9 ) *(v8 + 3) = (u32) (v9 - a2 + 1);
  }
  v8[2] = (u32)malloc(v8[3]);
  memcpy((void *)v8[2], a2, v8[3]);
  *(u8 *)(*(v8 + 3) + *(v8 + 2) - 1) = 0;
  return v8;
}

void unpack_42_6_7393A0(u32 *context, u32 a2)
{
  u32 *v8; // ebp@1
  u32 *v9; // eax@4
  void *v10; // esi@14
  u32 *v11; // eax@15
  void *v13; // [sp+8h] [bp-4h]@14

  v8 = context + 33;
  if ( a2 != *(context + 33) )
  {
    if ( (u32)a2 > 32 )
    {
      if ( (u32)a2 > 0x3FFFFFFF ) __asm int 3;
      *(context + 34) = a2;
      if ( *(context + 32) == (u32)context ) *(context + 32) = 0;
      v13 = (void *)*(context + 32);
      malloc_719490(&v13, 4 * a2);
      v10 = v13;
      if ( !*(context + 32) )
      {
        v11 = &a2;
        if ( a2 >= *v8 ) v11 = (u32 *)(context + 33);
        memcpy(v13, context, 4 * *v11);
      }
      *(context + 32) = (u32)v10;
      *v8 = a2;
    }
    else
    {
      if ( *(context + 32) != (u32)context )
      {
        v9 = &a2;
        if ( a2 >= *v8 ) v9 = (u32 *)(context + 33);
        memcpy(context, (void *)*(context + 32), 4 * *v9);
        if ( *(context + 32) ) free((void *)*(context + 32));
        *(context + 32) = (u32)context;
      }
      *v8 = a2;
      *(context + 34) = 32;
    }
  }
}

void unpack_42_end_context_720CA0(u32 *context)
{
  if ( context[32] != (u32)context )
  {
    if ( context[32] ) free((void *)context[32]);
    context[32] = (u32)context;
  }
  context[33] = 0;
  context[34] = 32;
}

u32 *unpack_42_6_714690(u32 *a1, u32 dwords, u32 skype_id, u32 a4)
{
  u32 *v6; // eax@1
  u32 *v8; // esi@1
  u32 v9; // ecx@2
  u32 v13; // qax@1

  v13 = 4 * dwords;
  if (v13 < dwords) __asm int 3;
  v8 = unpack_41_dword_715D70(a1 + 1, *(a1 + 3));
  v8[0] = 6;
  v8[1] = skype_id;
  v8[3] = 4 * dwords;
  v6 = (u32 *)malloc(v13);
  v8[2] = (u32)v6;
  if ( dwords )
  {
    v9 = a4 - (u32)v6;
    do
    {
      *v6 = *(u32 *)((u8 *)v6 + v9);
      ++v6;
      --dwords;
    }
    while ( dwords );
  }
  return v8;
}

void unpack_42_list_76B1B0(u32 ctx, u32 *into_list, u32 a3)
{
  u32 *v4; // eax@3
  u32 *v5; // esi@5
  u32 *v6; // ecx@10
  u32 v7; // ebx@10
  u32 v8; // eax@11
  u32 v9; // edi@14
  u32 v10; // ebx@16
  u32 v12; // eax@21
  u16 **v13; // edi@25
  u32 v14; // eax@26
  u32 v15; // eax@27
  u32 v17; // esi@27
  u8 v18; // bl@29
  u32 v20; // eax@38
  u32 v21; // ebx@38
  u32 v22; // esi@41
  u32 increment; // esi@45
  u32 v25; // eax@5
  u32 v26; // eax@7
  u32 v33; // ebx@17
  u32 v34; // eax@23
  u32 v35; // ST08_4@24
  u32 *v36; // eax@24
  u8 *v39; // ecx@29
  u32 v40; // edi@43
  u32 v41; // eax@45
  u32 *v42; // eax@48
  u32 *v44; // eax@48
  u32 v45; // ecx@48
  u32 v46; // eax@52
  u32 v50; // [sp+28h] [bp-9Ch]@3
  u32 v52; // [sp+24h] [bp-A0h]@5
  u8 skype_id[5]; // [sp+17h] [bp-ADh]@8
  u32 context[37]; // [sp+2Ch] [bp-98h]@41

  if ( a3 >= *(u32 *)(ctx + 0x1F2) ) goto LABEL_2;
  v50 = 2;
  v4 = &v50;
  if ( a3 <= 2 ) v4 = &a3;
  v25 = *v4;
  v5 = (u32 *) (ctx + 18 + 160 * v25);
  v52 = 0;
  if ( a3 )
  {
    if ( v5[39] )
    {
      v26 = unpack_42_dword_76ADE0(ctx, pack_42_thing1_E3B7F4, 0);
      v52 = v26;
      if (v26 > v5[39])
      {
LABEL_2:
        *(u32 *)(ctx + 0x202) = 1;
        return;
      }
    }
  }
  v5[39] = 0;
  *(u32 *)(skype_id+1) = 0;
  if ( *(u32 *)(ctx + 0x202) == 0 )
  {
    while ( 1 )
    {
      if ( !v52 )
      {
        v8 = unpack_42_769EA0(ctx, pack_42_word_E3B7A0);
        if ( !v8 ) return;
        if ( (u32)v8 > 6 )
        {
          v10 = v8 - 6;
          v9 = unpack_42_dword_76ADE0(ctx, pack_42_thing1_E3B7F4, 0);
          if ( v10 )
          {
            v33 = v5[v10];
            memcpy(v5 + 1, v5, 4 * v10);
            v5[0] = v33;
          }
        }
        else
        {
          if ( v8 != 6 ) v9 = v8 - 1;
          else v9 = unpack_42_dword_76ADE0(ctx, pack_42_thing1_E3B7F4, 0) + 5;
        }
        v7 = v5[0];
        *(u32 *)(skype_id+1) += v9;
      }
      else
      {
        v7 = v5[v5[39]*2+8];
        --v52;
        *(u32 *)(skype_id+1) = v5[v5[39]*2+7];
        pack_42_find_code_76A070(v5, v7);
      }
      if ( v5[39] < 16 )
      {
        v6 = *(u32 **)(skype_id+1);
        v5[v5[39]*2+7] = *(u32 *)(skype_id+1);
        v5[8+2*v5[39]++] = v7;
      }
      v12 = *(u32 *)(ctx + 0x20E);
      if ( *(u32 *)v12 < 16 ) goto LABEL_2;
      *(u32 *)v12 -= 16;
      switch ( v7 )
      {
        case 0:
          v34 = unpack_42_dword_76ADE0(ctx, pack_42_thing2_E3B804, 0);
          unpack_42_dword_714540(into_list, *(u32 *)(skype_id+1), v34);
          goto LABEL_50;
        case 5:
          v35 = a3 + 1;
          v36 = unpack_42_5_7147B0(into_list, *(u32 *)(skype_id+1));
          unpack_42_list_76B1B0(ctx, v36, v35);
          goto LABEL_50;
        case 3:
          v13 = pack_42_word_off_E3B748;
          v50 = 0;
          while ( 2 )
          {
            v14 = *(u32 *)(ctx + 0x20E);
            if ( *(u32 *)v14 < 1 )
            {
LABEL_39:
              *(u32 *)(ctx + 0x202) = 1;
              goto LABEL_50;
            }
            --*(u32 *)v14;
            v17 = unpack_42_769EA0(ctx, v13[1]);
            v13 = pack_42_word_off_E3B748 + 2 * v17;
            v15 = 0;
            if ( (*v13)[1] != 0x1000 ) v15 = unpack_42_769EA0(ctx, v13[0]);
            v39 = unpack_42_off_E3B054[v17];
            v18 = v39[v15];
            skype_id[0] = v39[v15];
            if ( *(u32 *)(ctx + 0x202) != 0 )
            {
              v18 = 0;
              skype_id[0] = 0;
            }
            if ( (u32)v50 >= *(u32 *)(ctx + 0x522) ) unpack_42_byte_85BDC0(ctx + 0x31E, (u32)skype_id);
            else *(u8 *)(v50 + *(u32 *)(ctx + 0x51E)) = v18;
            if ( !v18 ) break;
            v50++;
          }
          if ( !*(u32 *)(ctx + 0x202) ) unpack_42_3_7145D0(into_list, *(const u8 **)(ctx + 0x51E), *(u32 *)(skype_id+1), 0x7FFFFFFF);
          goto LABEL_49;
        case 6:
          v20 = unpack_42_dword_76ADE0(ctx, pack_42_thing2_E3B804, 0);
          v21 = v20;
          if ( (u32)v20 > 0x3FFFFFFF ) goto LABEL_39;
          if ( !unpack_42_76AEA0(4 * v20, ctx) ) goto LABEL_50;
          v22 = 0;
          context[32] = (u32)context;
          context[33] = 0;
          context[34] = 32;
          unpack_42_6_7393A0(context, v21);
          if ( !v21 ) goto LABEL_44;
          break;
        case 4:
          v41 = unpack_42_dword_76ADE0(ctx, pack_42_thing2_E3B804, 0);
          increment = v41;
          unpack_42_76AEA0(v41, ctx);
          goto LABEL_46;
        case 1:
          v46 = unpack_42_dword_76ADE0(ctx, pack_42_thing2_E3B804, 0);
          increment = v46;
          if ( v46 > 8 ) *(u32 *)(ctx + 0x202) = 1;
LABEL_46:
          if ( increment < -1 ) goto LABEL_47;
          goto LABEL_49;
        case 2:
          increment = 6;
LABEL_47:
          if ( !*(u32 *)(ctx + 0x202) )
          {
            v42 = unpack_42_from_951460((u32 *)(ctx + 0x212));
            v42[0] = (u32)into_list;
            v42[1] = into_list[3];
            v44 = unpack_41_dword_715D70(into_list + 1, into_list[3]);
            v45 = *(u32 *)(skype_id+1);
            v44[0] = 2;
            v44[1] = v45;
            v44[2] = increment;
            v44[3] = v7;
            unpack_42_inc_76AD90(ctx, increment);
          }
          goto LABEL_49;
        default:
          goto LABEL_50;
      }
      do
      {
        if ( *(u32 *)(ctx + 0x202) )
        {
          unpack_42_end_context_720CA0(context);
          return;
        }
        v40 = context[32] + 4 * v22++;
        *(u32 *)v40 = unpack_42_dword_76ADE0(ctx, pack_42_thing2_E3B804, 0);
      }
      while ( v22 < v21 );
LABEL_44:
      unpack_42_6_714690(into_list, v21, *(u32 *)(skype_id+1), context[32]);
      unpack_42_end_context_720CA0(context);
LABEL_49:
LABEL_50:
      if ( *(u32 *)(ctx + 0x202) ) return;
    }
  }
}

void unpack_42_2_715200(u32 *the_thing, u32 a2, u32 a3)
{
  if ( the_thing[0] == 3 || the_thing[0] == 4 || the_thing[0] == 6 )
  {
    if ( the_thing[2] ) free((void *)the_thing[2]);
  }
  else
  {
    if ( the_thing[0] == 5 )
    {
      if ( the_thing[2] ) Load_Byte(the_thing[2]);
    }
  }
  the_thing[0] = 2;
  the_thing[2] = a2;
  the_thing[3] = a3;
}

void unpack_42_4_715250(u32 bytes, u32 *the_thing, u32 blob)
{
  if ( the_thing[0] == 3 || the_thing[0] == 4 || the_thing[0] == 6 )
  {
    if ( the_thing[2] ) free((void *)the_thing[2]);
  }
  else
  {
    if ( the_thing[0] == 5 )
    {
      if ( the_thing[2] ) Load_Byte(the_thing[2]);
    }
  }
  the_thing[0] = 4;
  the_thing[2] = (u32)malloc(bytes);
  the_thing[3] = bytes;
  memcpy((void *)the_thing[2], (void *)blob, bytes);
}

void unpack_42_1_7151B0(u32 *the_thing, u32 a2, u32 a3)
{
  if ( the_thing[0] == 3 || the_thing[0] == 4 || the_thing[0] == 6 )
  {
    if ( the_thing[2] ) free((void *)the_thing[2]);
  }
  else
  {
    if ( the_thing[0] == 5 )
    {
      if ( the_thing[2] ) Load_Byte(the_thing[2]);
    }
  }
  the_thing[0] = 1;
  the_thing[2] = a2;
  the_thing[3] = a3;
}

u32 unpack_42_76AEC0(u32 *list_size, u32 ctx, u32 *into_list)
{
  u32 v3;
  u32 t2;
  u32 t3;
  u32 v7; // eax@5
  u32 v8; // eax@9
  u32 v9; // eax@13
  u32 v10; // edx@13
  u32 *v12; // ecx@18
  u32 *the_thing; // esi@19
  u32 v17; // eax@37
  u32 v18; // eax@41
  u8 v19; // al@13
  u32 *v22; // ecx@18
  u8 *v24; // ecx@27
  u64 the_qword; // [sp+14h] [bp-8h]@28

  *(u32 *)(ctx + 0x206) = 0;
  *(u32 *)(ctx + 0x202) = 0;
  *(u32 *)(ctx + 0x1FE) = 0;
  *(u32 *)(ctx + 0x20A) = -1;
  *(u32 *)(ctx + 0x20E) = (u32)list_size;
  if ( Load_Byte(ctx) != 0x42 ) return 0;
  v7 = *(u32 *)(ctx + 0x51E);
  if ( v7 != ctx + 0x31E )
  {
    if ( v7 ) free(*(void * *)(ctx + 0x51E));
    *(u32 *)(ctx + 0x51E) = ctx + 0x31E;
  }
  *(u32 *)(ctx + 0x522) = 0;
  *(u32 *)(ctx + 0x526) = 0x200;
  v8 = *(u32 *)(ctx + 0x312);
  if ( v8 != ctx + 0x212 )
  {
    if ( v8 ) free(*(void * *)(ctx + 0x312));
    *(u32 *)(ctx + 0x312) = ctx + 0x212;
  }
  *(u32 *)(ctx + 0x316) = 0;
  *(u32 *)(ctx + 0x31A) = 32;
  pack_42_init_769FB0(ctx);
  v19 = Load_Byte(ctx);
  *(u8 *)(ctx + 12) = v19;
  *(u32 *)(ctx + 4) = (u32)v19 >> 1;
  *(u32 *)(ctx + 8) = 128;
  unpack_42_list_76B1B0(ctx, into_list, 0);
  *(u32 *)(ctx + 8) >>= 1;
  unpack_42_769E50(ctx);
  v9 = *(u32 *)(ctx + 0x1FE);
  if ( v9 <= 3 )
  {
    **(u32 **)(ctx + 0x1F6) += v9 - 3;
    v10 = 3 - *(u32 *)(ctx + 0x1FE);
    **(u32 **)(ctx + 0x1FA) += v10;
    *(u32 *)(ctx + 0x1FE) = 0;
  }
  else
  {
    *(u32 *)(ctx + 0x202) = 1;
  }
  v3 = 0;
  if ( *(u32 *)(ctx + 0x316) != 0 )
  {
    while ( 1 )
    {
      if ( *(u32 **)(ctx + 0x202) != 0 ) goto LABEL_37;
      v22 = *(u32 **)(ctx + 0x312) + 2 * v3;
      v12 = (u32 *)v22[0];
      if ( v22[1] >= v12[3] )
      {
        the_thing = 0;
      }
      else
      {
        the_thing = (u32 *)v12[1] + 4 * v22[1];
      }
	  t2 = the_thing[2];
	  t3 = the_thing[3];
      if ( t2 > *(u32 *)(ctx + 0x206) )
      {
        *(u32 *)(ctx + 0x202) = 1;
        goto LABEL_37;
      }
      if ( t3 == 1 ) break;
      if ( t3 == 2 )
      {
        v24 = **(u8 ***)(ctx + 0x1F6);
        unpack_42_2_715200(the_thing, v24[0]+((v24[1]+((v24[2]+(v24[3]<<8))<<8))<<8),v24[4]+(v24[5]<<8));
      }
      else
      {
        if ( t3 == 4 )
        {
          unpack_42_4_715250(t2, the_thing, **(u32 **)(ctx + 0x1F6));
LABEL_33:
          goto LABEL_34;
        }
		__asm int 3;
      }
LABEL_34:
      **(u32 **)(ctx + 0x1F6) += t2;
      *(u32 *)(ctx + 0x206) -= t2;
      if ( ++v3 >= *(u32 *)(ctx + 0x316) ) goto LABEL_37;
    }
	the_qword = 0;
    if ( t2 )
    {
      memcpy ((void *)&the_qword, **(u8 ***)(ctx + 0x1F6), t2);
    }
    unpack_42_1_7151B0(the_thing, (u32)the_qword, (u32)(the_qword>>32));
    goto LABEL_33;
  }
LABEL_37:
  v17 = *(u32 *)(ctx + 0x312);
  if ( v17 != ctx + 0x212 )
  {
    if ( v17 != 0 ) free(*(void * *)(ctx + 0x312));
    *(u32 *)(ctx + 0x312) = ctx + 0x212;
  }
  *(u32 **)(ctx + 0x316) = 0;
  *(u32 *)(ctx + 0x31A) = 32;
  v18 = *(u32 *)(ctx + 0x51E);
  if ( v18 != ctx + 0x31E )
  {
    if ( v18 != 0 ) free(*(void * *)(ctx + 0x51E));
    *(u32 *)(ctx + 0x51E) = ctx + 0x31E;
  }
  *(u32 *)(ctx + 0x522) = 0;
  *(u32 *)(ctx + 0x526) = 0x200;
  return *(u32 *)(ctx + 0x202) == 0;
}

u32 unpack_41_dword_896070(u32 *into_dword, u8 **packed_dword, u32 *packed_bytes)
{
  u32 v5; // esi@1
  u8 v8; // dl@3

  *into_dword = 0;
  v5 = 0;
  while ( 1 )
  {
    if ( *packed_bytes-- == 0 ) break;
    v8 = *(*packed_dword)++;
    *into_dword |= (v8 & 127) << v5;
    v5 += 7;
    if ( v8 <= 127 ) return 1;
  }
  return 0;
}

u32 * unpack_41_0_715D70(u32 *the_thing, u32 the_dword)
{
  u32 v2; // eax@1
  u32 v5; // edi@3
  u32 * new_thing; // eax@6
  u32 * v7; // eax@6

  v2 = the_thing[2];
  if ( v2 >= the_thing[1] )
  {
    if ( v2 >= 8 ) v5 = (((v2 >= 32) - 1) & -24) + 32; else v5 = 4;
    malloc_719490((void * *)the_thing, 16 * (v5 + v2));
    *(the_thing + 1) += v5;
  }
  memcpy((void *)(16 * the_dword + *the_thing + 16), (void *)(16 * the_dword + *the_thing), 16 * (*(the_thing + 2) - the_dword));
  v7 = (u32 *)*the_thing;
  ++*(the_thing + 2);
  new_thing = v7 + 4 * the_dword;
  if ( new_thing )
  {
    new_thing[0] = 0;
    new_thing[1] = 0;
    new_thing[2] = 0;
    new_thing[3] = 0;
  }
  return new_thing;
}

u32 unpack_42_ctx_init_76ACD0(u32 max_depth, u32 ctx, u32 packed_blob, u32 packed_bytes)
{
  *(u32 *)(ctx + 0x1F2) = max_depth;
  *(u32 *)(ctx + 0x1FA) = packed_bytes;
  *(u32 *)(ctx + 0x1F6) = packed_blob;
  *(u32 *)(ctx + 0x312) = ctx + 0x212;
  *(u32 *)(ctx + 0x316) = 0;
  *(u32 *)(ctx + 0x31A) = 32;
  *(u32 *)(ctx + 0x51E) = ctx + 0x31E;
  *(u32 *)(ctx + 0x522) = 0;
  *(u32 *)(ctx + 0x526) = 0x200;
  return ctx;
}

void unpack_42_ctx_end_714D90(u32 ctx)
{
  if ( *(u32 *)(ctx + 0x51E) != ctx + 0x31E )
  {
    if ( *(u32 *)(ctx + 0x51E) ) free(*(void * *)(ctx + 0x51E));
    *(u32 *)(ctx + 0x51E) = ctx + 0x31E;
  }
  *(u32 *)(ctx + 0x522) = 0;
  *(u32 *)(ctx + 0x526) = 0x200;
  if ( *(void * *)(ctx + 0x312) != (void *)(ctx + 0x212) )
  {
    if ( *(void * *)(ctx + 0x312) ) free(*(void * *)(ctx + 0x312));
    *(u32 *)(ctx + 0x312) = ctx + 0x212;
  }
  *(u32 *)(ctx + 0x316) = 0;
  *(u32 *)(ctx + 0x31A) = 32;
  *(u32 *)ctx = 0;
}

u32 unpack_4142(u32 *into_list, u8 **packed_blob, u32 *packed_bytes, u8 *pack_42, u32 max_depth, u32 *list_size);

u32 unpack_41_715680(u8 **packed_blob, u32 *the_thing, u32 *packed_bytes, u32 max_depth, u32 *list_size)
{
	u32 *m; // ebp@3
	u32 *v9; // ebx@8
	u8 *v12; // eax@16
	u32 v15; // ecx@17
	u32 v25; // ebx@35
	u32 tt;
	u32 *n;
	
	--*packed_bytes;
	if (*packed_bytes == 0) return 0;
	the_thing[0] = *(*packed_blob)++;
	the_thing[1] = 0;
	the_thing[2] = 0;
	the_thing[3] = 0;
	m = the_thing + 2;
	n = the_thing + 3;
	if (!unpack_41_dword_896070(the_thing + 1, packed_blob, packed_bytes)) return 0;
	switch (*the_thing)
	{
	case 0:
		return unpack_41_dword_896070(the_thing + 2, packed_blob, packed_bytes);
	case 1:
		v9 = packed_bytes;
		if (*packed_bytes < 8) return 0;
		//dword(m,0) = _bswap32(dword(*packed_blob,1));
		//dword(m,1) = _bswap32(dword(*packed_blob,0));
		dword(m,0) = _bswap32(dword(*packed_blob,0));
		dword(n,0) = _bswap32(dword(*packed_blob,4));
		*packed_blob += 8;
		*v9 -= 8;
		return 1;
	case 2:
		if (*packed_bytes < 6) return 0;
		the_thing[2] = _bswap32(dword(*packed_blob,0));
		the_thing[3] = ntohs(word(*packed_blob,4));
		*packed_blob += 6;
		*packed_bytes -= 6;
		return 1;
	case 3:
		v12 = memchr(*packed_blob, 0, *packed_bytes);
		if (!v12 || (v15 = (u32)(v12 - *packed_blob + 1), the_thing[3] = (u32)(v12 - *packed_blob + 1), *list_size < v15)) return 0;
		*list_size -= v15;
		memcpy((void *)(*m = (u32)malloc(the_thing[3])), *packed_blob, the_thing[3]);
		*packed_blob += the_thing[3];
		*packed_bytes -= the_thing[3];
		return 1;
	case 4:
		if (!unpack_41_dword_896070(the_thing+3, packed_blob, packed_bytes) || (*packed_bytes < the_thing[3]) || (*list_size < the_thing[3])) return 0;
		*list_size -= the_thing[3];
		memcpy((void *)(*m = (u32)malloc(the_thing[3])), *packed_blob, the_thing[3]);
		*packed_blob += the_thing[3];
		*packed_bytes -= the_thing[3];
		return 1;
	default:
		if (*the_thing != 5)
		{
			if ((*the_thing != 6)
				|| !unpack_41_dword_896070(&tt, packed_blob, packed_bytes)
				|| (tt > *packed_bytes)
				|| (tt >= 128*1024*1024)
				|| (*list_size < (the_thing[3] = 4*tt)))
				return 0;
			*list_size -= 4*tt;
			*m = (u32) malloc(the_thing[3]);
			if (!tt) return 1;
			for (v25 = 0; v25 < tt; v25++)
			{
				if (!unpack_41_dword_896070(&dword(*m,v25*4), packed_blob, packed_bytes)) return 0;
			}
			return 1;
		}
		if (*list_size < 16) return 0;
		*list_size -= 16;
		if (*m = (u32) malloc (16))
		{
			dword(*m,0) = -1;
			dword(*m,4) = 0;
			dword(*m,8) = 0;
			dword(*m,12) = 0;
		}
		return unpack_4142((u32 *)*m, packed_blob, packed_bytes, 0, max_depth - 1, list_size);
	}
}

u32 unpack_4142(u32 *into_list, u8 **packed_blob, u32 *packed_bytes, u8 *pack_42, u32 max_depth, u32 *list_size)
{
  u32 v13;
  u32 length;
  u32 *length_ptr;
  u32 max_length;
  u32 *the_thing;
  u32 v22;
  u32 n;
  u32 ctx[333];

  if ( pack_42 ) *pack_42 = 0;
  if ( !max_depth || !*packed_bytes ) return 0;
  if ( **packed_blob == 0x41 )
  {
    --*packed_bytes;
    ++*packed_blob;
    if ( unpack_41_dword_896070(&length, packed_blob, packed_bytes) )
    {
      v22 = 100;
      length_ptr = (u32 *)&v22;
      if ( length <= 100 ) length_ptr = &length;
      max_length = into_list[3] + *length_ptr;
      if ( into_list[2] < max_length )
      {
        into_list[2] = max_length;
        malloc_719490((void **)into_list + 1, 16 * max_length);
      }
      n = 0;
      if ( !length ) return 1;
      while ( *list_size >= 16 )
      {
        *list_size -= 16;
        the_thing = unpack_41_0_715D70(into_list+1, into_list[3]);
		if ( !unpack_41_715680(packed_blob, the_thing, packed_bytes, max_depth, list_size)) break;
        if ( ++n >= length ) return 1;
      }
    }
    return 0;
  }
  if ( pack_42 ) *pack_42 = 1;
  unpack_42_ctx_init_76ACD0(max_depth, (u32)ctx, (u32)packed_blob, (u32)packed_bytes);
  v13 = unpack_42_76AEC0(list_size, (u32)ctx, into_list) != 0;
  unpack_42_ctx_end_714D90((u32)ctx);
  return v13;
}
