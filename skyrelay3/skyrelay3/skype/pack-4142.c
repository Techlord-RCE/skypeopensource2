/*\
|*|
|*| Skype 4142 Compression v1.0 by Sean O'Neil.
|*| Copyright (c) 2004-2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
\*/

#include "skype_basics.h"
#pragma warning(disable:4311 4312)

u8 pack_42_byte_E3B220[256] =
{
     0,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
     7,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
     4, 4, 4, 4, 4, 4, 4, 4, 4, 4,10,10,10,10,10,10,
    10, 6, 5, 5, 5, 6, 5, 5, 5, 6, 5, 5, 5, 5, 5, 6,
     5, 5, 5, 5, 5, 6, 5, 5, 5, 6, 5,10,10,10,10,10,
    10, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 3, 1, 3, 2,
     1, 1, 3, 3, 1, 2, 1, 1, 3, 2, 1,10,10,10,10,10,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
};
u8 pack_42_byte_E3B320[256] =
{
     0,34,35,36,37,38,39,40,41,42,13,43,44,12,45,46,
    47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,
     0, 4,16,28,30,31,15,14, 9, 7,10, 5, 6, 1, 0, 2,
     0, 2, 1, 4, 5, 6, 3, 7, 8, 9, 8,18,22,17,21,11,
    20, 0, 3, 9,10, 1,15,12,11, 2,13, 8, 5, 1, 6, 3,
     7,19, 4, 0, 2, 4,16,14,18, 5,17,26,27,25,24, 3,
    29, 1, 9, 6, 1, 0,11, 7, 3, 2,13, 4, 2, 2, 0, 3,
     5,14, 1, 3, 0, 4,12, 8, 4, 5,10,32,23,33,19,63,
    16, 5, 0,35,13, 8,60,51,43,56,57,53,36,54,58,46,
    15,20,49,37,18, 9,45,30,39, 1,23,11, 7,29,22,32,
    24,10,41,48,19,31,40,28,12, 4,33,62,61,44,59,63,
    14,34,38, 3,47,25,17,52, 2,55,21,42, 6,26,27,50,
    28,29,20, 1, 5, 3,23,30,31,32,33,34,35,36,26,27,
     2, 7,37,38,39,40,41, 0,16,15,42,24,43,44,45,46,
    21,25,19, 6,11, 4, 8, 9,12,14,18,17,10,22,47,13,
    48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
};
u16 pack_42_word_E3B0C4[] = {0,0x1000};
u16 pack_42_word_E3B10C[] = {0,0x4B8,0x8CB,0x0C89,0x0FC1,0x1000};
u16 pack_42_word_E3B420[] = {0,0x229,0x3E3,0x550,0x6B9,0x816,0x969,0x0AB9,0x0BB7,0x0CAE,0x0D8A,0x0E42,0x0EF7,0x0F87,0x0FF1,0x1000};
u16 pack_42_word_E3B440[] = {0,0x452,0x899,0x0B87,0x0E15,0x0F61,0x1000};
u16 pack_42_word_E3B450[] = {0,0x241,0x42A,0x5E2,0x775,0x901,0x0A88,0x0BFD,0x0D58,0x0EB2,0x1000};
u16 pack_42_word_E3B468[] = {0,0x1A0,0x2FA,0x420,0x539,0x63B,0x739,0x836,0x928,0x0A07,0x0AE6,0x0BB7,0x0C86,0x0D43,0x0DF2,0x0EA1,0x0F2F,0x0F97,0x0FD8,0x0FF0,0x1000};
u16 pack_42_word_E3B494[] = {0,0x5C8,0x8DA,0x0BBD,0x0E2F,0x0F23,0x1000};
u16 pack_42_word_E3B4A4[] = {0,0x1000};
u16 pack_42_word_E3B4A8[] = {0,0x0EF,0x1A5,0x242,0x2D4,0x366,0x3EE,0x46A,0x4DA,0x54A,0x5B3,0x619,0x67D,0x6D6,0x72D,0x77D,0x7CC,0x819,0x862,0x8AA,0x8F0,0x935,0x978,0x9BA,0x9F9,0x0A38,0x0A76,0x0AB3,0x0AF0,0x0B2C,0x0B63,0x0B99,0x0BCD,0x0C01,0x0C33,0x0C65,0x0C94,0x0CC3,0x0CF2,0x0D1E,0x0D49,0x0D73,0x0D9B,0x0DC2,0x0DE8,0x0E0D,0x0E31,0x0E53,0x0E73,0x0E93,0x0EB1,0x0ECF,0x0EED,0x0F0B,0x0F28,0x0F44,0x0F5F,0x0F79,0x0F91,0x0FA6,0x0FBB,0x0FD0,0x0FE2,0x0FF1,0x1000};
u16 pack_42_word_E3B530[] = {0,0x233,0x561,0x755,0x940,0x0A05,0x0ABD,0x0B48,0x0BD0,0x0C40,0x0C8A,0x0CCB,0x0D0B,0x0D47,0x0D7F,0x0DB2,0x0DE2,0x0E05,0x0E19,0x0E2D,0x0E40,0x0E50,0x0E5C,0x0E66,0x0E70,0x0E7A,0x0E84,0x0E8E,0x0E98,0x0EA2,0x0EAC,0x0EB6,0x0EC0,0x0ECA,0x0ED4,0x0EDE,0x0EE8,0x0EF2,0x0EFC,0x0F06,0x0F10,0x0F1A,0x0F24,0x0F2E,0x0F38,0x0F42,0x0F4C,0x0F56,0x0F60,0x0F6A,0x0F74,0x0F7E,0x0F88,0x0F92,0x0F9C,0x0FA6,0x0FB0,0x0FBA,0x0FC4,0x0FCE,0x0FD8,0x0FE2,0x0FEC,0x0FF6,0x1000};
u16 pack_42_word_E3B5B8[] = {0,0x32F,0x712,0x82B,0x904,0x9C3,0x0A78,0x0B27,0x0BC0,0x0C42,0x0C9A,0x0CEA,0x0D36,0x0D7E,0x0DC5,0x0DEE,0x0E06,0x0E1B,0x0E30,0x0E3C,0x0E48,0x0E52,0x0E5C,0x0E66,0x0E70,0x0E7A,0x0E84,0x0E8E,0x0E98,0x0EA2,0x0EAC,0x0EB6,0x0EC0,0x0ECA,0x0ED4,0x0EDE,0x0EE8,0x0EF2,0x0EFC,0x0F06,0x0F10,0x0F1A,0x0F24,0x0F2E,0x0F38,0x0F42,0x0F4C,0x0F56,0x0F60,0x0F6A,0x0F74,0x0F7E,0x0F88,0x0F92,0x0F9C,0x0FA6,0x0FB0,0x0FBA,0x0FC4,0x0FCE,0x0FD8,0x0FE2,0x0FEC,0x0FF6,0x1000};
u16 pack_42_word_E3B63C[] = {0,0x636,0x9C8,0x0AED,0x0BE5,0x0CA5,0x0F0E,0x0F7C,0x0F83,0x0F8A,0x0FC2,0x1000};
u16 pack_42_word_E3B654[] = {0,0x1E1,0x470,0x0C5C,0x0E79,0x0E88,0x0E8F,0x0E96,0x0F57,0x0F5E,0x0F87,0x1000};
u16 pack_42_word_E3B66C[] = {0,0x21D,0x66A,0x87E,0x0E9F,0x0EAF,0x0EB6,0x0EBD,0x0F97,0x0F9E,0x0FBF,0x1000};
u16 pack_42_word_E3B684[] = {0,0x3A9,0x76F,0x0CBA,0x0E7F,0x0E8E,0x0E95,0x0E9C,0x0F85,0x0F8C,0x0FB4,0x1000};
u16 pack_42_word_E3B69C[] = {0,0x1D4,0x1DB,0x1E2,0x1E9,0x0E93,0x0E9A,0x0EA1,0x0F31,0x0F38,0x0F3F,0x1000};
u16 pack_42_word_E3B6B4[] = {0,0x0AB,0x1E9,0x0B06,0x0C26,0x0C2D,0x0D68,0x0F05,0x0F4B,0x0F52,0x0FBD,0x1000};
u16 pack_42_word_E3B6CC[] = {0,0x12E,0x36D,0x478,0x898,0x89F,0x0D91,0x0EC5,0x0F92,0x0F99,0x0FA9,0x1000};
u16 pack_42_word_E3B6E4[] = {0,0x7,0x3EA,0x586,0x6C7,0x847,0x0D5F,0x0E37,0x0EC9,0x0ED0,0x0F5F,0x1000};
u16 pack_42_word_E3B6FC[] = {0,0x14D,0x29D,0x374,0x526,0x52D,0x53A,0x541,0x649,0x929,0x0FB1,0x1000};
u16 pack_42_word_E3B714[] = {0,0x7,0x0E,0x15,0x1C,0x23,0x2A,0x31,0x38,0x0FF2,0x0FF9,0x1000};
u16 pack_42_word_E3B72C[] = {0,0x15E,0x41C,0x4CE,0x59C,0x8C0,0x985,0x9B0,0x0B2C,0x0B33,0x0B58,0x1000};
u16 * pack_42_word_off_E3B748[] =
{
	pack_42_word_E3B0C4,pack_42_word_E3B63C,pack_42_word_E3B420,pack_42_word_E3B654,
    pack_42_word_E3B440,pack_42_word_E3B66C,pack_42_word_E3B10C,pack_42_word_E3B684,
    pack_42_word_E3B450,pack_42_word_E3B69C,pack_42_word_E3B468,pack_42_word_E3B6B4,
    pack_42_word_E3B494,pack_42_word_E3B6CC,pack_42_word_E3B4A4,pack_42_word_E3B6E4,
    pack_42_word_E3B4A8,pack_42_word_E3B6FC,pack_42_word_E3B530,pack_42_word_E3B714,
    pack_42_word_E3B5B8,pack_42_word_E3B72C
};
u16 pack_42_word_E3B7A0[] = {0,0x2A3,0x37C,0x67C,0x6A3,0x6AE,0x0A84,0x0B74,0x0DAD,0x0F5D,0x0FB2,0x0FD4,0x0FFF,0x1000};
u16 pack_42_word_E3B7BC[] = {0,0x123,0x266,0x2B4,0x8A2,0x9F5,0x0CFC,0x0F70,0x0FFF,0x1000};
u16 pack_42_word_E3B7D0[] = {0,0x14D,0x34C,0x42B,0x4A3,0x6CA,0x953,0x9C6,0x0A6C,0x0ABB,0x0BAE,0x0C43,0x0C9B,0x0CDD,0x0D31,0x0D93,0x0DB5,0x1000};
u32 pack_42_thing1_E3B7F4[4] = {7,2,1,(u32)pack_42_word_E3B7BC};
u32 pack_42_thing2_E3B804[4] = {16,1,0,(u32)pack_42_word_E3B7D0};

void * malloc_719490(void * *the_ptr, u32 bytes)
{
  void * result = *the_ptr ? realloc(*the_ptr, bytes) : malloc(bytes); // eax@2

  *the_ptr = result;
  if ( !result ) __asm int 3;
  return result;
}

u32 mem_expand_76A270(u32 required_size, u32 dummy, u32 ctx)
{
  u32 current_size; // edx@1
  u32 v4; // esi@2
  u32 v5; // ebx@3
  u32 v6; // ebx@5
  u32 v7; // ebp@5
  u32 v8; // eax@5
  u32 v10; // [sp+0h] [bp-4h]@1

  current_size = *(u32 *)(ctx + 0x3FE);
  if ( current_size < required_size )
  {
    v4 = *(u32 *)(ctx + 0x40A);
    if ( v4 )
    {
      v5 = *(u32 *)(v4 + 4);
	  v10 = v5 ? *(u32 *)(ctx + 0x402) - *(u32 *)v4 : 0;
      v8 = (required_size - current_size + 0x1FF) >> 9 << 9;
      v7 = v8;
      v6 = v8 + v5;
      if (v8 + !v5)
      {
        if ( *(u32 *)v4 ) free(*(void * *)v4);
        *(u32 *)v4 = 0;
      }
      else malloc_719490((void * *)v4, v6);
      *(u32 *)(v4 + 4) = v6;
      *(u32 *)(ctx + 0x3FE) += v7;
      required_size = *(u32 *)(ctx + 0x40A);
      *(u32 *)(ctx + 0x402) = v10 + *(u32 *)required_size;
    }
  }
  return required_size;
}

u32 pack_42_init_769FB0(u32 ctx)
{
  *(u32 *)(ctx + 174) = 0;
  *(u32 *)(ctx + 18) = 0;
  *(u32 *)(ctx + 22) = 4;
  *(u32 *)(ctx + 26) = 3;
  *(u32 *)(ctx + 30) = 5;
  *(u32 *)(ctx + 34) = 2;
  *(u32 *)(ctx + 38) = 6;
  *(u32 *)(ctx + 42) = 1;
  *(u32 *)(ctx + 0x14E) = 0;
  *(u32 *)(ctx + 178) = 0;
  *(u32 *)(ctx + 182) = 4;
  *(u32 *)(ctx + 186) = 3;
  *(u32 *)(ctx + 190) = 5;
  *(u32 *)(ctx + 194) = 2;
  *(u32 *)(ctx + 198) = 6;
  *(u32 *)(ctx + 202) = 1;
  *(u32 *)(ctx + 0x1EE) = 0;
  *(u32 *)(ctx + 0x152) = 0;
  *(u32 *)(ctx + 0x156) = 4;
  *(u32 *)(ctx + 0x15A) = 3;
  *(u32 *)(ctx + 0x15E) = 5;
  *(u32 *)(ctx + 0x162) = 2;
  *(u32 *)(ctx + 0x166) = 6;
  *(u32 *)(ctx + 0x16A) = 1;
  return ctx;
}

char Add_Byte(u32 ctx, char the_byte)
{
  u32 v3; // eax@2

  if ( *(u32 *)(ctx + 0x3FE) )
  {
    v3 = *(u32 *)(ctx + 0x402);
    *(u8 *)v3 = the_byte;
    ++*(u32 *)(ctx + 0x402);
    --*(u32 *)(ctx + 0x3FE);
  }
  else
  {
    v3 = mem_expand_76A270(1, ctx, ctx);
    if ( *(u32 *)(ctx + 0x3FE) )
    {
      v3 = the_byte;
      *(u8 *)((*(u32 *)(ctx + 0x402))++) = the_byte;
      --*(u32 *)(ctx + 0x3FE);
    }
    else
    {
      ++*(u32 *)(ctx + 0x406);
    }
  }
  return (u8) v3;
}

void pack_42_769CA0(u32 ctx)
{
  u32 v1; // eax@2

  for ( ; *(u32 *)(ctx + 8) <= 0x800000; *(u32 *)(ctx + 4) = (v1 & 0x7FFFFF) << 8 )
  {
    v1 = *(u32 *)(ctx + 4);
    if ( v1 >= 0x7F800000 )
    {
      if ( v1 <= 0X7FFFFFFF ) ++*(u32 *)(ctx + 13);
      else
      {
        Add_Byte(ctx, (u8)(*(u8 *)(ctx + 12) + 1));
        for ( ; *(u32 *)(ctx + 13); --*(u32 *)(ctx + 13) ) Add_Byte(ctx, 0);
        v1 = *(u32 *)(ctx + 4);
        *(u8 *)(ctx + 12) = (u8) (v1 >> 23);
      }
    }
    else
    {
      if ( *(u8 *)(ctx + 17) ) *(u8 *)(ctx + 17) = 0; else Add_Byte(ctx, *(u8 *)(ctx + 12));
      for ( ; *(u32 *)(ctx + 13); --*(u32 *)(ctx + 13) ) Add_Byte(ctx, 255);
      v1 = *(u32 *)(ctx + 4);
      *(u8 *)(ctx + 12) = (u8) (v1 >> 23);
    }
    *(u32 *)(ctx + 8) <<= 8;
  }
}

u32 pack_42_769D70(u32 ctx)
{
  u32 v1; // ebx@1

  *(u32 *)(ctx + 4) += (*(u32 *)(ctx + 8) >>= 1);
  pack_42_769CA0(ctx);
  v1 = *(u32 *)(ctx + 4) >> 23;
  if ( v1 <= 255 )
  {
    if ( *(u8 *)(ctx + 17) ) *(u8 *)(ctx + 17) = 0; else Add_Byte(ctx, *(u8 *)(ctx + 12));
    for ( ; *(u32 *)(ctx + 13); --*(u32 *)(ctx + 13) ) Add_Byte(ctx, 255);
    return Add_Byte(ctx, (u8) v1);
  }
  Add_Byte(ctx, (u8)(*(u8 *)(ctx + 12) + 1));
  if ( !*(u32 *)(ctx + 13) ) return Add_Byte(ctx, (u8) v1);
  do
  {
    Add_Byte(ctx, 0);
    --*(u32 *)(ctx + 13);
  }
  while ( *(u32 *)(ctx + 13) );
  return Add_Byte(ctx, (u8) v1);
}

u32 pack_42_new_ctx_76A0E0(u32 ctx, u32 a2, u8 * packed_list)
{
  *(u32 *)ctx = 0;	// used to contain Add_Byte address
  *(u32 *)(ctx + 0x3F2) = ctx + 0x1F2;
  *(u32 *)(ctx + 0x3F6) = 0;
  *(u32 *)(ctx + 0x3FA) = 32;
  *(u32 *)(ctx + 0x40A) = 0;
  *(u32 *)(ctx + 0x40E) = a2;
  *(u32 *)(ctx + 0x3FE) = a2;
  *(u8 * *)(ctx + 0x402) = packed_list;
  *(u32 *)(ctx + 0x406) = 0;
  return ctx;
}

u32 __stdcall pack_42_76A300(u32 ctx)
{
  u32 v2; // edi@2
  u32 v3; // esi@2
  u32 result; // eax@5

  if ( *(u32 *)(ctx + 0x40A) )
  {
    v3 = *(u32 *)(ctx + 0x40A);
    v2 = *(u32 *)(v3 + 4) - *(u32 *)(ctx + 0x3FE);
    if ( v2 )
    {
      malloc_719490((void * *)v3, v2);
      *(u32 *)(v3 + 4) = v2;
      result = *(u32 *)(*(u32 *)(ctx + 0x40A) + 4);
    }
    else
    {
      if ( v3 ) free(*(void * *)v3);
      *(u32 *)(v3 + 4) = v2;
      *(u32 *)v3 = 0;
      result = *(u32 *)(*(u32 *)(ctx + 0x40A) + 4);
    }
  }
  else
  {
    result = *(u32 *)(ctx + 0x406) + *(u32 *)(ctx + 0x40E) - *(u32 *)(ctx + 0x3FE);
  }
  return result;
}

void * pack_42_end_ctx_7149A0(u32 ctx)
{
  void * result; // eax@1

  result = *(void * *)(ctx + 0x3F2);
  if ( result != (void *)(ctx + 0x1F2) )
  {
    if ( result ) free(*(void * *)(ctx + 0x3F2)), result = NULL;
    *(u32 *)(ctx + 0x3F2) = ctx + 0x1F2;
  }
  *(u32 *)(ctx + 0x3F6) = 0;
  *(u32 *)(ctx + 0x3FA) = 32;
  *(u32 *)ctx = 0;
  return result;
}

u32 pack_42_dword_76A380(u32 ctx, u32 * thing, u32 the_dword)
{
  u32 bits; // ebp@1
  u32 result; // eax@5
  u32 v8; // edx@5
  u32 v9; // ecx@5
  u32 v10; // ebp@5
  u32 v11; // edi@5
  u32 v12; // edx@9
  u32 v13; // ecx@9
  u32 v14; // edi@9
  u32 v15; // eax@12
  u32 v16; // ecx@12
  u32 v17; // ebx@12
  u32 v18; // ebp@16
  u32 *v19; // eax@19
  u32 v20; // edx@21
  u32 v21; // ebx@21
  u32 v22; // edi@21
  u32 v23; // edi@5
  u16 *v24; // eax@9
  u32 v25; // edi@9
  u32 v26; // ecx@9
  u32 v27; // edi@11
  u16 *v28; // ecx@12
  u32 v29; // eax@12
  u32 v30; // edx@21
  u32 v31; // ebp@21
  u32 v32; // ebp@24
  u32 v33; // [sp+10h] [bp-Ch]@12
  u32 v34; // [sp+14h] [bp-8h]@17
  u32 v35; // [sp+18h] [bp-4h]@21

  bits = 0;
  do
  {
    if ( the_dword < (u32)(1 << (char)bits) ) break;
    ++bits;
  }
  while ( bits < 32 );
  if ( bits > thing[1] )
  {
    if ( bits >= thing[0] )
    {
      v28 = (u16 *)thing[3];
      v29 = thing[0] + thing[2];
      v17 = v28[v29 + 1];
      v33 = v28[v29];
      pack_42_769CA0(ctx);
      v15 = *(u32 *)(ctx + 8) >> 12;
      v16 = v33 * v15;
      if ( v17 & 0xFFFFF000 ) *(u32 *)(ctx + 8) -= v16;
      else *(u32 *)(ctx + 8) = v15 * (v17 - v33);
      *(u32 *)(ctx + 4) += v16;
      result = pack_42_dword_76A380(ctx, thing, bits - thing[0]);
    }
    else
    {
      v24 = (u16 *)thing[3];
      v25 = bits + thing[2];
      v26 = v24[v25];
      v14 = v24[v25 + 1];
      pack_42_769CA0(ctx);
      v12 = *(u32 *)(ctx + 8);
      result = v12 >> 12;
      v13 = v26 * (v12 >> 12);
      if ( v14 & 0xFFFFF000 )
      {
        *(u32 *)(ctx + 4) += v13;
        *(u32 *)(ctx + 8) = v12 - v13;
      }
      else
      {
        v27 = result * (v14 - v26);
        *(u32 *)(ctx + 4) += v13;
        *(u32 *)(ctx + 8) = v27;
      }
    }
    v18 = bits - 1;
    v33 = v18;
    for (v34 = 16; v18; v33 = v18)
    {
      v19 = &v34;
      if ( (u32)v18 <= 16 ) v19 = &v33;
      v22 = *v19;
      v30 = the_dword & ((1 << *v19) - 1);
      v31 = (u16)v30;
      v35 = (u16)v30;
      v21 = (u16)v30 + 1;
      pack_42_769CA0(ctx);
      result = *(u32 *)(ctx + 8) >> v22;
      v20 = v31 * result;
      if ( !(v21 >> v22) ) *(u32 *)(ctx + 8) = result * (v21 - v35);
      else *(u32 *)(ctx + 8) = result = *(u32 *)(ctx + 8) - v20;
      v32 = v33;
      *(u32 *)(ctx + 4) += v20;
      the_dword = (u32)the_dword >> v22;
      v18 = v32 - v22;
	}
  }
  else
  {
    v23 = thing[3];
    v10 = *(u16 *)(v23 + 2 * the_dword);
    v11 = *(u16 *)(v23 + 2 * the_dword + 2);
    pack_42_769CA0(ctx);
    v8 = *(u32 *)(ctx + 8);
    result = v8 >> 12;
    v9 = v10 * (v8 >> 12);
    if ( v11 & 0xFFFFF000 )
    {
      *(u32 *)(ctx + 4) += v9;
      *(u32 *)(ctx + 8) = v8 - v9;
    }
    else
    {
      *(u32 *)(ctx + 4) += v9;
      *(u32 *)(ctx + 8) = result * (v11 - v10);
    }
  }
  return result;
}

void pack_42_expand_ctx_87F0F0(u32 newctx, u32 ctx)
{
  u32 v3 = *(u32 *)(ctx + 0x204); // eax@2
  char v4; // zf@2

  if ( v3 + 1 > *(u32 *)(ctx + 0x208) )
  {
    v3 += 32;
    v4 = *(u32 *)(ctx + 0x200) == ctx;
    *(u32 *)(ctx + 0x208) = v3;
    if ( v4 ) *(u32 *)(ctx + 0x200) = 0;
    newctx = *(u32 *)(ctx + 0x200);
    malloc_719490((void * *)&ctx, 16 * v3);
    if ( !*(u32 *)(ctx + 0x200) ) memcpy((void *) newctx, (void *) ctx, 16 * *(u32 *)(ctx + 0x204));
    *(u32 *)(ctx + 0x200) = newctx;
  }
}

u32 pack_41_dword_7148A0(u32 the_dword, u8 **pos_ptr)
{
  u8 *ptr; // ecx@2
  u8 *v3; // ecx@5

  if ( the_dword > 127 )
  {
    ptr = *pos_ptr;
    do
    {
      *ptr = (u8)the_dword | 128;
      the_dword >>= 7;
      ++ptr;
    }
    while ( the_dword > 127 );
    *pos_ptr = ptr;
  }
  v3 = *pos_ptr;
  **pos_ptr = (u8) the_dword;
  *pos_ptr = v3 + 1;
  return the_dword;
}

u32 pack_4142(u32 * list, u8 * packed_list, u32 pack_42, u32 max_bytes);

void pack_41_copy_thing_715460(u8 *pos, u32 *thing)
{
  u32 i; // eax@1
  u32 the_dword; // eax@1
  u8 *v4; // esi@1
  u8 *v6; // esi@3
  u8 *pos_ptr; // [sp+0h] [bp-4h]@1

  *pos = *(u8 *)thing;
  v4 = pos + 1;
  for ( i = thing[1]; i > 127; ++v4 )
  {
    *v4 = (u8)i | 128;
    i >>= 7;
  }
  *v4 = (u8) i;
  v6 = v4 + 1;
  pos_ptr = v6;
  switch ( *thing )
  {
    case 0:
      for (the_dword = thing[2]; the_dword > 127; the_dword >>= 7) *v6++ = (u8)the_dword | 128;
      *v6 = (u8) the_dword;
      break;
    case 1:
      for (i = 0; i < 8; i++) v6[i] = ((u8*)(thing+2))[i^7];
      break;
    case 2:
      v6[0] = (u8) (thing[2] >> 24);	// IP
      v6[1] = (u8) (thing[2] >> 16);
      v6[2] = (u8) (thing[2] >>  8);
      v6[3] = (u8)  thing[2];
      v6[4] = (u8) (thing[3] >> 8);	// port
      v6[5] = (u8)  thing[3];
      break;
    case 3:
      memcpy(v6, (void *) thing[2], thing[3]);
      break;
    case 4:
      pack_41_dword_7148A0(thing[3], &pos_ptr);
      memcpy(pos_ptr, (void *)thing[2], thing[3]);
      break;
    case 5:
      pack_4142((u32 *)thing[2], v6, 0, -1);
      break;
    case 6:
      pack_41_dword_7148A0(thing[3] >> 2, &pos_ptr);
      for (i = 0; i < thing[3] >> 2; i++) pack_41_dword_7148A0(((u32 *)thing[2])[i], &pos_ptr);
      break;
    default:
      __asm int 3;
  }
}

u32 __fastcall packed_dword_chars_714880(u32 the_dword)
{
  u32 chars; // eax@1

  for ( chars = 1; the_dword > 127; ++chars ) the_dword >>= 7;
  return chars;
}

u32 get_4142_packed_length_7148D0(u32 * list, char pack42);

u32 get_41_packed_length_7155B0(u32 * thing)
{
  u32 id_chars; // edx@1
  u32 nchars; // edi@3
  u32 i; // eax@4
  u32 j; // ecx@4
  u32 chars; // eax@6
  u32 ptr; // ebx@18
  u32 dwords; // edx@19

  for (i = thing[1], id_chars = 1; i > 127; id_chars++) i >>= 7;
  nchars = id_chars + 1;
  switch ( thing[0] )
  {
    case 0:
      i = thing[2];
      for ( j = 1; i > 127; ++j ) i >>= 7;
      chars = j + nchars;
      break;
    case 1:
      chars = id_chars + 9;
      break;
    case 2:
      chars = id_chars + 7;
      break;
    case 3:
      chars = thing[3] + nchars;
      break;
    case 4:
      chars = id_chars + packed_dword_chars_714880(thing[3]) + nchars;
      break;
    case 5:
      chars = get_4142_packed_length_7148D0((u32 *) thing[2], 0) + nchars;
      break;
    case 6:
      ptr = thing[2];
	  dwords = thing[3] >> 2;
      nchars += packed_dword_chars_714880(dwords);
      for (i = 0; i < dwords; ) nchars += packed_dword_chars_714880(*(u32 *)(ptr + 4 * i++));
      // no break here, fall through
    default:
      chars = nchars;
      break;
  }
  return chars;
}

void * pack_42_76A540(u32 ctx, u32 * the_list);

u32 get_4142_packed_length_7148D0(u32 * list, char pack42)
{
  u32 v4; // eax@3
  u32 v5; // edx@3
  u32 v6; // ecx@3
  u32 v7; // edi@5
  u32 total_length; // ebx@6
  u32 ctx[0x107]; // [sp+10h] [bp-420h]@2

  if ( pack42 )
  {
    pack_42_new_ctx_76A0E0((u32)ctx, 0, 0);
    pack_42_76A540((u32)ctx, list);
    total_length = pack_42_76A300((u32)ctx);
    pack_42_end_ctx_7149A0((u32)ctx);
    return total_length;
  }
  v5 = *(u32 *)(list + 12);
  v4 = *(u32 *)(list + 12);
  for (v6 = 1; v4 > 127; v6++) v4 >>= 7;
  for (v7 = 0, total_length = v6 + 1; v7 < v5; v7++)
  {
    total_length += get_41_packed_length_7155B0(v7 * 4 + *(u32 * *)(list + 4));
  }
  return total_length;
}

void pack_42_9F8BA0(u32 *ptr, u32 *ctx)
{
  u32 words = ctx[33]; // eax@2

  if ( words + 1 > ctx[34] )
  {
    ctx[34] = words + 32;
    ptr = (u32 *)ctx[32];
    if (ptr == ctx) ctx[32] = 0;
    malloc_719490((void * *)&ptr, 4 * (words + 32));
    if (!ctx[32]) memcpy((void *)ptr, (void *)ctx, 4 * words);
    ctx[32] = (u32)ptr;
  }
}

u32 pack_42_copy_thing_9FF4E0(u32 * ctx, u32 *ptr, u32 i)
{
  u32 result; // eax@3

  if ( ctx[33] >= ctx[34] ) pack_42_9F8BA0(ptr, ctx);
  memcpy((void *)(ctx[32] + 4 * i + 4), (void *)(ctx[32] + 4 * i), 4 * (ctx[33]++ - i));
  result = 4 * i + ctx[32];
  if (result) *(u32 *)result = 0;
  return result;
}

u32 pack_42_find_code_76A070(u32 *code_array, u32 look_for)
{
  u32 i; // esi@1
  u32 v5; // ebx@7

  i = 0;
  while ( 1 )
  {
    if ( i > 6 ) __asm int 3;
    if ( code_array[i] == look_for ) break;
    ++i;
  }
  if ( i )
  {
    v5 = code_array[i];
    memcpy(code_array + 1, code_array, 4 * i);
    *code_array = v5;
  }
  return i;
}

void pack_42_76A690(u32 ctx, u32 *list_ptr, u32 a3)
{
  u32 thing_i; // ebx@1
  u32 i; // eax@3
  u32 *thing_ptr; // edi@3
  u32 *layered_list_ptr;
  u32 *v8; // eax@8
  u32 v9; // eax@10
  u32 v10; // edx@10
  u32 v11; // edi@10
  u32 *v12; // ecx@13
  u32 *v13; // ebx@15
  u32 last_thing; // edx@20
  u32 v15; // eax@23
  u32 v16; // edx@23
  u32 *list; // ebx@23
  u32 v19; // eax@30
  u32 v20; // ecx@30
  u32 v21; // eax@33
  u32 v22; // eax@34
  u32 v23; // edx@35
  u32 v24; // ecx@35
  u16 **v25; // ecx@43
  u32 v26; // ebx@43
  u32 v27; // edx@44
  u32 v28; // ecx@44
  u32 v29; // ebx@44
  u32 v30; // edi@44
  u16 *v31; // ecx@47
  u32 v32; // edx@48
  u32 v33; // ecx@48
  u32 v34; // ebx@48
  u32 v35; // edi@48
  u32 v36; // ebx@54
  u32 v37; // edi@54
  u32 v38; // ecx@57
  u32 v39; // ebx@57
  u32 v40; // eax@59
  u32 bytes_to_pack; // edi@62
  u32 v45; // eax@67
  u32 v46; // ebx@68
  u32 v47; // ST00_4@72
  u32 v50; // ecx@73
  u32 v51; // eax@75
  u32 things; // eax@1
  u32 v54; // eax@7
  u32 allocated_things; // ecx@23
  u32 code_to_look_for; // ST08_4@23
  u32 v57; // eax@30
  u8 v58; // al@44
  u16 *v59; // ecx@44
  u32 v60; // eax@44
  u32 v61; // eax@48
  u32 case_4_bytes; // eax@57
  u32 v64; // ecx@59
  u32 v68; // ecx@67
  u8 v69; // zf@67
  u32 v74; // eax@73
  u8 v75; // cf@73
  u32 v76; // ecx@75
  u8 v77; // zf@75
  u8 v78; // cf@80
  u32 context[37]; // [sp+38h] [bp-A8h]@1
  u16 **v82; // [sp+10h] [bp-D0h]@2
  u32 v83; // [sp+10h] [bp-D0h]@2
  u32 v86; // [sp+14h] [bp-CCh]@8
  u32 *v84; // [sp+28h] [bp-B8h]@10
  u32 v88; // [sp+18h] [bp-C8h]@10
  u32 v89; // [sp+24h] [bp-BCh]@20
  u32 current_thing; // [sp+2Ch] [bp-B4h]@22
  u32 v91; // [sp+20h] [bp-C0h]@44
  u8 v92; // [sp+1Fh] [bp-C1h]@44

  things = list_ptr[3];
  thing_i = 0;
  context[32] = (u32)context;
  context[33] = 0;
  context[34] = 32;
  if ( things )
  {
    v83 = 0;
    do
    {
      thing_ptr = (u32 *)(v83 + list_ptr[1]);
      i = 0;
      if ( context[33] )
      {
        layered_list_ptr = (u32 *)thing_ptr[1];
        do
        {
          if ( layered_list_ptr < ((u32 * *)((u32 *)context[32])[i])[1] ) break;
          ++i;
        }
        while ( i < context[33] );
      }
      v54 = pack_42_copy_thing_9FF4E0(context, layered_list_ptr, i);
      v83 += 16;
      *(u32 **)v54 = thing_ptr;
      ++thing_i;
    }
    while ( thing_i < list_ptr[3] );
  }
  v86 = 2;
  v8 = (u32 *)&v86;
  if ( a3 <= 2 ) v8 = &a3;
  v10 = 160 * *v8;
  v9 = 0;
  v11 = v10 + ctx + 18;
  v84 = (u32 *)(v10 + ctx + 18);
  v88 = 0;
  if ( a3 )
  {
    if ( *(u32 *)(v10 + ctx + 174) )
    {
      if ( context[33] > 0 )
      {
        v12 = (u32 *)(v10 + ctx + 50);
        do
        {
          if ( (u32)v9 >= *(u32 *)(v10 + ctx + 174) ) break;
          v13 = (u32 *)((u32 *)context[32])[v9];
          if ( *(v13 + 1) != *(v12 - 1) ) break;
          if ( *v13 != *v12 ) break;
          ++v9;
          v12 += 2;
        }
        while ( v9 < context[33] );
        v88 = v9;
      }
      pack_42_dword_76A380(ctx, pack_42_thing1_E3B7F4, v9);
    }
  }
  last_thing = 0;
  *(u32 *)(v11 + 156) = 0;
  v89 = 0;
  if ( context[33] )
  {
    while ( 1 )
    {
      list = (u32 *)((u32 *)context[32])[v89];
      allocated_things = list[1];
      current_thing = list[1];
      code_to_look_for = list[0];
      v83 = allocated_things - last_thing;
      v15 = pack_42_find_code_76A070((u32 *)v11, code_to_look_for);
      v16 = v84[39];
      if ( v16 < 16 )
      {
        v84[2 * v16 + 7] = list[1];
        v11 = list[0];
        v84[2 * v84[39]++ + 8] = list[0];
      }
      if ( v88 )
      {
        --v88;
        goto LABEL_40;
      }
      if ( v15 ) break;
      v57 = __min (v83, 5);
      v11 = pack_42_word_E3B7A0[v57 + 2];
      v86 = pack_42_word_E3B7A0[v57 + 1];
      pack_42_769CA0(ctx);
      v19 = *(u32 *)(ctx + 8) >> 12;
      v20 = v86 * v19;
      if ( v11 & 0xFFFFF000 )
      {
        *(u32 *)(ctx + 8) -= v20;
      }
      else
      {
        v11 = v19 * (v11 - v86);
        *(u32 *)(ctx + 8) = v11;
      }
      v21 = v83;
      *(u32 *)(ctx + 4) += v20;
      if ( v21 >= 5 )
      {
        v22 = v21 - 5;
LABEL_39:
        pack_42_dword_76A380(ctx, pack_42_thing1_E3B7F4, v22);
      }
LABEL_40:
      switch ( list[0] )
      {
        case 0:
          pack_42_dword_76A380(ctx, pack_42_thing2_E3B804, list[2]);
          break;
        case 5:
          pack_42_76A690(ctx, (u32 *)list[2], a3 + 1);
          break;
        case 3:
          v26 = list[2];
          v25 = pack_42_word_off_E3B748;
          while ( 1 )
          {
            v58 = *(u8 *)v26;
            v59 = v25[1];
            v91 = v26 + 1;
            v29 = v58;
            v92 = v58;
            v60 = pack_42_byte_E3B220[v58];
            v30 = v59[v60 + 1];
            v82 = pack_42_word_off_E3B748 + 2 * v60;
            v86 = v59[v60];
            pack_42_769CA0(ctx);
            v27 = *(u32 *)(ctx + 8);
            v28 = v86 * (v27 >> 12);
            if ( !(v30 & 0xFFFFF000) ) *(u32 *)(ctx + 8) = (v27 >> 12) * (v30 - v86);
            else *(u32 *)(ctx + 8) = v27 - v28;
            *(u32 *)(ctx + 4) += v28;
            v31 = *v82;
            if ( *(*v82 + 1) != 0x1000 )
            {
              v61 = pack_42_byte_E3B320[v29];
              v34 = v31[v61];
              v35 = v31[v61 + 1];
              pack_42_769CA0(ctx);
              v32 = *(u32 *)(ctx + 8);
              v33 = v34 * (v32 >> 12);
              if ( v35 & 0xFFFFF000 ) *(u32 *)(ctx + 8) = v32 - v33;
              else *(u32 *)(ctx + 8) = (v32 >> 12) * (v35 - v34);
              *(u32 *)(ctx + 4) += v33;
            }
            if ( !v92 ) break;
            v25 = v82;
            v26 = v91;
          }
          break;
        case 6:
          v37 = list[3] >> 2;
          v91 = list[2];
          pack_42_dword_76A380(ctx, pack_42_thing2_E3B804, v37);
          v36 = 0;
          if ( v37 )
          {
            do pack_42_dword_76A380(ctx, pack_42_thing2_E3B804, *(u32 *)(v91 + 4 * v36++));
            while ( v36 < v37 );
          }
          break;
        case 4:
          case_4_bytes = list[3];
          v39 = list[2];
          pack_42_dword_76A380(ctx, pack_42_thing2_E3B804, case_4_bytes);
          v38 = *(u32 *)(ctx + 0x3F6);
          if ( v38 >= *(u32 *)(ctx + 0x3FA) ) pack_42_expand_ctx_87F0F0(v38, v11);
          v64 = *(u32 *)(ctx + 0x3F6);
          v40 = *(u32 *)(ctx + 0x3F2) + 16 * v64;
          *(u32 *)(ctx + 0x3F6) = v64 + 1;
          *(u32 *)v40 = 0;
          *(u32 *)(v40 + 4) = 0;
          *(u32 *)(v40 + 8) = 0;
          *(u32 *)(v40 + 12) = 0;
          *(u32 *)(v40 + 4) = v39;
          *(u32 *)v40 = case_4_bytes;
          break;
        case 1:
          for (bytes_to_pack = 8; bytes_to_pack; bytes_to_pack--) if (((u8 *)(list+2))[bytes_to_pack-1]) break;
          pack_42_dword_76A380(ctx, pack_42_thing2_E3B804, bytes_to_pack);
          if ( *(u32 *)(ctx + 0x3F6) >= *(u32 *)(ctx + 0x3FA) )
          {
            pack_42_expand_ctx_87F0F0(ctx, ctx + 0x1F2);
          }
          v68 = *(u32 *)(ctx + 0x3F6);
          v69 = *(u32 *)(ctx + 0x3F2) + 16 * v68 == 0;
          v45 = *(u32 *)(ctx + 0x3F2) + 16 * v68;
          *(u32 *)(ctx + 0x3F6) = v68 + 1;
          if ( v69 )
          {
            v46 = 0;
          }
          else
          {
            *(u32 *)v45 = 0;
            *(u32 *)(v45 + 4) = 0;
            *(u32 *)(v45 + 8) = 0;
            *(u32 *)(v45 + 12) = 0;
            v46 = v45;
          }
          if ( (u32)bytes_to_pack > 8 ) __asm int 3;
          *(u32 *)(v46 + 4) = 0;
          *(u32 *)v46 = bytes_to_pack;
          v47 = v46 + 8;
          goto LABEL_79;
        case 2:
          v74 = *(u32 *)(ctx + 0x3F6);
          v75 = v74 < *(u32 *)(ctx + 0x3FA);
          if ( !v75 ) pack_42_expand_ctx_87F0F0(v50, v11);
          v76 = *(u32 *)(ctx + 0x3F6);
          v77 = *(u32 *)(ctx + 0x3F2) + 16 * v76 == 0;
          v51 = *(u32 *)(ctx + 0x3F2) + 16 * v76;
          *(u32 *)(ctx + 0x3F6) = v76 + 1;
          if ( v77 )
          {
            v51 = 0;
          }
          else
          {
            *(u32 *)v51 = 0;
            *(u32 *)(v51 + 4) = 0;
            *(u32 *)(v51 + 8) = 0;
            *(u32 *)(v51 + 12) = 0;
          }
          bytes_to_pack = 6;
          *(u32 *)(v51 + 4) = 0;
          *(u32 *)v51 = 6;
          v47 = v51 + 8;
LABEL_79:
          memcpy((void *)v47, (u8 *)(list+2), bytes_to_pack);
          break;
        default:
          break;
      }
      v78 = v89++ + 1 < context[33];
      if ( !v78 ) goto LABEL_81;
      last_thing = current_thing;
      v11 = (u32)v84;
    }
    v86 = pack_42_word_E3B7A0[v15 + 6];
    v11 = pack_42_word_E3B7A0[v15 + 7];
    pack_42_769CA0(ctx);
    v23 = *(u32 *)(ctx + 8);
    v24 = v86 * (v23 >> 12);
    if ( v11 & 0xFFFFF000 )
    {
      *(u32 *)(ctx + 8) = v23 - v24;
    }
    else
    {
      v11 = (v23 >> 12) * (v11 - v86);
      *(u32 *)(ctx + 8) = v11;
    }
    *(u32 *)(ctx + 4) += v24;
    v22 = v83;
    goto LABEL_39;
  }
LABEL_81:
  pack_42_769CA0(ctx);
  *(u32 *)(ctx + 8) = 0x2A3 * (*(u32 *)(ctx + 8) >> 12);
  if ( context[32] && ((u32 *)context[32] != context) ) free((void *)context[32]);
}

void * pack_42_76A540(u32 ctx, u32 * thing)
{
  void *v2; // eax@1
  u32 v3; // ebx@1
  u32 v4; // ebp@1
  u32 packed_bytes; // eax@5
  void * packed_end; // eax@5
  u32 v7; // esi@6
  u32 v8; // eax@7
  u32 v9; // ecx@7
  u32 v10; // ebp@11
  u32 v11; // eax@12
  u32 current_packed_byte; // esi@12
  u32 v14; // esi@12
  u32 v15; // [sp+10h] [bp-4h]@1

  v2 = *(void **)(ctx + 0x3F2);
  v4 = ctx + 0x1F2;
  packed_end = *(void * *)(v4 + 0x200);
  v3 = 0;
  v15 = ctx + 0x1F2;
  if ( v2 != (void *)(ctx + 0x1F2) )
  {
    if ( v2 ) free (v2);
    *(u32 *)(ctx + 0x3F2) = ctx + 0x1F2;
  }
  *(u32 *)(ctx + 0x3F6) = 0;
  *(u32 *)(ctx + 0x3FA) = 32;
  pack_42_init_769FB0(ctx);
  *(u32 *)(ctx + 4) = 0;
  *(u32 *)(ctx + 8) = 0x80000000;
  *(u8 *)(ctx + 12) = 0;
  *(u32 *)(ctx + 13) = 0;
  *(u8 *)(ctx + 17) = 1;
  Add_Byte(ctx, 0x42);
  pack_42_76A690(ctx, thing, 0);
  pack_42_769D70(ctx);
  packed_bytes = *(u32 *)(ctx + 0x3F6);
  if ( packed_bytes )
  {
    v7 = 0;
    if ( packed_bytes > 0 )
    {
      v8 = *(u32 *)(ctx + 0x3F2);
      v9 = *(u32 *)(ctx + 0x3F6);
      do
      {
        v7 += *(u32 *)v8;
        v8 += 16;
        --v9;
      }
      while ( v9 );
    }
    mem_expand_76A270(v8, v7, ctx);
    if ( *(u32 *)(ctx + 0x3FE) < v7 ) *(u32 *)(ctx + 0x406) += v7;
    else if ( *(u32 *)(ctx + 0x3F6) > 0 )
    {
      v10 = 0;
      do
      {
        v14 = *(u32 *)(ctx + 0x3F2);
        v11 = *(u32 *)(v10 + 4 + v14);
        current_packed_byte = v10 + v14;
        if ( !v11 ) v11 = current_packed_byte + 8;
        memcpy((void *)(*(u32 *)(ctx + 0x402)), (void *)v11, *(u32 *)current_packed_byte);
        *(u32 *)(ctx + 0x402) += *(u32 *)current_packed_byte;
        *(u32 *)(ctx + 0x3FE) -= *(u32 *)current_packed_byte;
        v3++;
        v10 += 16;
      }
      while ( v3 < *(u32 *)(ctx + 0x3F6) );
      v4 = v15;
      v3 = 0;
    }
    packed_end = *(void * *)(v4 + 0x200);
    if ( (u32)packed_end != v4 )
    {
      if ( (u32)packed_end != v3 ) free(*(void * *)(v4 + 0x200)), packed_end = 0;
      *(u32 *)(v4 + 0x200) = v4;
    }
    *(u32 *)(v4 + 0x204) = v3;
    *(u32 *)(v4 + 0x208) = 32;
  }
  return packed_end;
}

u32 pack_4142(u32 * list, u8 * packed_list, u32 pack_42, u32 max_bytes)
{
  u32 packed_size; // eax@2
  u32 v8; // eax@5
  u8 * pl; // esi@5
  u8 * pos; // esi@7
  u32 i; // ebx@8
  u32 total_length; // esi@2
  u32 ctx[263]; // [sp+18h] [bp-420h]@2

  if ( pack_42 )
  {
    pack_42_new_ctx_76A0E0((u32)ctx, max_bytes, packed_list);
    pack_42_76A540((u32)ctx, list);
    total_length = pack_42_76A300((u32)ctx);
    pack_42_end_ctx_7149A0((u32)ctx);
    packed_size = total_length;
  }
  else if ( (max_bytes == -1) || (max_bytes >= (packed_size = get_4142_packed_length_7148D0(list, 0))) )
  {
    *(u8 *)packed_list = 0x41;
    v8 = list[3];
    for ( pl = packed_list + 1; v8 > 127; ++pl )
    {
      *pl = (u8)v8 | 128;
      v8 >>= 7;
    }
    *pl = (u8)v8;
    pos = pl + 1;
    if (list[3] <= 0x7FFFFFFF) for (i = 0; i < list[3]; i++)
    {
      pack_41_copy_thing_715460(pos, (u32 *)list[1] + i*4);
      pos += get_41_packed_length_7155B0((u32 *)list[1] + i*4);
    }
    packed_size = (u32) (pos - packed_list);
  }
  return packed_size;
}
