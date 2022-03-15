#include <string.h>

extern const int AesLookupTableA0[256];
extern const int AesLookupTableA1[256];
extern const int AesLookupTableA2[256];
extern const int AesLookupTableA3[256];
extern const int SosemanukDivTable[256];
extern const int SosemanukMulTable[256];

#define HIBYTE(v) ((v>>24)&0xff)
#define LOBYTE(v) (v&0xff)
#define BYTE1(v) ((v>>8)&0xff)
#define BYTE2(v) ((v>>16)&0xff)

unsigned int c_init_enc_state(unsigned int *state1, const char *key)
{
  int v3; // edi
  unsigned int v4; // edx
  unsigned int v5; // edi
  unsigned int v6; // ebx
  int v7; // esi
  unsigned int v8; // eax
  unsigned int v9; // ebx
  int v10; // esi
  int v11; // edx
  int v12; // edi
  unsigned int v13; // ebx
  int v14; // edi
  unsigned int v15; // esi
  int v16; // edi
  int v17; // edi
  unsigned int v18; // ebx
  int v19; // edi
  int v20; // eax
  int v21; // edx
  int v22; // edi
  int v23; // edx
  unsigned int v24; // ebx
  int v25; // edi
  int v26; // eax
  int v27; // edi
  int v28; // edx
  unsigned int v29; // esi
  int v30; // edi
  int v31; // eax
  int v32; // edi
  int v33; // edx
  unsigned int v34; // ebx
  int v35; // edi
  int v36; // eax
  int v37; // edx
  int v38; // edi
  int v39; // edx
  unsigned int v40; // ebx
  int v41; // edi
  int v42; // eax
  int v43; // edi
  int v44; // edx
  unsigned int v45; // ebx
  int v46; // edi
  int v47; // eax
  int v48; // edi
  int v49; // edx
  unsigned int v50; // ebx
  int v51; // edi
  int v52; // eax
  int v53; // edi
  int v54; // edx
  unsigned int v55; // esi
  int v56; // edi
  int v57; // eax
  int v58; // edi
  int v59; // edx
  unsigned int v60; // ebx
  unsigned int v61; // esi
  int v62; // edi
  int v63; // eax
  int v64; // edx
  int v65; // edi
  int v66; // edx
  int v67; // edi
  int v68; // esi
  int v69; // eax
  int v70; // esi
  int v71; // esi
  int v72; // eax
  int v73; // zf
  unsigned int result; // eax
  int v75; // [esp+Ch] [ebp-50h]
  int v76; // [esp+10h] [ebp-4Ch]
  int v77; // [esp+14h] [ebp-48h]
  unsigned int v78; // [esp+14h] [ebp-48h]
  unsigned int v79; // [esp+14h] [ebp-48h]
  unsigned int v80; // [esp+14h] [ebp-48h]
  unsigned int v81; // [esp+14h] [ebp-48h]
  unsigned int v82; // [esp+18h] [ebp-44h]
  unsigned int v83; // [esp+1Ch] [ebp-40h]
  unsigned int v84; // [esp+1Ch] [ebp-40h]
  unsigned int v85; // [esp+20h] [ebp-3Ch]
  unsigned int v86; // [esp+24h] [ebp-38h]
  unsigned int v87; // [esp+28h] [ebp-34h]
  unsigned int v88; // [esp+2Ch] [ebp-30h]
  unsigned int v89; // [esp+30h] [ebp-2Ch]
  unsigned int v90; // [esp+34h] [ebp-28h]
  unsigned int v91; // [esp+38h] [ebp-24h]
  unsigned int v92; // [esp+3Ch] [ebp-20h]
  unsigned int v93; // [esp+40h] [ebp-1Ch]
  unsigned int v94; // [esp+44h] [ebp-18h]
  unsigned int v95; // [esp+48h] [ebp-14h]
  unsigned int v96; // [esp+4Ch] [ebp-10h]
  unsigned int v97; // [esp+50h] [ebp-Ch]
  unsigned int v98; // [esp+54h] [ebp-8h]
  unsigned int v99; // [esp+58h] [ebp-4h]
  unsigned int v100; // [esp+64h] [ebp+8h]

  v3 = key[3] | ((key[2] | ((key[1] | (*key << 8)) << 8)) << 8);
  *state1 = v3;
  state1[1] = key[7] | ((key[6] | ((key[5] | (key[4] << 8)) << 8)) << 8);
  state1[2] = key[11] | ((key[10] | ((key[9] | (key[8] << 8)) << 8)) << 8);
  state1[3] = key[15] | ((key[14] | ((key[13] | (key[12] << 8)) << 8)) << 8);
  state1[4] = ~v3;
  state1[5] = ~state1[1];
  state1[6] = ~state1[2];
  state1[7] = ~state1[3];
  v4 = *state1;
  state1[9] = state1[1];
  state1[10] = state1[2];
  state1[11] = state1[3];
  state1[8] = v4;
  state1[12] = ~v4;
  state1[13] = ~state1[1];
  state1[14] = ~state1[2];
  state1[15] = ~state1[3];
  v100 = *state1;
  v5 = 0;
  v6 = state1[10];
  v7 = 0;
  v99 = state1[1];
  v98 = state1[2];
  v97 = state1[3];
  v96 = state1[8];
  v95 = state1[9];
  v89 = state1[11];
  v93 = state1[4];
  v92 = state1[5];
  v82 = state1[13];
  v85 = v82;
  v88 = state1[6];
  v90 = state1[14];
  v91 = state1[7];
  v8 = state1[15];
  v94 = v6;
  v83 = 0;
  v77 = 0;
  v87 = state1[12];
  v76 = 2;
  while ( 1 )
  {
    v9 = v77 + v6;
    v86 = v7 ^ (v100 + v5) ^ v82 ^ (v8 << 8) ^ (v93 >> 8) ^ SosemanukDivTable[(unsigned char)v93] ^ SosemanukMulTable[HIBYTE(v8)];
    v10 = AesLookupTableA0[(unsigned char)v83] ^ AesLookupTableA3[HIBYTE(v83)] ^ AesLookupTableA1[BYTE1(v83)] ^ AesLookupTableA2[BYTE2(v83)];
    v11 = v87 ^ (v97 >> 8) ^ (v90 << 8) ^ (v9 + v86) ^ SosemanukDivTable[(unsigned char)v97] ^ SosemanukMulTable[HIBYTE(v90)];
    v90 = v10 ^ v11;
    v12 = AesLookupTableA0[(unsigned char)v9] ^ AesLookupTableA3[HIBYTE(v9)] ^ AesLookupTableA1[BYTE1(v9)] ^ AesLookupTableA2[BYTE2(v9)];
    v13 = v12 + v96;
    v85 = v12 ^ (v10 + v95 + (v10 ^ v11)) ^ (v98 >> 8) ^ (v85 << 8) ^ SosemanukDivTable[(unsigned char)v98] ^ SosemanukMulTable[v85 >> 24] ^ v89;
    v14 = AesLookupTableA0[(unsigned char)(v10 + v95)] ^ AesLookupTableA3[(v10 + v95) >> 24] ^ AesLookupTableA1[(unsigned char)((unsigned short)(v10 + v95) >> 8)] ^ AesLookupTableA2[(unsigned char)((v10 + v95) >> 16)];
    v78 = v14 + v91;
    v87 = v14 ^ (v13 + v85) ^ v94 ^ (v99 >> 8) ^ (v87 << 8) ^ SosemanukDivTable[(unsigned char)v99] ^ SosemanukMulTable[v87 >> 24];
    v15 = v14 + v91 + v87;
    v16 = AesLookupTableA2[BYTE2(v13)];
    state1[18] = v78;
    v17 = AesLookupTableA0[(unsigned char)v13] ^ AesLookupTableA3[HIBYTE(v13)] ^ AesLookupTableA1[BYTE1(v13)] ^ v16;
    v18 = v17 + v88;
    v89 = v17 ^ v15 ^ v95 ^ (v100 >> 8) ^ (v89 << 8) ^ SosemanukDivTable[(unsigned char)v100] ^ SosemanukMulTable[v89 >> 24];
    v19 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[(unsigned char)v78] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v20 = *((unsigned char *)state1 + 74);
    v21 = SosemanukMulTable[HIBYTE(v94)];
    state1[18] = v18;
    v22 = AesLookupTableA2[v20] ^ v19;
    v94 = v22 ^ (v18 + v89) ^ v96 ^ (v94 << 8) ^ (v86 >> 8) ^ SosemanukDivTable[(unsigned char)v86] ^ v21;
    v23 = (unsigned char)v18;
    v24 = v22 + v92;
    v25 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v23] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v26 = *((unsigned char *)state1 + 74);
    state1[18] = v24;
    v27 = AesLookupTableA2[v26] ^ v25;
    v79 = v27 + v93;
    v95 = v27 ^ (v24 + v94) ^ v91 ^ (v95 << 8) ^ (v90 >> 8) ^ SosemanukDivTable[(unsigned char)v90] ^ SosemanukMulTable[HIBYTE(v95)];
    v28 = (unsigned char)v24;
    *(unsigned char*)&v24 = v27 + v93;
    v29 = v27 + v93 + v95;
    v30 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v28] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v31 = *((unsigned char *)state1 + 74);
    state1[18] = v79;
    v32 = AesLookupTableA2[v31] ^ v30;
    v96 = v32 ^ v29 ^ v88 ^ (v96 << 8) ^ (v85 >> 8) ^ SosemanukDivTable[(unsigned char)v85] ^ SosemanukMulTable[HIBYTE(v96)];
    v33 = (unsigned char)v24;
    v34 = v32 + v97;
    v35 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v33] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v36 = *((unsigned char *)state1 + 74);
    v37 = SosemanukMulTable[HIBYTE(v91)];
    state1[18] = v34;
    v38 = AesLookupTableA2[v36] ^ v35;
    v91 = v38 ^ (v34 + v96) ^ v92 ^ (v87 >> 8) ^ (v91 << 8) ^ SosemanukDivTable[(unsigned char)v87] ^ v37;
    v39 = (unsigned char)v34;
    v40 = v38 + v98;
    v41 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v39] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v42 = *((unsigned char *)state1 + 74);
    state1[18] = v40;
    v43 = AesLookupTableA2[v42] ^ v41;
    v80 = v43 + v99;
    v88 = v43 ^ (v40 + v91) ^ v93 ^ (v88 << 8) ^ (v89 >> 8) ^ SosemanukDivTable[(unsigned char)v89] ^ SosemanukMulTable[HIBYTE(v88)];
    v44 = (unsigned char)v40;
    v45 = v43 + v99;
    v46 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v44] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v47 = *((unsigned char *)state1 + 74);
    state1[18] = v80;
    v48 = AesLookupTableA2[v47] ^ v46;
    v92 = v97 ^ v48 ^ (v45 + v88) ^ (v94 >> 8) ^ (v92 << 8) ^ SosemanukDivTable[(unsigned char)v94] ^ SosemanukMulTable[HIBYTE(v92)];
    v49 = (unsigned char)v45;
    v50 = v48 + v100;
    v51 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v49] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v52 = *((unsigned char *)state1 + 74);
    state1[18] = v50;
    v53 = AesLookupTableA2[v52] ^ v51;
    v81 = v53 + v86;
    v93 = v98 ^ v53 ^ (v50 + v92) ^ (v93 << 8) ^ (v95 >> 8) ^ SosemanukDivTable[(unsigned char)v95] ^ SosemanukMulTable[HIBYTE(v93)];
    v54 = (unsigned char)v50;
    *(unsigned char*)&v50 = v53 + v86;
    v55 = v53 + v86 + v93;
    v56 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v54] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v57 = *((unsigned char *)state1 + 74);
    state1[18] = v81;
    v58 = AesLookupTableA2[v57] ^ v56;
    v97 = v99 ^ v58 ^ v55 ^ (v97 << 8) ^ (v96 >> 8) ^ SosemanukDivTable[(unsigned char)v96] ^ SosemanukMulTable[HIBYTE(v97)];
    v59 = (unsigned char)v50;
    v60 = v58 + v90;
    v61 = v58 + v90 + v97;
    v62 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[v59] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v63 = *((unsigned char *)state1 + 74);
    v64 = SosemanukMulTable[HIBYTE(v98)];
    state1[18] = v60;
    v65 = AesLookupTableA2[v63] ^ v62;
    v82 = v85;
    v98 = v100 ^ v65 ^ v61 ^ (v91 >> 8) ^ (v98 << 8) ^ SosemanukDivTable[(unsigned char)v91] ^ v64;
    v84 = v85 + v65;
    v66 = SosemanukMulTable[HIBYTE(v99)];
    v67 = AesLookupTableA2[*((unsigned char *)state1 + 74)] ^ AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[(unsigned char)v60] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    state1[18] = v84;
    *(unsigned char*)&v60 = v67 + v87;
    v99 = v67 ^ (v84 + v98) ^ v86 ^ (v99 << 8) ^ (v88 >> 8) ^ SosemanukDivTable[(unsigned char)v88] ^ v66;
    v68 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[(unsigned char)v84] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v69 = *((unsigned char *)state1 + 74);
    state1[18] = v67 + v87;
    v70 = AesLookupTableA2[v69] ^ v68;
    v75 = v70 ^ (v67 + v87 + v99);
    v83 = v70 + v89;
    v5 = v70 + v89;
    v100 = v75 ^ v90 ^ (v100 << 8) ^ (v92 >> 8) ^ SosemanukDivTable[(unsigned char)v92] ^ SosemanukMulTable[HIBYTE(v100)];
    v71 = AesLookupTableA1[*((unsigned char *)state1 + 73)] ^ AesLookupTableA0[(unsigned char)v60] ^ AesLookupTableA3[*((unsigned char *)state1 + 75)];
    v72 = *((unsigned char *)state1 + 74);
    state1[18] = v5;
    v7 = AesLookupTableA2[v72] ^ v71;
    v73 = v76-- == 1;
    v77 = v7;
    if ( v73 )
      break;
    v8 = v86;
    v6 = v94;
  }
  *state1 = v100;
  state1[1] = v99;
  state1[2] = v98;
  state1[3] = v97;
  state1[8] = v96;
  state1[9] = v95;
  state1[10] = v94;
  state1[11] = v89;
  state1[4] = v93;
  state1[5] = v92;
  state1[6] = v88;
  state1[7] = v91;
  state1[16] = v75;
  state1[15] = v86;
  state1[13] = v85;
  state1[17] = v5;
  state1[19] = v7;
  state1[14] = v90;
  result = v87;
  state1[12] = v87;
  return result;
}

int c_update_enc_state(int *state1, int *out_stream)
{
  unsigned int v3; // esi
  unsigned int v4; // edx
  unsigned int v5; // edi
  int v6; // esi
  int v7; // ecx
  int v8; // ecx
  unsigned int v9; // edi
  int v10; // esi
  int v11; // ecx
  int v12; // eax
  unsigned int v13; // edi
  int v14; // esi
  unsigned int v15; // edx
  int v16; // ecx
  int v17; // eax
  int *v18; // edx
  unsigned int v19; // edi
  unsigned int v20; // ecx
  int v21; // eax
  int v22; // ecx
  int v23; // eax
  int v24; // eax
  int v25; // edi
  int *v26; // esi
  int v27; // eax
  int v28; // ecx
  int v29; // edi
  int v30; // edx
  int v31; // eax
  int v32; // eax
  int *v33; // edi
  int v34; // ecx
  int v35; // esi
  int v36; // eax
  int v37; // edx
  int v38; // eax
  int v39; // eax
  int v40; // ecx
  int v41; // esi
  int v42; // eax
  int v43; // edx
  int v44; // eax
  int v45; // eax
  int v46; // esi
  int v47; // ecx
  int v48; // eax
  int v49; // esi
  int v50; // edx
  int v51; // eax
  int v52; // ecx
  int v53; // esi
  int v54; // eax
  int v55; // edx
  int v56; // eax
  int v57; // eax
  int v58; // ecx
  int v59; // esi
  int v60; // eax
  int v61; // edx
  int v62; // eax
  int v63; // ecx
  int v64; // esi
  int v65; // eax
  int v66; // edx
  int v67; // eax
  int v68; // eax
  int v69; // ecx
  int v70; // esi
  int v71; // eax
  int v72; // edx
  int v73; // eax
  int v74; // esi
  int v75; // edx
  int v76; // eax
  int v77; // ecx
  int v78; // esi
  int v79; // eax
  int v80; // edx
  int v81; // eax
  int v82; // ecx
  int v83; // esi
  int v84; // eax
  int v85; // edx
  int v86; // eax
  int v87; // ecx
  int v88; // esi
  int v89; // eax
  int v90; // edx
  int v91; // eax
  int result; // eax

  v3 = state1[15];
  v4 = state1[18];
  v5 = state1[13] ^ (v3 << 8) ^ ((unsigned int)state1[4] >> 8) ^ SosemanukDivTable[(unsigned char)state1[4]] ^ SosemanukMulTable[HIBYTE(v3)];
  v6 = state1[19] + state1[10];
  v7 = AesLookupTableA2[BYTE2(v4)];
  state1[18] = v6;
  state1[15] = v5;
  v8 = AesLookupTableA0[(unsigned char)v4] ^ AesLookupTableA3[HIBYTE(v4)] ^ AesLookupTableA1[BYTE1(v4)] ^ v7;
  state1[19] = v8;
  *out_stream = state1[14] ^ v8 ^ (v6 + v5);
  v9 = state1[12] ^ (state1[14] << 8) ^ ((unsigned int)state1[3] >> 8) ^ SosemanukDivTable[(unsigned char)state1[3]] ^ SosemanukMulTable[HIBYTE(state1[14])];
  v10 = state1[19] + state1[9];
  state1[14] = v9;
  v11 = AesLookupTableA0[(unsigned char)state1[18]] ^ AesLookupTableA3[HIBYTE(state1[18])] ^ AesLookupTableA1[(unsigned char)BYTE1(state1[18])] ^ AesLookupTableA2[(unsigned char)BYTE2(state1[18])];
  state1[18] = v10;
  v12 = state1[13] ^ v11 ^ (v10 + v9);
  state1[19] = v11;
  out_stream[1] = v12;
  v13 = state1[11] ^ (state1[13] << 8) ^ ((unsigned int)state1[2] >> 8) ^ SosemanukDivTable[(unsigned char)state1[2]] ^ SosemanukMulTable[HIBYTE(state1[13])];
  v14 = state1[19] + state1[8];
  v15 = state1[18];
  state1[13] = v13;
  v16 = AesLookupTableA0[(unsigned char)v15] ^ AesLookupTableA3[HIBYTE(v15)] ^ AesLookupTableA1[BYTE1(v15)] ^ AesLookupTableA2[BYTE2(v15)];
  state1[19] = v16;
  v17 = state1[12] ^ v16 ^ (v13 + v14);
  state1[18] = v14;
  out_stream[2] = v17;
  v18 = state1;
  v19 = state1[10] ^ (state1[12] << 8) ^ ((unsigned int)state1[1] >> 8) ^ SosemanukDivTable[(unsigned char)state1[1]] ^ SosemanukMulTable[HIBYTE(state1[12])];
  state1[17] = state1[7] + state1[19];
  v20 = HIBYTE(state1[18]);
  v21 = (unsigned char)state1[18];
  state1[12] = v19;
  v22 = AesLookupTableA2[*((unsigned char *)v18 + 74)] ^ AesLookupTableA1[*((unsigned char *)v18 + 73)] ^ AesLookupTableA0[v21] ^ AesLookupTableA3[v20];
  v23 = state1[17];
  state1[18] = v23;
  v24 = v22 ^ state1[11] ^ (v19 + v23);
  state1[19] = v22;
  out_stream[3] = v24;
  v25 = (v18[11] << 8) ^ ((unsigned int)*v18 >> 8) ^ SosemanukDivTable[(unsigned char)*v18] ^ SosemanukMulTable[HIBYTE(v18[11])];
  v26 = state1;
  state1[17] = state1[19] + state1[6];
  v27 = *((unsigned char *)state1 + 72);
  v28 = *((unsigned char *)state1 + 75);
  v29 = state1[9] ^ v25;
  state1[11] = v29;
  v30 = AesLookupTableA2[*((unsigned char *)v26 + 74)] ^ AesLookupTableA1[*((unsigned char *)v26 + 73)] ^ AesLookupTableA3[v28] ^ AesLookupTableA0[v27];
  v31 = state1[17];
  state1[18] = v31;
  v32 = v29 + v31;
  v33 = state1;
  state1[19] = v30;
  out_stream[4] = state1[19] ^ state1[10] ^ v32;
  v34 = *((unsigned char *)state1 + 75);
  v35 = v33[8] ^ (v33[10] << 8) ^ ((unsigned int)v26[15] >> 8) ^ SosemanukDivTable[(unsigned char)v26[15]] ^ SosemanukMulTable[*((unsigned char *)v26 + 43)];
  state1[17] = state1[5] + state1[19];
  v36 = *((unsigned char *)state1 + 72);
  state1[10] = v35;
  v37 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v34] ^ AesLookupTableA0[v36];
  v38 = state1[17];
  state1[18] = v38;
  v39 = v37 ^ state1[9] ^ (v35 + v38);
  state1[19] = v37;
  out_stream[5] = v39;
  v40 = *((unsigned char *)state1 + 75);
  v41 = v33[7] ^ (v33[9] << 8) ^ ((unsigned int)v33[14] >> 8) ^ SosemanukDivTable[(unsigned char)v33[14]] ^ SosemanukMulTable[*((unsigned char *)v33 + 39)];
  state1[17] = state1[19] + state1[4];
  v42 = *((unsigned char *)state1 + 72);
  state1[9] = v41;
  v43 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v40] ^ AesLookupTableA0[v42];
  v44 = state1[17];
  state1[18] = v44;
  v45 = v43 ^ state1[8] ^ (v41 + v44);
  state1[19] = v43;
  out_stream[6] = v45;
  v46 = (v33[8] << 8) ^ ((unsigned int)v33[13] >> 8) ^ SosemanukDivTable[(unsigned char)v33[13]] ^ SosemanukMulTable[*((unsigned char *)v33 + 35)];
  v47 = *((unsigned char *)state1 + 75);
  state1[17] = state1[3] + state1[19];
  v48 = *((unsigned char *)state1 + 72);
  v49 = state1[6] ^ v46;
  state1[8] = v49;
  v50 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v47] ^ AesLookupTableA0[v48];
  v51 = state1[17];
  state1[18] = v51;
  state1[19] = v50;
  out_stream[7] = state1[7] ^ v50 ^ (v49 + v51);
  v52 = *((unsigned char *)state1 + 75);
  v53 = v33[5] ^ (v33[7] << 8) ^ ((unsigned int)v33[12] >> 8) ^ SosemanukDivTable[(unsigned char)v33[12]] ^ SosemanukMulTable[*((unsigned char *)v33 + 31)];
  state1[17] = state1[2] + state1[19];
  v54 = *((unsigned char *)state1 + 72);
  state1[7] = v53;
  v55 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v52] ^ AesLookupTableA0[v54];
  v56 = state1[17];
  state1[18] = v56;
  v57 = v55 ^ state1[6] ^ (v53 + v56);
  state1[19] = v55;
  out_stream[8] = v57;
  v58 = *((unsigned char *)state1 + 75);
  v59 = v33[4] ^ (v33[6] << 8) ^ ((unsigned int)v33[11] >> 8) ^ SosemanukDivTable[(unsigned char)v33[11]] ^ SosemanukMulTable[*((unsigned char *)v33 + 27)];
  state1[17] = state1[1] + state1[19];
  v60 = *((unsigned char *)state1 + 72);
  state1[6] = v59;
  v61 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v58] ^ AesLookupTableA0[v60];
  v62 = state1[17];
  state1[18] = v62;
  state1[19] = v61;
  out_stream[9] = state1[5] ^ v61 ^ (v59 + v62);
  v63 = *((unsigned char *)state1 + 75);
  v64 = v33[3] ^ (v33[5] << 8) ^ ((unsigned int)v33[10] >> 8) ^ SosemanukDivTable[(unsigned char)v33[10]] ^ SosemanukMulTable[*((unsigned char *)v33 + 23)];
  state1[17] = *state1 + state1[19];
  v65 = *((unsigned char *)state1 + 72);
  state1[5] = v64;
  v66 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v63] ^ AesLookupTableA0[v65];
  v67 = state1[17];
  state1[18] = v67;
  v68 = v66 ^ state1[4] ^ (v64 + v67);
  state1[19] = v66;
  out_stream[10] = v68;
  v69 = *((unsigned char *)state1 + 75);
  v70 = v33[2] ^ (v33[4] << 8) ^ ((unsigned int)v33[9] >> 8) ^ SosemanukDivTable[(unsigned char)v33[9]] ^ SosemanukMulTable[*((unsigned char *)v33 + 19)];
  state1[17] = state1[15] + state1[19];
  v71 = *((unsigned char *)state1 + 72);
  state1[4] = v70;
  v72 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v69] ^ AesLookupTableA0[v71];
  v73 = state1[17];
  state1[18] = v73;
  state1[19] = v72;
  out_stream[11] = state1[3] ^ v72 ^ (v70 + v73);
  v74 = v33[1] ^ (v33[3] << 8) ^ ((unsigned int)v33[8] >> 8) ^ SosemanukDivTable[(unsigned char)v33[8]] ^ SosemanukMulTable[*((unsigned char *)v33 + 15)];
  state1[3] = v74;
  state1[17] = state1[14] + state1[19];
  v75 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[*((unsigned char *)v33 + 75)] ^ AesLookupTableA0[*((unsigned char *)v33 + 72)];
  v76 = state1[17];
  state1[18] = v76;
  state1[19] = v75;
  out_stream[12] = state1[2] ^ v75 ^ (v74 + v76);
  v77 = *((unsigned char *)state1 + 75);
  v78 = *v33 ^ (v33[2] << 8) ^ ((unsigned int)v33[7] >> 8) ^ SosemanukDivTable[(unsigned char)v33[7]] ^ SosemanukMulTable[*((unsigned char *)v33 + 11)];
  state1[17] = state1[13] + state1[19];
  v79 = *((unsigned char *)state1 + 72);
  state1[2] = v78;
  v80 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v77] ^ AesLookupTableA0[v79];
  v81 = state1[17];
  state1[18] = v81;
  state1[19] = v80;
  out_stream[13] = state1[1] ^ v80 ^ (v78 + v81);
  v82 = *((unsigned char *)state1 + 75);
  v83 = v33[15] ^ (v33[1] << 8) ^ ((unsigned int)v33[6] >> 8) ^ SosemanukDivTable[(unsigned char)v33[6]] ^ SosemanukMulTable[*((unsigned char *)v33 + 7)];
  state1[17] = state1[19] + state1[12];
  v84 = *((unsigned char *)state1 + 72);
  state1[1] = v83;
  v85 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v82] ^ AesLookupTableA0[v84];
  v86 = state1[17];
  state1[18] = v86;
  state1[19] = v85;
  out_stream[14] = *state1 ^ v85 ^ (v83 + v86);
  v87 = *((unsigned char *)state1 + 75);
  v88 = v33[14] ^ ((unsigned int)v33[5] >> 8) ^ (*v33 << 8) ^ SosemanukDivTable[(unsigned char)v33[5]] ^ SosemanukMulTable[*((unsigned char *)v33 + 3)];
  state1[17] = state1[19] + state1[11];
  v89 = *((unsigned char *)state1 + 72);
  *state1 = v88;
  v90 = AesLookupTableA2[*((unsigned char *)v33 + 74)] ^ AesLookupTableA1[*((unsigned char *)v33 + 73)] ^ AesLookupTableA3[v87] ^ AesLookupTableA0[v89];
  v91 = state1[17];
  state1[18] = v91;
  state1[19] = v90;
  result = state1[15] ^ v90 ^ (v88 + v91);
  out_stream[15] = result;
  return result;
}
