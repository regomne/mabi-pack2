/* ecrypt-sync.h */

/* 
 * Header file for synchronous stream ciphers without authentication
 * mechanism.
 * 
 * *** Please only edit parts marked with "[edit]". ***
 */

#ifndef Snow2_SYNC
#define Snow2_SYNC

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;
typedef unsigned long long u64;

/* ------------------------------------------------------------------------- */

/* Cipher parameters */

/* 
 * The name of your cipher.
 */
#define Snow2_NAME "SNOW-2.0"                 /* [edit] */ 
#define Snow2_PROFILE "bench"

/*
 * Specify which key and IV sizes are supported by your cipher. A user
 * should be able to enumerate the supported sizes by running the
 * following code:
 *
 * for (i = 0; Snow2_KEYSIZE(i) <= Snow2_MAXKEYSIZE; ++i)
 *   {
 *     keysize = Snow2_KEYSIZE(i);
 *
 *     ...
 *   }
 *
 * All sizes are in bits.
 */

#define Snow2_MAXKEYSIZE 256                  /* [edit] */
#define Snow2_KEYSIZE(i) (128 + (i)*128)      /* [edit] */

#define Snow2_MAXIVSIZE 128                   /* [edit] */
#define Snow2_IVSIZE(i) (128 + (i)*32)        /* [edit] */

/* ------------------------------------------------------------------------- */

/* Data structures */

/* 
 * Snow2_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
  u32 keysize;
  s8 key[32]; /* MODIFIED in Mabinogi, original type is u8 */

  u32 s15, s14, s13, s12, s11, s10, s9, s8, s7, s6, s5, s4, s3, s2, s1, s0;
  u32 r1, r2; 
} Snow2_ctx;

/* ------------------------------------------------------------------------- */

/* Mandatory functions */

/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void Snow2_init(void);

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void Snow2_keysetup(
  Snow2_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called Snow2_keysetup(), the user is
 * allowed to call Snow2_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void Snow2_ivsetup(
  Snow2_ctx* ctx, 
  const u8* iv);

/*
 * Encryption/decryption of arbitrary length messages.
 *
 * For efficiency reasons, the API provides two types of
 * encrypt/decrypt functions. The Snow2_encrypt_bytes() function
 * (declared here) encrypts byte strings of arbitrary length, while
 * the Snow2_encrypt_blocks() function (defined later) only accepts
 * lengths which are multiples of Snow2_BLOCKLENGTH.
 * 
 * The user is allowed to make multiple calls to
 * Snow2_encrypt_blocks() to incrementally encrypt a long message,
 * but he is NOT allowed to make additional encryption calls once he
 * has called Snow2_encrypt_bytes() (unless he starts a new message
 * of course). For example, this sequence of calls is acceptable:
 *
 * Snow2_keysetup();
 *
 * Snow2_ivsetup();
 * Snow2_encrypt_blocks();
 * Snow2_encrypt_blocks();
 * Snow2_encrypt_bytes();
 *
 * Snow2_ivsetup();
 * Snow2_encrypt_blocks();
 * Snow2_encrypt_blocks();
 *
 * Snow2_ivsetup();
 * Snow2_encrypt_bytes();
 * 
 * The following sequence is not:
 *
 * Snow2_keysetup();
 * Snow2_ivsetup();
 * Snow2_encrypt_blocks();
 * Snow2_encrypt_bytes();
 * Snow2_encrypt_blocks();
 */

/*
 * By default Snow2_encrypt_bytes() and Snow2_decrypt_bytes() are
 * defined as macros which redirect the call to a single function
 * Snow2_process_bytes(). If you want to provide separate encryption
 * and decryption functions, please undef
 * Snow2_HAS_SINGLE_BYTE_FUNCTION.
 */
#define Snow2_HAS_SINGLE_BYTE_FUNCTION       /* [edit] */
#ifdef Snow2_HAS_SINGLE_BYTE_FUNCTION

#define Snow2_encrypt_bytes(ctx, plaintext, ciphertext, msglen)   \
  Snow2_process_bytes(0, ctx, plaintext, ciphertext, msglen)

#define Snow2_decrypt_bytes(ctx, ciphertext, plaintext, msglen)   \
  Snow2_process_bytes(1, ctx, ciphertext, plaintext, msglen)

void Snow2_process_bytes(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  Snow2_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 msglen);                /* Message length in bytes. */ 

#else

void Snow2_encrypt_bytes(
  Snow2_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void Snow2_decrypt_bytes(
  Snow2_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* Message length in bytes. */ 

#endif

/* ------------------------------------------------------------------------- */

/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext. If your cipher cannot provide this function
 * (e.g., because it is not strictly a synchronous cipher), please
 * reset the Snow2_GENERATES_KEYSTREAM flag.
 */

#define Snow2_GENERATES_KEYSTREAM
#ifdef Snow2_GENERATES_KEYSTREAM

void Snow2_keystream_bytes(
  Snow2_ctx* ctx,
  u8* keystream,
  u32 length);                /* Length of keystream in bytes. */

#endif

/* ------------------------------------------------------------------------- */

/* Optional optimizations */

/* 
 * By default, the functions in this section are implemented using
 * calls to functions declared above. However, you might want to
 * implement them differently for performance reasons.
 */

/*
 * All-in-one encryption/decryption of (short) packets.
 *
 * The default definitions of these functions can be found in
 * "ecrypt-sync.c". If you want to implement them differently, please
 * undef the Snow2_USES_DEFAULT_ALL_IN_ONE flag.
 */
#define Snow2_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

/*
 * Undef Snow2_HAS_SINGLE_PACKET_FUNCTION if you want to provide
 * separate packet encryption and decryption functions.
 */
#define Snow2_HAS_SINGLE_PACKET_FUNCTION     /* [edit] */
#ifdef Snow2_HAS_SINGLE_PACKET_FUNCTION

#define Snow2_encrypt_packet(                                        \
    ctx, iv, plaintext, ciphertext, mglen)                            \
  Snow2_process_packet(0,                                            \
    ctx, iv, plaintext, ciphertext, mglen)

#define Snow2_decrypt_packet(                                        \
    ctx, iv, ciphertext, plaintext, mglen)                            \
  Snow2_process_packet(1,                                            \
    ctx, iv, ciphertext, plaintext, mglen)

void Snow2_process_packet(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  Snow2_ctx* ctx, 
  const u8* iv,
  const u8* input, 
  u8* output, 
  u32 msglen);

#else

void Snow2_encrypt_packet(
  Snow2_ctx* ctx, 
  const u8* iv,
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);

void Snow2_decrypt_packet(
  Snow2_ctx* ctx, 
  const u8* iv,
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);

#endif

/*
 * Encryption/decryption of blocks.
 * 
 * By default, these functions are defined as macros. If you want to
 * provide a different implementation, please undef the
 * Snow2_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
 * declared below.
 */

#define Snow2_BLOCKLENGTH 64                 /* [edit] */

#define Snow2_USES_DEFAULT_BLOCK_MACROS      /* [edit] */
#ifdef Snow2_USES_DEFAULT_BLOCK_MACROS

#define Snow2_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
  Snow2_encrypt_bytes(ctx, plaintext, ciphertext,                 \
    (blocks) * Snow2_BLOCKLENGTH)

#define Snow2_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
  Snow2_decrypt_bytes(ctx, ciphertext, plaintext,                 \
    (blocks) * Snow2_BLOCKLENGTH)

#ifdef Snow2_GENERATES_KEYSTREAM

#define Snow2_keystream_blocks(ctx, keystream, blocks)            \
  Snow2_keystream_bytes(ctx, keystream,                           \
    (blocks) * Snow2_BLOCKLENGTH)

#endif

#else

/*
 * Undef Snow2_HAS_SINGLE_BLOCK_FUNCTION if you want to provide
 * separate block encryption and decryption functions.
 */
#define Snow2_HAS_SINGLE_BLOCK_FUNCTION      /* [edit] */
#ifdef Snow2_HAS_SINGLE_BLOCK_FUNCTION

#define Snow2_encrypt_blocks(ctx, plaintext, ciphertext, blocks)     \
  Snow2_process_blocks(0, ctx, plaintext, ciphertext, blocks)

#define Snow2_decrypt_blocks(ctx, ciphertext, plaintext, blocks)     \
  Snow2_process_blocks(1, ctx, ciphertext, plaintext, blocks)

void Snow2_process_blocks(
  int action,                 /* 0 = encrypt; 1 = decrypt; */
  Snow2_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 blocks);                /* Message length in blocks. */

#else

void Snow2_encrypt_blocks(
  Snow2_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 blocks);                /* Message length in blocks. */ 

void Snow2_decrypt_blocks(
  Snow2_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 blocks);                /* Message length in blocks. */ 

#endif

#ifdef Snow2_GENERATES_KEYSTREAM

void Snow2_keystream_blocks(
  Snow2_ctx* ctx,
  u8* keystream,
  u32 blocks);                /* Keystream length in blocks. */ 

#endif

#endif

/*
 * If your cipher can be implemented in different ways, you can use
 * the Snow2_VARIANT parameter to allow the user to choose between
 * them at compile time (e.g., gcc -DSnow2_VARIANT=3 ...). Please
 * only use this possibility if you really think it could make a
 * significant difference and keep the number of variants
 * (Snow2_MAXVARIANT) as small as possible (definitely not more than
 * 10). Note also that all variants should have exactly the same
 * external interface (i.e., the same Snow2_BLOCKLENGTH, etc.). 
 */
#define Snow2_MAXVARIANT 1                   /* [edit] */

#ifndef Snow2_VARIANT
#define Snow2_VARIANT 1
#endif

#if (Snow2_VARIANT > Snow2_MAXVARIANT)
#error this variant does not exist
#endif

/* ------------------------------------------------------------------------- */

#endif
