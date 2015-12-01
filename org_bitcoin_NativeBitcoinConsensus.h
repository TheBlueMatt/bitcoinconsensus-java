/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_bitcoin_NativeBitcoinConsensus */

#ifndef _Included_org_bitcoin_NativeBitcoinConsensus
#define _Included_org_bitcoin_NativeBitcoinConsensus
#ifdef __cplusplus
extern "C" {
#endif
#undef org_bitcoin_NativeBitcoinConsensus_P2SH
#define org_bitcoin_NativeBitcoinConsensus_P2SH 1L
#undef org_bitcoin_NativeBitcoinConsensus_DERSIG
#define org_bitcoin_NativeBitcoinConsensus_DERSIG 2L
#undef org_bitcoin_NativeBitcoinConsensus_CHECKLOCKTIMEVERIFY
#define org_bitcoin_NativeBitcoinConsensus_CHECKLOCKTIMEVERIFY 4L
/*
 * Class:     org_bitcoin_NativeBitcoinConsensus
 * Method:    consensus_script_verify
 * Signature: (Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_bitcoin_NativeBitcoinConsensus_consensus_1script_1verify
  (JNIEnv *, jclass, jobject, jobject, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
