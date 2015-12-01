#include "org_bitcoin_NativeBitcoinConsensus.h"

#include <bitcoinconsensus.h>
#include <string.h>

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeBitcoinConsensus_consensus_1script_1verify
  (JNIEnv* env, jclass classObject, jobject scriptPubKeyBuffer, jobject txToBuffer, jint nIn, jint flags)
{
	int consensus_flags = bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NONE;

	if (flags & org_bitcoin_NativeBitcoinConsensus_P2SH)
		consensus_flags |= bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH;
	if (flags & org_bitcoin_NativeBitcoinConsensus_DERSIG)
		consensus_flags |= bitcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG;
	if (flags & org_bitcoin_NativeBitcoinConsensus_CHECKLOCKTIMEVERIFY)
		consensus_flags |= bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY;
	
	const unsigned char* scriptPubKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, scriptPubKeyBuffer);
	jint scriptPubKeyLen;
	memcpy(&scriptPubKeyLen, scriptPubKey, sizeof(scriptPubKeyLen));
	scriptPubKey += sizeof(scriptPubKeyLen);

	const unsigned char* txTo = (unsigned char*) (*env)->GetDirectBufferAddress(env, txToBuffer);
	jint txToLen;
	memcpy(&txToLen, txTo, sizeof(txToLen));
	txTo += sizeof(txToLen);

	bitcoinconsensus_error err = bitcoinconsensus_ERR_OK;
	if (bitcoinconsensus_verify_script(scriptPubKey, scriptPubKeyLen, txTo, txToLen, nIn, consensus_flags, &err) == 1)
		return 1;
	if (err != bitcoinconsensus_ERR_OK)
		return -1;
	return 0;
}
