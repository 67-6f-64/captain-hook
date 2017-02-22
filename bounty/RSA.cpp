#include "RSA.h"

//TODO:  add cryptopp to support these...
#include <rsa.h>
#include <randpool.h>
#include <filters.h>


CRSA::CRSA()
{
}


CRSA::~CRSA()
{
}

void CRSA::GenerateKey(BYTE seed[], size_t seedLen, size_t keyLen)
{
	CryptoPP::RandomPool randomPool;
	randomPool.Put(seed, seedLen);

	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(randomPool, 1024);
	CryptoPP::ArraySink decArr(privateKey, privateKeyLen);
	decryptor.DEREncode(decArr);
	decArr.MessageEnd();
	privateKeyLen = decArr.TotalPutLength();

	CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(decryptor);
	CryptoPP::ArraySink encArr(publicKey, publicKeyLen);
	encryptor.DEREncode(encArr);
	encArr.MessageEnd();
	publicKeyLen = encArr.TotalPutLength();
}

void CRSA::Encrypt(BYTE seed[], size_t seedLen, 
				   BYTE publicKey[], size_t publicKeyLen, 
				   BYTE plainData[], size_t plainDataLen, 
				   BYTE cipherData[], size_t& cipherDataLen)
{
	CryptoPP::ArraySource keyArr(publicKey, publicKeyLen, true);
	CryptoPP::RSAES_OAEP_SHA_Encryptor enc;
	enc.AccessKey().Load(keyArr);

	CryptoPP::RandomPool randomPool;
	randomPool.Put(seed, seedLen);

	size_t putLen = 0;
	size_t fixedLen = enc.FixedMaxPlaintextLength();
	for (size_t i = 0; i < plainDataLen; i += fixedLen)
	{
		size_t len = fixedLen < (plainDataLen - i) ? fixedLen : (plainDataLen - i);
		CryptoPP::ArraySink *dstArr = new CryptoPP::ArraySink(cipherData + putLen, cipherDataLen - putLen);
		CryptoPP::ArraySource source(plainData + i, len, true, new CryptoPP::PK_EncryptorFilter(randomPool, enc, dstArr));
		putLen += dstArr->TotalPutLength();
	}
	cipherDataLen = putLen;
}

void CRSA::Decrypt(BYTE seed[], size_t seedLen, 
				   BYTE publicKey[], size_t publicKeyLen, 
				   BYTE cipherData[], size_t cipherDataLen, 
				   BYTE plainData[], size_t& plainDataLen)
{
	CryptoPP::ArraySource keyArr(privateKey, privateKeyLen, true);
	CryptoPP::RSAES_OAEP_SHA_Decryptor dec;
	dec.AccessKey().Load(keyArr);

	CryptoPP::RandomPool randomPool;
	randomPool.Put(seed, seedLen);

	size_t putLen = 0;
	size_t fixedLen = dec.FixedCiphertextLength();
	for (size_t i = 0; i < cipherDataLen; i += fixedLen)
	{
		size_t len = fixedLen < (cipherDataLen - i) ? fixedLen : (cipherDataLen - i);
		CryptoPP::ArraySink *dstArr = new CryptoPP::ArraySink(plainData + putLen, plainDataLen - putLen);
		CryptoPP::ArraySource source(cipherData + i, len, true, new CryptoPP::PK_DecryptorFilter(randomPool, dec, dstArr));
		putLen += dstArr->TotalPutLength();
	}
	plainDataLen = putLen;
}
