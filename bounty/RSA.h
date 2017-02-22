#pragma once
#include <windef.h>

class CRSA
{
public:
	CRSA();

	~CRSA();

	void GenerateKey(BYTE seed[], size_t seedLen, size_t keyLen);

	void Encrypt(BYTE seed[], size_t seedLen,
				 BYTE publicKey[], size_t publicKeyLen, 
				 BYTE plainData[], size_t plainDataLen, 
				 BYTE cipherData[], size_t &cipherDataLen
				 );

	void Decrypt(BYTE seed[], size_t seedLen,
		BYTE publicKey[], size_t publicKeyLen,
		BYTE cipherData[], size_t cipherDataLen,
		BYTE plainData[], size_t &plainDataLen
	);
};

