//========= Copyright Bernt Andreas Eide, All rights reserved. ============//
//
// Purpose: Simple DES C++ implementation, with bruteforce func.
//
//=============================================================================//

#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <iostream>
#include <chrono>
#include <vector>

using namespace std;

template<class T>
T rotate_bits(const T &n, const T &shift, const uint8_t &num_bits) // Left circular shift.
{
	return ((n << shift) | (n >> (num_bits - shift)));
}

struct uint10_t // Define a 10 bit structure for our keys.
{
	uint16_t value : 10;
	uint16_t _ : 6;
};

struct uint4_t
{
	uint8_t left : 4;
	uint8_t right : 4;
};

struct uint2_t
{
	uint8_t value : 2;
	uint8_t _ : 6;
};

const static uint8_t S0[4][4] = {
	{ 1, 0, 3, 2 },
	{ 3, 2, 1, 0 },
	{ 0, 2, 1, 3 },
	{ 3, 1, 3, 2 }
};

const static uint8_t S1[4][4] = {
	{ 0, 1, 2, 3 },
	{ 2, 0, 1, 3 },
	{ 3, 0, 1, 0 },
	{ 2, 1, 0, 3 }
};

enum BIT_VALUES {
	MASK_BIT_0 = 0x000,
	MASK_BIT_1 = 0x001,
	MASK_BIT_2 = 0x002,
	MASK_BIT_3 = 0x004,
	MASK_BIT_4 = 0x008,
	MASK_BIT_5 = 0x010,
	MASK_BIT_6 = 0x020,
	MASK_BIT_7 = 0x040,
	MASK_BIT_8 = 0x080,
	MASK_BIT_9 = 0x100,
	MASK_BIT_10 = 0x200,
	MASK_BIT_ALL_8 = 0xFF,
	MASK_BIT_ALL_10 = 1023,
};

uint8_t get_ip(const uint8_t &v)
{
	return (
		((MASK_BIT_8 & v) >> 3) |
		((MASK_BIT_7 & v) << 1) |
		((MASK_BIT_6 & v)) |
		((MASK_BIT_5 & v) >> 1) |
		((MASK_BIT_4 & v) >> 2) |
		((MASK_BIT_3 & v) << 4) |
		((MASK_BIT_2 & v) >> 1) |
		((MASK_BIT_1 & v) << 2)
		);
}

uint8_t get_inv_ip(const uint8_t &v)
{
	return (
		((MASK_BIT_8 & v) >> 1) |
		((MASK_BIT_7 & v) >> 4) |
		((MASK_BIT_6 & v)) |
		((MASK_BIT_5 & v) << 3) |
		((MASK_BIT_4 & v) << 1) |
		((MASK_BIT_3 & v) >> 2) |
		((MASK_BIT_2 & v) << 2) |
		((MASK_BIT_1 & v) << 1)
		);
}

uint4_t F(const uint4_t &R, const uint8_t &subkey)
{
	uint4_t result; // right

	result.right = ((MASK_BIT_4 & R.right) >> 1) | ((MASK_BIT_3 & R.right) >> 1) | ((MASK_BIT_2 & R.right) >> 1) | ((MASK_BIT_1 & R.right) << 3); // EP1
	result.left = ((MASK_BIT_4 & R.right) >> 3) | ((MASK_BIT_3 & R.right) << 1) | ((MASK_BIT_2 & R.right) << 1) | ((MASK_BIT_1 & R.right) << 1); // EP2

	result.right = (result.right ^ ((subkey >> 4) & 0xF));
	result.left = (result.left ^ (subkey & 0xF));

	uint2_t v1, v2, v3, v4;

	v1.value = ((MASK_BIT_4 & result.right) >> 2) | (MASK_BIT_1 & result.right);
	v2.value = ((MASK_BIT_3 & result.right) >> 1) | ((MASK_BIT_2 & result.right) >> 1);

	v3.value = ((MASK_BIT_4 & result.left) >> 2) | (MASK_BIT_1 & result.left);
	v4.value = ((MASK_BIT_3 & result.left) >> 1) | ((MASK_BIT_2 & result.left) >> 1);

	result.left = (S0[v1.value][v2.value] << 2) | (S1[v3.value][v4.value]);
	result.left = ((MASK_BIT_4 & result.left) >> 3) | ((MASK_BIT_3 & result.left) << 1) | ((MASK_BIT_2 & result.left)) | ((MASK_BIT_1 & result.left) << 2);
	result.right = result.left;

	return result;
}

uint8_t SW(const uint8_t &v)
{
	return (((v & 0xF0) >> 4) | (((v & 0xF) << 4)));
}

uint8_t FK(const uint8_t &v, const uint8_t &key)
{
	uint4_t tmp;
	tmp.left = ((v >> 4) & 0xF);
	tmp.right = (v & 0xF);

	uint4_t res = F(tmp, key);
	res.right = tmp.left ^ res.right;

	uint8_t out = (((res.right << 4) & 0xF0) | tmp.right);
	return out;
}

void create_subkeys(const uint10_t &key, uint8_t &key1, uint8_t &key2)
{
	uint10_t key_permuted;
	key_permuted.value =
		((MASK_BIT_10 & key.value) >> 6) |
		((MASK_BIT_9 & key.value) >> 1) |
		((MASK_BIT_8 & key.value) << 2) |
		((MASK_BIT_7 & key.value) >> 1) |
		((MASK_BIT_6 & key.value) << 3) |
		((MASK_BIT_5 & key.value) >> 4) |
		((MASK_BIT_4 & key.value) << 3) |
		((MASK_BIT_3 & key.value) >> 1) |
		((MASK_BIT_2 & key.value) << 1) |
		((MASK_BIT_1 & key.value) << 4);

	key_permuted.value = rotate_bits((key_permuted.value & 0x3E0), 1, 5) & 0x3E0 | rotate_bits((key_permuted.value & 0x1F), 1, 5) & 0x1F;
	key1 = ((MASK_BIT_1 & key_permuted.value) << 1) |
		((MASK_BIT_2 & key_permuted.value) >> 1) |
		((MASK_BIT_3 & key_permuted.value) << 1) |
		((MASK_BIT_4 & key_permuted.value) << 2) |
		((MASK_BIT_5 & key_permuted.value) << 3) |
		((MASK_BIT_6 & key_permuted.value) >> 3) |
		((MASK_BIT_7 & key_permuted.value) >> 2) |
		((MASK_BIT_8 & key_permuted.value) >> 1);

	key_permuted.value = rotate_bits((key_permuted.value & 0x3E0), 2, 5) & 0x3E0 | rotate_bits((key_permuted.value & 0x1F), 2, 5) & 0x1F;
	key2 = ((MASK_BIT_1 & key_permuted.value) << 1) |
		((MASK_BIT_2 & key_permuted.value) >> 1) |
		((MASK_BIT_3 & key_permuted.value) << 1) |
		((MASK_BIT_4 & key_permuted.value) << 2) |
		((MASK_BIT_5 & key_permuted.value) << 3) |
		((MASK_BIT_6 & key_permuted.value) >> 3) |
		((MASK_BIT_7 & key_permuted.value) >> 2) |
		((MASK_BIT_8 & key_permuted.value) >> 1);
}

uint8_t encrypt_sdes(const uint8_t &block, const uint8_t &key1, const uint8_t &key2)
{
	return (get_inv_ip(FK(SW(FK(get_ip(block), key1)), key2)));
}

uint8_t decrypt_sdes(const uint8_t &block, const uint8_t &key1, const uint8_t &key2)
{
	return (get_inv_ip(FK(SW(FK(get_ip(block), key2)), key1)));
}

uint8_t encrypt_triple_sdes(const uint8_t &block, const uint8_t &subkey1, const uint8_t &subkey2, const uint8_t &subkey3, const uint8_t &subkey4)
{
	return (encrypt_sdes(decrypt_sdes(encrypt_sdes(block, subkey1, subkey2), subkey3, subkey4), subkey1, subkey2));
}

uint8_t decrypt_triple_sdes(const uint8_t &block, const uint8_t &subkey1, const uint8_t &subkey2, const uint8_t &subkey3, const uint8_t &subkey4)
{
	return (decrypt_sdes(encrypt_sdes(decrypt_sdes(block, subkey1, subkey2), subkey3, subkey4), subkey1, subkey2));
}

// Break Simple Triple DES
// ciphertext is an array of the int values (chars)
// keyword should be used to find some important phrase in the decrypted plaintext, offset is used to improve performance
// so you don't have to search from the start of the string, to see if the substring keyword is in it.
void bruteforce(const uint8_t *ciphertext, const uint32_t &cipherlength, const char *keyword, const uint32_t &offset, const bool bReverse = false)
{
	uint32_t iter = 1, i = 0;
	uint10_t key1, key2;
	uint16_t k1, k2;
	uint8_t sub_key1, sub_key2, sub_key3, sub_key4;
	char *pText = new char[cipherlength + 1];
	pText[cipherlength] = '\0';
	for (k1 = 0; k1 < 1024; k1++)
	{
		for (k2 = 0; k2 < 1024; k2++)
		{
			key1.value = (bReverse ? (1023 - k1) : k1);
			key2.value = (bReverse ? (1023 - k2) : k2);
			create_subkeys(key1, sub_key1, sub_key2);
			create_subkeys(key2, sub_key3, sub_key4);

			for (i = 0; i < cipherlength; i++)
				pText[i] = (unsigned char)decrypt_triple_sdes(ciphertext[i], sub_key1, sub_key2, sub_key3, sub_key4);

			printf("Progress -- %u / 1048576\n", iter);
			if (strstr((pText + (cipherlength - offset)), keyword)) // Check the last Y characters. If the keyword can be found.
			{
				printf("\nKey 1 %u, Key 2 %u --> '%s'\n", key1.value, key2.value, pText);
				delete[] pText;
				return;
			}

			iter++;
		}
	}
	delete[] pText;
	printf("\nFOUND NOTHING\n");
}

void testing()
{
	uint10_t key1; key1.value = 910;
	uint10_t key2; key2.value = 235;

	uint8_t sub_key1, sub_key2;
	create_subkeys(key1, sub_key1, sub_key2);

	uint8_t sub_key3, sub_key4;
	create_subkeys(key2, sub_key3, sub_key4);

	vector<uint8_t> ciphertext;
	uint10_t key, keyZ;
	key.value = 910;
	keyZ.value = 235;

	const char *text = "THIS IS A STRING";
	for (uint32_t i = 0; i < strlen(text); i++)
	{
		uint8_t c = text[i];
		ciphertext.push_back(encrypt_sdes(c, sub_key1, sub_key2));
	}

	printf("RET %u\n", decrypt_sdes(encrypt_sdes(85, sub_key1, sub_key2), sub_key1, sub_key2));
	printf("RET %u\n", decrypt_triple_sdes(encrypt_triple_sdes(85, sub_key1, sub_key2, sub_key3, sub_key4), sub_key1, sub_key2, sub_key3, sub_key4));

	printf("\nCIPHERTEXT\n");
	for (uint8_t x : ciphertext)
		printf("%c", x);

	printf("\nPLAINTEXT\n");
	for (uint8_t x : ciphertext)
		printf("%c", decrypt_sdes(x, sub_key1, sub_key2));
}

int main(int argc, char **args)
{
	const uint8_t ciphertxt[] = { 1, 167, 50, 198, 100, 167, 215, 167, 156, 116, 116, 156, 1, 167, 1, 153, 161, 218, 1, 156, 239, 126, 36, 156, 156, 153, 161, 126, 160, 179, 218, 161, 198, 36, 161, 35, 167, 116, 156, 65, 161, 126, 1, 126, 215, 215, 167, 239, 167, 156, 153, 218, 1, 156, 239, 126, 36, 167, 218, 65 };

	printf("Start cracking\n");
	auto start = chrono::steady_clock::now();
	bruteforce(ciphertxt, 60, "security", 8, true);
	auto end = chrono::steady_clock::now();
	auto diff = end - start;
	cout << "Ended cracking, time elapsed, " << chrono::duration <double, milli>(diff).count() << " ms!" << endl;

	while (1)
	{
		if (_kbhit())
			break;
	}

	return 0;
}
