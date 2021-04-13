#include "pch.h"
#include <iostream>
#include <fstream>
#include <aes.h>
#include <filters.h>
#include <modes.h>
#include "osrng.h"
#include <Windows.h>
#include "hex.h"

#pragma comment(lib, "cryptlib.lib")

using namespace std;

byte key[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F'}, 
iv[] = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'},
iv9[] = { '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9' };


string encryptcbc(string plainText)
{
	string cipherText;

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
	CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::StringSink(cipherText), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));

	return cipherText;
}

string encryptcbc7(string plainText)
{
	string cipherText;

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv9);
	CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::StringSink(cipherText), CryptoPP::StreamTransformationFilter::PKCS_PADDING));

	return cipherText;
}

string encryptcfb(string plainText)
{
	string cipherText;

	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, sizeof(key), iv, 4);
	CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(cfbEncryption, new CryptoPP::StringSink(cipherText)));

	return cipherText;
}

string encryptecb(string plainText)
{
	string cipherText;

	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, sizeof(key));
	CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(cfbEncryption, new CryptoPP::StringSink(cipherText), CryptoPP::StreamTransformationFilter::PKCS_PADDING));

	return cipherText;
}

string decryptecb(string cipher) {
	string recovered = "";
	//Decryption
	CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
	d.SetKey(key, sizeof(key));
	// The StreamTransformationFilter removes
	//  padding as required.
	CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered))); // StringSource

	return recovered;
}

string decryptcbc(string cipher) {
	string recovered = "";
	//Decryption
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d(key, sizeof(key), iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered), CryptoPP::StreamTransformationFilter::ZEROS_PADDING)); // StringSource

	return recovered;
}
string decryptcfb(string cipher) {
	string recovered = "";
	//Decryption
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption d(key, sizeof(key), iv, 4);
	// The StreamTransformationFilter removes
	//  padding as required.
	CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered))); // StringSource

	return recovered;
}
string decryptcbc7(string cipher) {
	string recovered = "";
	//Decryption
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv9);
		// The StreamTransformationFilter removes
		//  padding as required.
	CryptoPP::StringSource s(cipher, true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(recovered), CryptoPP::StreamTransformationFilter::PKCS_PADDING)); // StringSource
	
	return recovered;
}

void readCipher()
{
	ifstream in("cipher.txt");
	ofstream out("decryp.txt");

	string line;
	string decryptedText;
	getline(in, line);
	out << decryptcbc(line)<<endl;
	cout << decryptcbc(line) << endl;
	line.clear();
	getline(in, line);
	out << decryptcfb(line)<<endl;
	cout << decryptcfb(line) << endl;
	line.clear();
	getline(in, line);
	out << decryptcbc7(line) << endl;
	cout << decryptcbc7(line) << endl;
	line.clear();
	getline(in, line);
	out << decryptecb(line) << endl;
	cout << decryptecb(line) << endl;

	in.close();
	out.close();
}

string beautiful(string cipher)
{
	string cipherTextHex;
	CryptoPP::StringSource(cipher, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(cipherTextHex)));
	return cipherTextHex;
}

int main()
{
	string text = "Hello World!";
	cout << "text : " << text << endl;
	string result;
	ofstream out("out.txt");
	ofstream out2("cipher.txt");

	result = encryptcbc(text);
	cout << "cipher cbc : " << beautiful(result) << endl;
	out.write(beautiful(result).c_str(), beautiful(result).length())<<endl;
	out2.write(result.c_str(), result.length()) << endl;
	result = encryptcfb(text);
	cout << "cipher cfb: " << beautiful(result) << endl;
	out.write(beautiful(result).c_str(), beautiful(result).length()) << endl;
	out2.write(result.c_str(), result.length()) << endl;
	result = encryptcbc7(text);
	cout << "cipher cfb 9999: " << beautiful(result) << endl;
	out.write(beautiful(result).c_str(), beautiful(result).length()) << endl;
	out2.write(result.c_str(), result.length()) << endl;
	result = encryptecb(text);
	cout << "cipher ecb: " << beautiful(result) << endl;
	out.write(beautiful(result).c_str(), beautiful(result).length()) << endl;
	out2.write(result.c_str(), result.length()) << endl;

	readCipher();

	out.close();
	return 0;
}