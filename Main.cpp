// Implement the SHA-256 algorithm in C++.

#include <iostream>
#include <string>
#include <cmath>
#include <vector>
#include <fstream>
#include <curl/curl.h>
 
using namespace std;

// Constants used in SHA-256 algorithm
constexpr uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 algorithm
void sha256(std::string input, uint32_t hash[8]) {
	// Initialize
	uint32_t a, b, c, d, e, f, g, h;
	a = 0x6a09e667;
	b = 0xbb67ae85;
	c = 0x3c6ef372;
	d = 0xa54ff53a;
	e = 0x510e527f;
	f = 0x9b05688c;
	g = 0x1f83d9ab;
	h = 0x5be0cd19;

	// Pre-processing
	uint32_t l = input.length() * 8;
	input.append(1, 0x80);
	while (input.length() % 64 != 56)
		input.append(1, 0x00);
	input.append(std::string(8, 0x00));
	for (int i = 0; i < 8; i++)
		input[input.length() - 8 + i] = (l >> (8 * (7 - i))) & 0xff;

	// Process the message
	std::vector<uint32_t> w(64);
	for (int i = 0; i < input.length(); i += 64) {
		for (int j = 0; j < 16; j++)
			w[j] = (uint32_t)input[i + j * 4] << 24 | (uint32_t)input[i + j * 4 + 1] << 16 | (uint32_t)input[i + j * 4 + 2] << 8 | (uint32_t)input[i + j * 4 + 3];
		for (int j = 16; j < 64; j++)
			w[j] = (w[j - 16] + (w[j - 15] >> 7 | w[j - 15] << (32 - 7)) ^ (w[j - 15] >> 18 | w[j - 15] << (32 - 18)) ^ (w[j - 15] >> 3)) + w[j - 7] + (w[j - 2] >> 17 | w[j - 2] << (32 - 17)) ^ (w[j - 2] >> 19 | w[j - 2] << (32 - 19)) ^ (w[j - 2] >> 10);
		uint32_t aa = a, bb = b, cc = c, dd = d, ee = e, ff = f, gg = g, hh = h;
		for (int j = 0; j < 64; j++) {
			uint32_t t1 = hh + ((ee >> 6 | ee << (32 - 6)) ^ (ee >> 11 | ee << (32 - 11)) ^ (ee >> 25 | ee << (32 - 25))) + (ee & ff ^ ~ee & gg) + K[j] + w[j];
			uint32_t t2 = ((aa >> 2 | aa << (32 - 2)) ^ (aa >> 13 | aa << (32 - 13)) ^ (aa >> 22 | aa << (32 - 22))) + (aa & bb ^ aa & cc ^ bb & cc);
			hh = gg;
			gg = ff;
			ff = ee;
			ee = dd + t1;
			dd = cc;
			cc = bb;
			bb = aa;
			aa = t1 + t2;
		}
		a += aa;
		b += bb;
		c += cc;
		d += dd;
		e += ee;
		f += ff;
		g += gg;
		h += hh;
	}

	// Output
	hash[0] = a;
	hash[1] = b;
	hash[2] = c;
	hash[3] = d;
	hash[4] = e;
	hash[5] = f;
	hash[6] = g;
	hash[7] = h;
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string* data) {
    data->append((char*) contents, size * nmemb);
    return size * nmemb;
}

int main() {
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
    CURL *curl;
    CURLcode res;
    string readBuffer;
 
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
 
        cout << readBuffer << endl;
    }
    std::string input = readBuffer;
    
	uint32_t hash[8];
	sha256(input, hash);
	std::cout << "SHA-256 hash: ";
	for (int i = 0; i < 8; i++)
		std::cout << std::hex << hash[i];
	std::cout << std::endl;
	return 0;
}
