#import <Cordova/CDV.h>
#import <libkern/OSByteOrder.h>

#import "LMNCrypto.h"

#import "lmn_aes.h"
#import "lmn_files.h"
#import "lmn_base64.h"
#import "lmn_hex.h"
#import "lmn_filters.h"
#import "lmn_gcm.h"
#import "lmn_cryptlib.h"

@interface LMNCrypto () {}
@end

CryptoPP::word64 decodeBase64(const std::string &encoded, byte **result) {
	CryptoPP::Base64Decoder decoder;

	decoder.Put((byte*)encoded.data(), encoded.size());
	decoder.MessageEnd();

	CryptoPP::word64 size = decoder.MaxRetrievable();

	if (size && size <= SIZE_MAX)
	{
		*result = new byte[size];
		decoder.Get(*result, size);
	}

	return size;
}

CryptoPP::word64 decodeHex(const std::string &encoded, byte **result) {
	CryptoPP::HexDecoder decoder;

	decoder.Put((byte*)encoded.data(), encoded.size());
	decoder.MessageEnd();

	CryptoPP::word64 size = decoder.MaxRetrievable();

	if (size && size <= SIZE_MAX)
	{
		*result = new byte[size];
		decoder.Get(*result, size);
	}

	return size;
}

void encryptFile(
	NSString *finName,
	NSString *foutName,
	const byte *key, CryptoPP::word64 keySize
) {
	// create output file
	NSFileManager* fileMgr = [[NSFileManager alloc] init];
	[fileMgr createFileAtPath:foutName contents:nil attributes:nil];

	const char *fin = [finName UTF8String];
	const char *fout = [foutName UTF8String];

	std::ofstream foutStream;
	foutStream.open(fout);

	// generate 16 bytes of random iv
	byte iv[16];
	arc4random_buf(iv, 16);

	// write iv size
	char ivSize[4] = {0, 0, 0, 16};
	foutStream.write(ivSize, 4);

	// write iv
	foutStream.write(reinterpret_cast<char *>(iv), 16);

	// init cipher
	CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption aesEncryption;
	aesEncryption.SetKeyWithIV(key, keySize, iv, 16);

	// output sink
	CryptoPP::FileSink *sink = new CryptoPP::FileSink(foutStream);

	// init filter
	CryptoPP::BufferedTransformation *filter
		= new CryptoPP::StreamTransformationFilter(
			aesEncryption,
			sink,
			CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING
		);

	// pump
	CryptoPP::FileSource fsrc(fin, true, filter);

	// close
	foutStream.close();
}

void decryptFile(
	NSString *finName,
	NSString *foutName,
	const byte *key, CryptoPP::word64 keySize
) {
	// create output file
	NSFileManager* fileMgr = [[NSFileManager alloc] init];
	[fileMgr createFileAtPath:foutName contents:nil attributes:nil];

	const char *fin = [finName UTF8String];
	const char *fout = [foutName UTF8String];

	std::ifstream finStream;
	finStream.open(fin);

	// read iv size
	char ivSizeBuf[4];
	finStream.read(ivSizeBuf, 4);
	uint32_t ivSize = (uint32_t)ivSizeBuf[3]
		+ ((uint32_t)ivSizeBuf[2] << 8)
		+ ((uint32_t)ivSizeBuf[1] << 16)
		+ ((uint32_t)ivSizeBuf[0] << 24);

	// read iv
	char* ivBuf = new char[ivSize];
	finStream.read(ivBuf, ivSize);

	// init cipher
	CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption aesDecryption;
	aesDecryption.SetKeyWithIV(
		key,
		keySize,
		reinterpret_cast<byte *>(ivBuf),
		ivSize
	);

	// output sink
	CryptoPP::FileSink *sink = new CryptoPP::FileSink(fout, true);

	// init filter
	CryptoPP::BufferedTransformation *filter
		= new CryptoPP::StreamTransformationFilter(
			aesDecryption,
			sink,
			CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING
		);

	// input source, skip
	finStream.seekg(20);
	CryptoPP::FileSource fsrc(finStream, true, filter);

	// filters and sinks are auto deallocated
	delete ivBuf;

	// close input file
	finStream.close();
}

CDVPluginResult* handleFile(CDVInvokedUrlCommand* command, bool isDecrypt)
{
	// 0th: input file path
	// 1st: output file path
	// 2nd: key

	if (command.arguments.count != 3) {
		return [CDVPluginResult
			resultWithStatus:CDVCommandStatus_ERROR
			messageAsString:@"Invalid parameters"
		];
	} else {
		try {
			NSString *finString = [command.arguments objectAtIndex:0];
			NSString *foutString = [command.arguments objectAtIndex:1];

			std::string keyHex(
				[[command.arguments objectAtIndex:2] UTF8String]
			);

			byte *key = nil;

			CryptoPP::word64 keySize = decodeHex(keyHex, &key);

			if (isDecrypt) {
				decryptFile(finString, foutString, key, keySize);
			} else {
				encryptFile(finString, foutString, key, keySize);
			}

			delete key;

			return [CDVPluginResult
				resultWithStatus:CDVCommandStatus_OK
				messageAsString:foutString
			];
		}
		catch(const CryptoPP::Exception& e)
		{
			return [CDVPluginResult
				resultWithStatus:CDVCommandStatus_ERROR
				messageAsString:[NSString stringWithUTF8String:e.what()]
			];
		}
	}
}

@implementation LMNCrypto

- (void)encryptFile:(CDVInvokedUrlCommand*)command
{
	[self.commandDelegate runInBackground:^ {
		[self.commandDelegate
			sendPluginResult:handleFile(command, false)
			callbackId:command.callbackId
		];
	}];
}

- (void)decryptFile:(CDVInvokedUrlCommand*)command
{
	[self.commandDelegate runInBackground:^ {
		[self.commandDelegate
			sendPluginResult:handleFile(command, true)
			callbackId:command.callbackId
		];
	}];
}

@end
