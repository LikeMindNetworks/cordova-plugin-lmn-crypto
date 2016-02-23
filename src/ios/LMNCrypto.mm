#import <Cordova/CDV.h>
#import "LMNCrypto.h"

#import "aes.h"
#import "files.h"
#import "base64.h"
#import "hex.h"
#import "filters.h"
#import "gcm.h"
#import "cryptlib.h"

@interface LMNCrypto () {}
@end

CryptoPP::word64 decodeBase64(const std::string &encoded, byte **result) {
	CryptoPP::Base64Decoder decoder;

	decoder.Put( (byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();

	CryptoPP::word64 size = decoder.MaxRetrievable();

	if (size && size <= SIZE_MAX)
	{
		*result = new byte[size];
		decoder.Get(*result, size);
	}

	return size;
}

void encryptOrDecryptFile(
	bool isDecrypt,
	NSString *finName,
	NSString *foutName,
	const byte *key, CryptoPP::word64 keySize,
	const byte *iv, CryptoPP::word64 ivSize,
	int tagSize
) {
	CryptoPP::AuthenticatedSymmetricCipher *blockCipher;
	CryptoPP::BufferedTransformation *filter;

	if (isDecrypt) {
		blockCipher = new CryptoPP::GCM< CryptoPP::AES >::Decryption();
	} else {
		blockCipher = new CryptoPP::GCM< CryptoPP::AES >::Encryption();
	}

	// set keys
	blockCipher->SetKeyWithIV(key, keySize, iv, ivSize);

	// parse the file names as url and get their paths
	NSURLComponents *finUrl = [NSURLComponents componentsWithString:finName];
	NSURLComponents *foutUrl = [NSURLComponents componentsWithString:foutName];

	// create output file
	NSFileManager* fileMgr = [[NSFileManager alloc] init];
	[fileMgr createFileAtPath:foutUrl.path contents:nil attributes:nil];

	const char *fin = [finUrl.path UTF8String];
	const char *fout = [foutUrl.path UTF8String];

	CryptoPP::FileSink *sink = new CryptoPP::FileSink(fout, true);

	if (isDecrypt) {
		filter = new CryptoPP::AuthenticatedDecryptionFilter(
			*blockCipher,
			sink,
			CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
			tagSize
		);
	} else {
		filter = new CryptoPP::AuthenticatedEncryptionFilter(
			*blockCipher, sink, false, tagSize
		);
	}

	CryptoPP::FileSource(fin, true, filter);

	// filters and sinks are auto deallocated
	delete blockCipher;
}

CDVPluginResult* handleFile(CDVInvokedUrlCommand* command, bool isDecrypt)
{
	// 0th: input file path
	// 1st: output file path
	// 2nd: key
	// 3rd: iv
	// 4th: tagSize

	if (command.arguments.count != 5) {
		return [CDVPluginResult
			resultWithStatus:CDVCommandStatus_ERROR
			messageAsString:@"Invalid parameters"
		];
	} else {
		try {
			NSString *finString = [command.arguments objectAtIndex:0];
			NSString *foutString = [command.arguments objectAtIndex:1];

			std::string keyBase64(
				[[command.arguments objectAtIndex:2] UTF8String]
			);
			std::string ivBase64(
				[[command.arguments objectAtIndex:3] UTF8String]
			);
			int tagSize = (int)[[command.arguments objectAtIndex:4] integerValue];

			byte *key = nil, *iv = nil;

			CryptoPP::word64 keySize = decodeBase64(keyBase64, &key);
			CryptoPP::word64 ivSize = decodeBase64(ivBase64, &iv);

			encryptOrDecryptFile(
				isDecrypt, finString, foutString, key, keySize, iv, ivSize, tagSize
			);

			delete key;
			delete iv;

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

- (void)decryptString:(CDVInvokedUrlCommand*)command
{
	[self.commandDelegate runInBackground:^ {
		CDVPluginResult* pluginResult = nil;

		try
		{
			std::string cipherBase64(
				[[command.arguments objectAtIndex:0] UTF8String]
			);
			std::string keyBase64(
				[[command.arguments objectAtIndex:1] UTF8String]
			);
			std::string ivBase64(
				[[command.arguments objectAtIndex:2] UTF8String]
			);

			std::string msg;
			byte *cipher = nil, *key = nil, *iv = nil;

			CryptoPP::word64 cipherSize = decodeBase64(cipherBase64, &cipher);
			CryptoPP::word64 keySize = decodeBase64(keyBase64, &key);
			CryptoPP::word64 ivSize = decodeBase64(ivBase64, &iv);

			CryptoPP::GCM< CryptoPP::AES >::Decryption d;
			d.SetKeyWithIV(key, keySize, iv, ivSize);

			CryptoPP::StringSink *sink = new CryptoPP::StringSink(msg);
			CryptoPP::AuthenticatedDecryptionFilter *filter
				= new CryptoPP::AuthenticatedDecryptionFilter(
				  d,
				  sink,
				  CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
				  8
				);

			CryptoPP::StringSource(cipher, cipherSize, true, filter);

			delete cipher;
			delete key;
			delete iv;

			NSString* result = [NSString stringWithUTF8String:msg.c_str()];
			pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
				messageAsString:result];
		}
		catch(const CryptoPP::Exception& e)
		{
			NSString* what = [NSString stringWithUTF8String:e.what()];
			pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
				messageAsString:what];
		}

		[self.commandDelegate sendPluginResult:pluginResult
			callbackId:command.callbackId];
	}];
}

@end
