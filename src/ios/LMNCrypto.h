#import <UIKit/UIKit.h>
#import <Cordova/CDVPlugin.h>

@interface LMNCrypto : CDVPlugin
{}

- (void)decryptString:(CDVInvokedUrlCommand*)command;

- (void)encryptFile:(CDVInvokedUrlCommand*)command;
- (void)decryptFile:(CDVInvokedUrlCommand*)command;

@end
