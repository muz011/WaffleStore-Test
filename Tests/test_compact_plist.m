#import <Foundation/Foundation.h>
#import "WFSCompactPlist.h"

// ipatool v2.5.0 exact expected output (verified via howett.net/plist encoder without indent).
// Keys sorted alphabetically: appleId, attempt, guid, password, rmp, why.
// Format: header + DOCTYPE on separate lines, plist body on ONE line, no trailing newline.
static NSString* const kExpectedXMLPlist =
	@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
	"<plist version=\"1.0\"><dict>"
	"<key>appleId</key><string>test@example.com</string>"
	"<key>attempt</key><string>1</string>"
	"<key>guid</key><string>AABBCCDD1122</string>"
	"<key>password</key><string>secret123</string>"
	"<key>rmp</key><string>0</string>"
	"<key>why</key><string>signIn</string>"
	"</dict></plist>";

static NSDictionary* const kTestAuthBody = @{
	@"appleId":  @"test@example.com",
	@"attempt":  @"1",
	@"guid":     @"AABBCCDD1122",
	@"password": @"secret123",
	@"rmp":      @"0",
	@"why":      @"signIn",
};

static int WFSRunPlistTests(void)
{
	int failures = 0;

	NSData* expectedData = [kExpectedXMLPlist dataUsingEncoding:NSUTF8StringEncoding];
	NSData* actualData = WFSEncodeCompactXMLPlist(kTestAuthBody);

	NSLog(@"Expected length: %lu", (unsigned long)expectedData.length);
	NSLog(@"Actual length:   %lu", (unsigned long)actualData.length);

	if (actualData.length != expectedData.length)
	{
		NSLog(@"FAIL: byte length mismatch: expected %lu, got %lu",
			(unsigned long)expectedData.length, (unsigned long)actualData.length);
		failures++;
	}
	else if (![actualData isEqualToData:expectedData])
	{
		NSLog(@"FAIL: byte content mismatch");
		const uint8_t* a = actualData.bytes;
		const uint8_t* e = expectedData.bytes;
		for (NSUInteger i = 0; i < actualData.length; i++)
		{
			if (a[i] != e[i])
			{
				NSLog(@"  first diff at byte %lu: expected 0x%02x, got 0x%02x", (unsigned long)i, e[i], a[i]);
				break;
			}
		}
		failures++;
	}

	NSString* actualStr = [[NSString alloc] initWithData:actualData encoding:NSUTF8StringEncoding];
	if (![actualStr isEqualToString:kExpectedXMLPlist])
	{
		NSLog(@"FAIL: string content mismatch");
		NSLog(@"expected:\n%@", kExpectedXMLPlist);
		NSLog(@"actual:\n%@", actualStr);
		failures++;
	}

	NSData* signData = WFSEncodeCompactXMLPlist(kTestAuthBody);
	NSData* httpData = WFSEncodeCompactXMLPlist(kTestAuthBody);
	if (![signData isEqualToData:httpData])
	{
		NSLog(@"FAIL: two calls produce different bytes (signing vs HTTP body)");
		failures++;
	}

	NSRange appleIdRange = [actualStr rangeOfString:@"<key>appleId</key>"];
	NSRange attemptRange = [actualStr rangeOfString:@"<key>attempt</key>"];
	NSRange guidRange = [actualStr rangeOfString:@"<key>guid</key>"];
	NSRange passwordRange = [actualStr rangeOfString:@"<key>password</key>"];
	NSRange rmpRange = [actualStr rangeOfString:@"<key>rmp</key>"];
	NSRange whyRange = [actualStr rangeOfString:@"<key>why</key>"];
	if (appleIdRange.location > attemptRange.location ||
		attemptRange.location > guidRange.location ||
		guidRange.location > passwordRange.location ||
		passwordRange.location > rmpRange.location ||
		rmpRange.location > whyRange.location)
	{
		NSLog(@"FAIL: keys not in alphabetical order");
		failures++;
	}

	NSRange plistOpen = [actualStr rangeOfString:@"<plist version=\"1.0\">"];
	NSRange dictClose = [actualStr rangeOfString:@"</dict></plist>"];
	if (plistOpen.location != NSNotFound && dictClose.location != NSNotFound)
	{
		NSUInteger searchFrom = plistOpen.location + plistOpen.length;
		NSUInteger searchLen = dictClose.location - searchFrom;
		NSRange newlineInRange = [actualStr rangeOfString:@"\n" options:0 range:NSMakeRange(searchFrom, searchLen)];
		if (newlineInRange.location != NSNotFound)
		{
			NSLog(@"FAIL: unexpected newline inside plist body (expected compact single-line format)");
			failures++;
		}
	}

	if (failures == 0)
	{
		NSLog(@"PASS: all 5 serialization tests passed — output is byte-for-byte equivalent to ipatool");
	}
	else
	{
		NSLog(@"FAIL: %d test(s) failed", failures);
	}

	return failures;
}

int main(int argc, const char* argv[])
{
	@autoreleasepool
	{
		return WFSRunPlistTests();
	}
}
