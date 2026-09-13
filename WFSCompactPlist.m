#import "WFSCompactPlist.h"

static void WFSXMLEscape(NSMutableString* output, NSString* value)
{
	for (NSUInteger i = 0; i < value.length; i++)
	{
		unichar c = [value characterAtIndex:i];
		switch (c)
		{
			case '&':  [output appendString:@"&amp;"];  break;
			case '<':  [output appendString:@"&lt;"];   break;
			case '>':  [output appendString:@"&gt;"];   break;
			case '"':  [output appendString:@"&quot;"];  break;
			case '\'': [output appendString:@"&apos;"]; break;
			default:   [output appendFormat:@"%C", c];  break;
		}
	}
}

static void WFSWriteCompactPlistValue(id value, NSMutableString* output)
{
	if ([value isKindOfClass:[NSString class]])
	{
		[output appendString:@"<string>"];
		WFSXMLEscape(output, value);
		[output appendString:@"</string>"];
	}
	else if ([value isKindOfClass:[NSNumber class]])
	{
		const char* type = [value objCType];
		if (strcmp(type, @encode(BOOL)) == 0 || strcmp(type, @encode(BOOL)) == 0)
		{
			[output appendString:[value boolValue] ? @"<true/>" : @"<false/>"];
		}
		else
		{
			[output appendString:@"<integer>"];
			[output appendString:[value stringValue]];
			[output appendString:@"</integer>"];
		}
	}
	else if ([value isKindOfClass:[NSData class]])
	{
		[output appendString:@"<data>"];
		[output appendString:[value base64EncodedStringWithOptions:0]];
		[output appendString:@"</data>"];
	}
	else if ([value isKindOfClass:[NSArray class]])
	{
		[output appendString:@"<array>"];
		for (id item in value)
		{
			WFSWriteCompactPlistValue(item, output);
		}
		[output appendString:@"</array>"];
	}
	else if ([value isKindOfClass:[NSDictionary class]])
	{
		[output appendString:@"<dict>"];
		NSArray* sortedKeys = [[value allKeys] sortedArrayUsingSelector:@selector(compare:)];
		for (NSString* key in sortedKeys)
		{
			[output appendString:@"<key>"];
			WFSXMLEscape(output, key);
			[output appendString:@"</key>"];
			WFSWriteCompactPlistValue(value[key], output);
		}
		[output appendString:@"</dict>"];
	}
}

NSData* WFSEncodeCompactXMLPlist(NSDictionary* dict)
{
	NSMutableString* output = [NSMutableString string];
	[output appendString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"];
	[output appendString:@"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"];
	[output appendString:@"<plist version=\"1.0\">"];
	WFSWriteCompactPlistValue(dict, output);
	[output appendString:@"</plist>"];
	return [output dataUsingEncoding:NSUTF8StringEncoding];
}
