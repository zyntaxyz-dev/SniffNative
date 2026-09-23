// SniffNative Tweak.x — observador nativo (proposito SNIFF, nivel iOS).
// COMPILAR: macOS + theos (ver README). NO compila en Windows.
// Diseno: solo ObjC runtime + hooks ObjC (sin substrate C-hooks: en
// sideload ESign no hay CydiaSubstrate; fishhook vendria en v2).
// Todo es log+forward con guards; el juego sigue intacto.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static NSFileHandle *gLog = nil;
static unsigned long gCount = 0;

static void SNLog(NSString *fmt, ...) {
    if (!gLog) return;
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    @try {
        NSString *line = [NSString stringWithFormat:@"[+%@] %@\n",
            @([[NSDate date] timeIntervalSince1970]), s];
        [gLog writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        gCount++;
    } @catch (NSException *e) {}
}

// ---------- %ctor: imagenes cargadas + clases del framework anogs ----------
%ctor {
    @autoreleasepool {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *logPath = [[paths firstObject] stringByAppendingPathComponent:@"sniff_native.log"];
        [[NSFileManager defaultManager] createFileAtPath:logPath contents:nil attributes:nil];
        gLog = [NSFileHandle fileHandleForWritingAtPath:logPath];
        [gLog seekToEndOfFile];
        SNLog(@"START tweak v1 %@ %@", [[UIDevice currentDevice] systemVersion], [[NSBundle mainBundle] bundleIdentifier]);

        // 1. Imagenes Mach-O cargadas (buscar anogs / TSS / tencent).
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            NSString *ns = [NSString stringWithUTF8String:name];
            NSString *low = [ns lowercaseString];
            if ([low containsString:@"anogs"] || [low containsString:@"tss"] ||
                [low containsString:@"tencent"] || [low containsString:@"shadowtracker"] ||
                [low containsString:@".app/ShadowTrack"]) {
                SNLog(@"IMAGE [%u] %@", i, ns);
            }
        }
        SNLog(@"IMAGES total=%u", n);

        // 2. Clases ObjC cuya imagen/nombre huela a seguridad (targets v2).
        int nc = objc_getClassList(NULL, 0);
        Class *cls = (Class *)malloc(sizeof(Class) * nc);
        nc = objc_getClassList(cls, nc);
        unsigned found = 0;
        for (int i = 0; i < nc; i++) {
            const char *cn = class_getName(cls[i]);
            if (!cn) continue;
            NSString *s = [NSString stringWithUTF8String:cn];
            NSString *low = [s lowercaseString];
            if ([low containsString:@"anogs"] || [low containsString:@"tss"] ||
                [low containsString:@"tencent"] || [low containsString:@"anticheat"] ||
                [low containsString:@"hawk"] || [low containsString:@"mrpcs"] ||
                [low containsString:@"tersafe"] || [low containsString:@"bugly"] ||
                [low containsString:@"wetest"] || [low containsString:@"aceanti"]) {
                unsigned mc = 0;
                Method *ml = class_copyMethodList(object_getClass(cls[i]), &mc);
                SNLog(@"CLASS %@ (+%u metodos clase)", s, mc);
                if (ml) free(ml);
                if (++found > 200) break; // tope anti-spam
            }
        }
        free(cls);
        SNLog(@"CLASSES seguridad=%u de %d", found, nc);
    }
}

// ---------- Telemetria HTTP: endpoints reales (tencent/wetest/bugly/cloud) --
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))h {
    @try {
        NSString *url = request.URL.absoluteString ?: @"<nil>";
        NSString *low = [url lowercaseString];
        if ([low containsString:@"tencent"] || [low containsString:@"wetest"] ||
            [low containsString:@"bugly"] || [low containsString:@"qcloud"] ||
            [low containsString:@"qq.com"] || [low containsString:@"keyauth"] ||
            [low containsString:@"report"] || [low containsString:@"tss"] ||
            [low containsString:@"anti"] || [low containsString:@"cheat"] ||
            [low containsString:@"ban"] || [low containsString:@"log"]) {
            SNLog(@"HTTP %@ %@", request.HTTPMethod ?: @"?", url);
        }
    } @catch (NSException *e) {}
    return %orig;
}
%end

// ---------- Fuentes de HWID (lo que el juego puede leer para atarte) -------
%hook UIDevice
- (NSString *)identifierForVendor {
    NSString *v = %orig;
    SNLog(@"HWID identifierForVendor=%@", v);
    return v;
}
%end

%hook UIPasteboard
+ (UIPasteboard *)generalPasteboard {
    UIPasteboard *pb = %orig;
    SNLog(@"HWID generalPasteboard=%@ items=%lu", pb.name, (unsigned long)pb.numberOfItems);
    return pb;
}
%end

// ---------- Chequeos jailbreak/entorno (rutas que el juego husmea) ---------
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    BOOL r = %orig;
    @try {
        NSString *low = [path lowercaseString];
        if ([low containsString:@"cydia"] || [low containsString:@"substrate"] ||
            [low containsString:@"jailbreak"] || [low containsString:@"mobilesubstrate"] ||
            [low containsString:@"esign"] || [low containsString:@"sileo"] ||
            [low containsString:@"zebra"] || [low containsString:@"anogs"] ||
            [low containsString:@"tss"]) {
            SNLog(@"ENV fileExists %@ -> %d", path, r);
        }
    } @catch (NSException *e) {}
    return r;
}
%end
