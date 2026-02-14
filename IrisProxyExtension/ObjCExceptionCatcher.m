#import "ObjCExceptionCatcher.h"
#import <dlfcn.h>

SecIdentityRef _Nullable TrySecIdentityCreate(
    SecCertificateRef _Nonnull certificate,
    SecKeyRef _Nonnull privateKey,
    NSString * _Nullable * _Nullable outExceptionReason)
{
    typedef SecIdentityRef _Nullable (*CreateFn)(CFAllocatorRef, SecCertificateRef, SecKeyRef);
    CreateFn create = (CreateFn)dlsym(RTLD_DEFAULT, "SecIdentityCreate");
    if (!create) {
        if (outExceptionReason) *outExceptionReason = @"SecIdentityCreate symbol not found";
        return NULL;
    }

    @try {
        SecIdentityRef identity = create(NULL, certificate, privateKey);
        return identity;
    } @catch (NSException *exception) {
        if (outExceptionReason) {
            *outExceptionReason = [NSString stringWithFormat:@"%@: %@",
                exception.name, exception.reason ?: @"(no reason)"];
        }
        return NULL;
    }
}
