#import <Foundation/Foundation.h>
#import <Security/Security.h>

/// Calls SecIdentityCreate (private API) wrapped in @try/@catch.
/// SecIdentityCreate crashes with SIGABRT in system extensions due to
/// an internal NSException from _SecKeyCheck. This wrapper catches the
/// exception so the process survives, and returns the exception message.
CF_RETURNS_RETAINED
SecIdentityRef _Nullable TrySecIdentityCreate(
    SecCertificateRef _Nonnull certificate,
    SecKeyRef _Nonnull privateKey,
    NSString * _Nullable * _Nullable outExceptionReason);
