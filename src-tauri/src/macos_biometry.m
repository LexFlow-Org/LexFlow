// Compiled into the macOS application. No runtime compiler or helper process.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/SecTask.h>
#include <stdint.h>

// Data Protection Keychain access requires an application identifier or an
// allowed access group. Ad-hoc packages without these cannot offer enrollment.
static BOOL lexflow_has_keychain_entitlement(void) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task == NULL) return NO;
    CFTypeRef identifier = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.application-identifier"), NULL);
    BOOL allowed = identifier != NULL && CFGetTypeID(identifier) == CFStringGetTypeID()
        && CFStringGetLength((CFStringRef)identifier) > 0;
    if (identifier != NULL) CFRelease(identifier);
    if (!allowed) {
        CFTypeRef groups = SecTaskCopyValueForEntitlement(task, CFSTR("keychain-access-groups"), NULL);
        allowed = groups != NULL && CFGetTypeID(groups) == CFArrayGetTypeID()
            && CFArrayGetCount((CFArrayRef)groups) > 0;
        if (groups != NULL) CFRelease(groups);
    }
    CFRelease(task);
    return allowed;
}

// Independent capability bits; this never authenticates or reads a credential.
// Device readiness is current policy availability, not the physical presence
// of a sensor (for example, enrolled fingers may be temporarily locked out).
enum {
    LEXFLOW_DEVICE_READY = 1,
    LEXFLOW_APP_AUTHORIZED = 2,
    LEXFLOW_CHECK_FAILED = 4,
};

int32_t lexflow_biometry_status(void) {
    @autoreleasepool {
        @try {
            LAContext *context = [[LAContext alloc] init];
            NSError *error = nil;
            BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                                 error:&error];
            [context invalidate];
            // Query both independently so an unsigned build never masquerades
            // as a Mac without Touch ID. Enrollment still verifies the real ACL.
            BOOL authorized = lexflow_has_keychain_entitlement();
            return (available ? LEXFLOW_DEVICE_READY : 0)
                | (authorized ? LEXFLOW_APP_AUTHORIZED : 0);
        } @catch (NSException *exception) {
            (void)exception;
            return LEXFLOW_CHECK_FAILED; // Never unwind through Rust FFI.
        }
    }
}

int32_t lexflow_can_use_biometrics(void) {
    return lexflow_biometry_status() == (LEXFLOW_DEVICE_READY | LEXFLOW_APP_AUTHORIZED) ? 1 : 0;
}
