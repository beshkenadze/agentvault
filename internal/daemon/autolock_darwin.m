// autolock_darwin.m implements the native screen-lock / sleep observers for
// auto-locking the session. cgo compiles .m files in this package automatically
// on darwin (the matching declarations live in autolock_darwin.go's cgo
// preamble). This file is NOT a Go file and carries no build tags; it is only
// reachable from the darwin && cgo build of the package.
//
// RUN-LOOP REQUIREMENT (read this before debugging "it compiles but never
// fires"): NSDistributedNotificationCenter (screen lock) and
// NSWorkspace.notificationCenter (sleep) deliver notifications on a run loop.
// avd's Go main does not run a CFRunLoop, so registering observers alone is not
// enough — nothing pumps the loop and the blocks never run. We therefore spin a
// dedicated thread in av_autolock_start that registers the observers and then
// runs CFRunLoopRun(). av_autolock_stop stops that run loop and removes the
// observers. This thread requirement is exactly why the manual hardware-verify
// step (lock the screen, then `av status`) is mandatory: a green build only
// proves it compiles.

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <CoreFoundation/CoreFoundation.h>

// goAutoLockFire is the cgo-exported Go callback (generated from the //export in
// autolock_darwin.go). Each observer block invokes it; it locks the session.
extern void goAutoLockFire(void);

// State shared between start and stop. Access is serialized by the Go side:
// StartAutoLock and its returned stop are the only callers of
// av_autolock_start/av_autolock_stop, and stop is wrapped in sync.Once, so these
// statics never race.
static id avLockObserver = nil;   // distributed: com.apple.screenIsLocked
static id avSleepObserver = nil;  // workspace: NSWorkspaceWillSleepNotification
static CFRunLoopRef avRunLoop = NULL;
static NSThread *avThread = nil;

// av_autolock_run is the body of the dedicated observer thread. It registers the
// two observers against the CURRENT thread's run loop, publishes that run loop
// for av_autolock_stop, then runs the loop. CFRunLoopRun returns only when the
// loop is stopped (av_autolock_stop) or has no sources; we add a no-op source so
// it does not exit immediately before the observers' sources are live.
static void av_autolock_run(void) {
    @autoreleasepool {
        avRunLoop = CFRunLoopGetCurrent();

        void (^fire)(NSNotification *) = ^(NSNotification *note) {
            (void)note;
            goAutoLockFire();
        };

        avLockObserver =
            [[NSDistributedNotificationCenter defaultCenter]
                addObserverForName:@"com.apple.screenIsLocked"
                            object:nil
                             queue:nil
                        usingBlock:fire];

        avSleepObserver =
            [[[NSWorkspace sharedWorkspace] notificationCenter]
                addObserverForName:NSWorkspaceWillSleepNotification
                            object:nil
                             queue:nil
                        usingBlock:fire];

        // Keep the run loop alive even though the notification sources may not
        // register an explicit CFRunLoopSource until a notification is posted.
        // An empty timer source guarantees CFRunLoopRun has work and does not
        // return immediately.
        CFRunLoopTimerRef keepAlive = CFRunLoopTimerCreate(
            kCFAllocatorDefault,
            CFAbsoluteTimeGetCurrent() + 1.0e10, // far future
            1.0e10,                              // long interval
            0, 0, NULL, NULL);
        CFRunLoopAddTimer(avRunLoop, keepAlive, kCFRunLoopCommonModes);

        CFRunLoopRun();

        // Loop stopped: tear down the keep-alive timer. Observer removal happens
        // in av_autolock_stop (it runs before signalling the loop to stop).
        CFRunLoopRemoveTimer(avRunLoop, keepAlive, kCFRunLoopCommonModes);
        CFRelease(keepAlive);
        avRunLoop = NULL;
    }
}

// av_autolock_start spins the dedicated observer thread (idempotent: a second
// call while a thread is live is ignored). The thread registers the observers
// and pumps a run loop so the OS notifications are delivered.
void av_autolock_start(void) {
    @autoreleasepool {
        if (avThread != nil) {
            return; // already running
        }
        avThread = [[NSThread alloc] initWithBlock:^{
            av_autolock_run();
        }];
        avThread.name = @"agentvault-autolock";
        [avThread start];
    }
}

// av_autolock_stop removes the observers and stops the run loop, letting the
// observer thread exit. It is non-blocking: it signals the run loop and returns
// without joining the thread. Safe to call when nothing is running (guards on
// the statics) — the Go stop() also wraps this in sync.Once.
void av_autolock_stop(void) {
    @autoreleasepool {
        if (avLockObserver != nil) {
            [[NSDistributedNotificationCenter defaultCenter]
                removeObserver:avLockObserver];
            avLockObserver = nil;
        }
        if (avSleepObserver != nil) {
            [[[NSWorkspace sharedWorkspace] notificationCenter]
                removeObserver:avSleepObserver];
            avSleepObserver = nil;
        }
        if (avRunLoop != NULL) {
            CFRunLoopStop(avRunLoop);
        }
        avThread = nil;
    }
}
