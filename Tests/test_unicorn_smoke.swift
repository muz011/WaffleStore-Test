import Foundation

@main
struct UnicornSmokeTest {

    static var failures = 0

    static func check(_ label: String, _ ok: Bool) {
        if ok {
            print("PASS: \(label)")
        } else {
            print("FAIL: \(label)")
            failures += 1
        }
    }

    static func main() {
        guard let uni = WFSSwiftUnicorn.create() else {
            print("FAIL: libunicorn did not load")
            exit(2)
        }
        check("a) libunicorn loads", true)

        let ver = uni.libraryVersion()
        check("a) runtime version reported (\(ver))", !ver.isEmpty && ver != "unknown")

        let openRc = uni.openArch(4, mode: 8)
        check("b) x86-64 engine opens (rc=\(openRc))", openRc == 0)

        let errnoVal = uni.lastErrno()
        check("b) uc_errno queryable (val=\(errnoVal))", errnoVal == 0)

        let mapRc = uni.memMap(0x10000, size: 0x1000, perms: 7)
        check("c) memory can be mapped (rc=\(mapRc))", mapRc == 0)

        let movRax: [UInt8] = [0x48, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let w1 = uni.memWriteBytes(0x10000, bytes: movRax)
        check("write mov rax, 0x1234 (rc=\(w1))", w1 == 0)

        uni.regWriteU64(35, 0)
        uni.regWriteU64(41, 0x10000)

        let startRc = uni.emuStart(0x10000, until: 0x1000a, timeout: 0, count: 0)
        check("d) instruction sequence executes (rc=\(startRc), strerror=\(uni.strerror(startRc)))", startRc == 0)

        let rax = uni.regReadU64(35)
        check("e) registers readable/writable (RAX=0x\(String(rax, radix: 16)))", rax == 0x1234)

        let rip = uni.regReadU64(41)
        check("execution reached end (RIP=0x\(String(rip, radix: 16)))", rip == 0x1000a)

        guard let cbPtr = dlsym(dlopen(nil, RTLD_NOW), "wfs_smoke_hook_cb"),
              let countSym = dlsym(dlopen(nil, RTLD_NOW), "wfs_smoke_hook_count") else {
            print("FAIL: resolve C hook helper symbols")
            exit(1)
        }
        let hookCount = unsafeBitCast(countSym, to: (@convention(c) () -> UInt64).self)

        let hookMapRc = uni.memMap(0x20000, size: 0x1000, perms: 7)
        check("hook region mapped (rc=\(hookMapRc))", hookMapRc == 0)

        let nops: [UInt8] = [0x90, 0x90, 0x90]
        let w2 = uni.memWriteBytes(0x20000, bytes: nops)
        check("hook region code written (rc=\(w2))", w2 == 0)

        let hookRc = uni.hookAdd(type: 4, callback: cbPtr, userData: 0, begin: 0x20000, end: 0x20010)
        let hookHandle = uni.lastHook
        check("f) ranged code hook installs (rc=\(hookRc), handle=\(hookHandle))", hookRc == 0 && hookHandle != 0)

        let rangedBefore = hookCount()
        let hr1 = uni.emuStart(0x20000, until: 0x20003, timeout: 0, count: 0)
        check("hooked region executes (rc=\(hr1))", hr1 == 0)
        let rip2 = uni.regReadU64(41)
        check("hooked region actually ran (RIP=0x\(String(rip2, radix: 16)))", rip2 == 0x20003)
        check("f) ranged hook fired during execution (fires: \(hookCount() - rangedBefore))", hookCount() > rangedBefore)

        let delRc = uni.hookDel(hookHandle)
        check("hook removes (rc=\(delRc))", delRc == 0)

        let delBase = hookCount()
        let hr2 = uni.emuStart(0x20000, until: 0x20003, timeout: 0, count: 0)
        check("region executes after hook removal (rc=\(hr2))", hr2 == 0)
        let rip3 = uni.regReadU64(41)
        check("post-removal run still reaches end (RIP=0x\(String(rip3, radix: 16)))", rip3 == 0x20003)
        check("hook no longer fires (deltas: \(hookCount() - delBase))", hookCount() == delBase)

        let map3Rc = uni.memMap(0x30000, size: 0x1000, perms: 7)
        check("second region mapped (rc=\(map3Rc))", map3Rc == 0)
        let w3 = uni.memWriteBytes(0x30000, bytes: nops)
        check("second region code written (rc=\(w3))", w3 == 0)

        let hook2Rc = uni.hookAdd(type: 4, callback: cbPtr, userData: 0, begin: 0x30000, end: 0x30010)
        let hook2Handle = uni.lastHook
        check("second ranged code hook installs (rc=\(hook2Rc), handle=\(hook2Handle))", hook2Rc == 0 && hook2Handle != 0)

        let secondBefore = hookCount()
        let hr3 = uni.emuStart(0x30000, until: 0x30003, timeout: 0, count: 0)
        check("second region executes (rc=\(hr3))", hr3 == 0)
        let rip4 = uni.regReadU64(41)
        check("second region actually ran (RIP=0x\(String(rip4, radix: 16)))", rip4 == 0x30003)
        check("second ranged hook fires (fires: \(hookCount() - secondBefore))", hookCount() > secondBefore)

        _ = uni.hookDel(hook2Handle)

        guard let memCb = dlsym(dlopen(nil, RTLD_NOW), "wfs_smoke_mem_cb"),
              let memCountSym = dlsym(dlopen(nil, RTLD_NOW), "wfs_smoke_mem_count") else {
            print("FAIL: resolve C mem hook helper symbols")
            exit(1)
        }
        let memHookCount = unsafeBitCast(memCountSym, to: (@convention(c) () -> UInt64).self)

        let memHookType = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9)
        let memHookRc = uni.hookAdd(type: memHookType, callback: memCb, userData: 0, begin: 1, end: 0)
        let memHookHandle = uni.lastHook
        check("h) mem fault hook installs (rc=\(memHookRc), handle=\(memHookHandle))", memHookRc == 0 && memHookHandle != 0)

        let memBefore = memHookCount()
        let badRc = uni.emuStart(0x50000, until: 0x50005, timeout: 0, count: 0)
        check("unmapped fetch faults (rc=\(badRc))", badRc != 0)
        check("h) mem fault hook fired (fires: \(memHookCount() - memBefore))", memHookCount() > memBefore)

        let memDelRc = uni.hookDel(memHookHandle)
        check("mem fault hook removes (rc=\(memDelRc))", memDelRc == 0)

        uni.closeEngine()
        check("g) engine closes cleanly (engine=nil: \(uni.engine == nil))", uni.engine == nil)

        if failures == 0 {
            print("ALL UNICORN SMOKE TESTS PASSED")
        } else {
            print("\(failures) UNICORN SMOKE TEST(S) FAILED")
        }
        exit(failures == 0 ? 0 : 1)
    }
}