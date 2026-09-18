import Foundation

var smokeHookFires = 0

let smokeHookCb: @convention(c) (UnsafeMutableRawPointer?, UInt64, UInt32, UInt64) -> Void = { _, _, _, _ in
    smokeHookFires += 1
}

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

        let openRc = uni.openArch(4, mode: 8)
        check("b) x86-64 engine opens (rc=\(openRc))", openRc == 0)

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

        let hookMapRc = uni.memMap(0x20000, size: 0x1000, perms: 7)
        check("hook region mapped (rc=\(hookMapRc))", hookMapRc == 0)

        let nops: [UInt8] = [0x90, 0x90, 0x90]
        let w2 = uni.memWriteBytes(0x20000, bytes: nops)
        check("hook region code written (rc=\(w2))", w2 == 0)

        let cbPtr = unsafeBitCast(smokeHookCb, to: UnsafeMutableRawPointer.self)
        let hookRc = uni.hookAdd(type: 1, callback: cbPtr, userData: 0, begin: 0x20000, end: 0x20010)
        let hookHandle = uni.lastHook
        check("f) code hook installs (rc=\(hookRc), handle=\(hookHandle))", hookRc == 0 && hookHandle != 0)

        let runsPre = smokeHookFires
        let hr1 = uni.emuStart(0x20000, until: 0x20003, timeout: 0, count: 0)
        check("hooked region executes (rc=\(hr1))", hr1 == 0)
        let rip2 = uni.regReadU64(41)
        check("hooked region actually ran (RIP=0x\(String(rip2, radix: 16)))", rip2 == 0x20003)
        check("f) hook fired during execution (fires: \(smokeHookFires - runsPre))", smokeHookFires > runsPre)

        let delRc = uni.hookDel(hookHandle)
        check("hook removes (rc=\(delRc))", delRc == 0)

        let runsBase = smokeHookFires
        let hr2 = uni.emuStart(0x20000, until: 0x20003, timeout: 0, count: 0)
        check("region executes after hook removal (rc=\(hr2))", hr2 == 0)
        check("hook no longer fires (deltas: \(smokeHookFires - runsBase))", smokeHookFires == runsBase)

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