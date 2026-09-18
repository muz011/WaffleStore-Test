import Foundation

@objc class WFSSwiftUnicorn: NSObject {

    private var handle: UnsafeMutableRawPointer?
    private var _open: (@convention(c) (UInt32, UInt32, UnsafeMutablePointer<UnsafeMutableRawPointer?>) -> Int32)?
    private var _close: (@convention(c) (UnsafeMutableRawPointer?) -> Int32)?
    private var _memMap: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UInt64, UInt32) -> Int32)?
    private var _memUnmap: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UInt64) -> Int32)?
    private var _memRead: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UnsafeMutableRawPointer?, UInt64) -> Int32)?
    private var _memWrite: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UnsafeRawPointer?, UInt64) -> Int32)?
    private var _regRead: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutableRawPointer?) -> Int32)?
    private var _regWrite: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeRawPointer?) -> Int32)?
    private var _emuStart: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UInt64, UInt64, UInt64) -> Int32)?
    private var _emuStop: (@convention(c) (UnsafeMutableRawPointer?) -> Int32)?
    private var _hookAdd: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?, Int32, UnsafeMutableRawPointer?, UInt64, UInt64, UInt64) -> Int32)?
    private var _hookDel: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Int32)?
    private var _strerror: (@convention(c) (Int32) -> UnsafePointer<CChar>?)?

    @objc private(set) var engine: UnsafeMutableRawPointer?

    @objc class func create() -> WFSSwiftUnicorn? {
        let instance = WFSSwiftUnicorn()
        return instance.isLoaded ? instance : nil
    }

    private override init() {
        super.init()
        guard loadLibrary() else { return }
    }

    private func loadLibrary() -> Bool {
        var libHandle = dlopen("libunicorn.2.dylib", RTLD_NOW)
        if libHandle == nil {
            libHandle = dlopen("libunicorn.dylib", RTLD_NOW)
        }
        if let override = getenv("WFS_UNICORN_LIB") {
            let path = String(cString: override)
            if !path.isEmpty, let h = dlopen(path, RTLD_NOW) {
                libHandle = h
            }
        }
        guard let libHandle = libHandle else {
            if let d = dlerror() {
                loadError = String(cString: d)
            } else {
                loadError = "libunicorn dylib not found"
            }
            return false
        }
        self.handle = libHandle

        _open = unsafeBitCast(dlsym(libHandle, "uc_open"), to: (@convention(c) (UInt32, UInt32, UnsafeMutablePointer<UnsafeMutableRawPointer?>) -> Int32).self)
        _close = unsafeBitCast(dlsym(libHandle, "uc_close"), to: (@convention(c) (UnsafeMutableRawPointer?) -> Int32).self)
        _memMap = unsafeBitCast(dlsym(libHandle, "uc_mem_map"), to: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UInt64, UInt32) -> Int32).self)
        _memUnmap = unsafeBitCast(dlsym(libHandle, "uc_mem_unmap"), to: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UInt64) -> Int32).self)
        _memRead = unsafeBitCast(dlsym(libHandle, "uc_mem_read"), to: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UnsafeMutableRawPointer?, UInt64) -> Int32).self)
        _memWrite = unsafeBitCast(dlsym(libHandle, "uc_mem_write"), to: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UnsafeRawPointer?, UInt64) -> Int32).self)
        _regRead = unsafeBitCast(dlsym(libHandle, "uc_reg_read"), to: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutableRawPointer?) -> Int32).self)
        _regWrite = unsafeBitCast(dlsym(libHandle, "uc_reg_write"), to: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeRawPointer?) -> Int32).self)
        _emuStart = unsafeBitCast(dlsym(libHandle, "uc_emu_start"), to: (@convention(c) (UnsafeMutableRawPointer?, UInt64, UInt64, UInt64, UInt64) -> Int32).self)
        _emuStop = unsafeBitCast(dlsym(libHandle, "uc_emu_stop"), to: (@convention(c) (UnsafeMutableRawPointer?) -> Int32).self)
        _hookAdd = unsafeBitCast(dlsym(libHandle, "uc_hook_add"), to: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?, Int32, UnsafeMutableRawPointer?, UInt64, UInt64, UInt64) -> Int32).self)
        _hookDel = unsafeBitCast(dlsym(libHandle, "uc_hook_del"), to: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Int32).self)
        _strerror = unsafeBitCast(dlsym(libHandle, "uc_strerror"), to: (@convention(c) (Int32) -> UnsafePointer<CChar>?).self)

        guard _open != nil, _close != nil, _memMap != nil, _memUnmap != nil,
              _memRead != nil, _memWrite != nil, _regRead != nil, _regWrite != nil,
              _emuStart != nil, _emuStop != nil, _hookAdd != nil, _hookDel != nil,
              _strerror != nil else {
            loadError = "libunicorn missing required API symbols"
            dlclose(libHandle)
            self.handle = nil
            return false
        }
        return true
    }

    @objc var isLoaded: Bool { return handle != nil }

    @objc private(set) var loadError: String = ""

    @objc func openArch(_ arch: UInt32, mode: UInt32) -> Int32 {
        guard let fn = _open else { return -1 }
        var eng: UnsafeMutableRawPointer?
        let rc = fn(arch, mode, &eng)
        if rc == 0 { self.engine = eng }
        return rc
    }

    @objc func closeEngine() {
        if let eng = engine, let fn = _close {
            _ = fn(eng)
        }
        engine = nil
    }

    @objc func memMap(_ address: UInt64, size: UInt64, perms: UInt32) -> Int32 {
        guard let fn = _memMap, let eng = engine else { return -1 }
        return fn(eng, address, size, perms)
    }

    @objc func memUnmap(_ address: UInt64, size: UInt64) -> Int32 {
        guard let fn = _memUnmap, let eng = engine else { return -1 }
        return fn(eng, address, size)
    }

    @objc func memRead(_ address: UInt64, buffer: UnsafeMutableRawPointer, size: UInt64) -> Int32 {
        guard let fn = _memRead, let eng = engine else { return -1 }
        return fn(eng, address, buffer, size)
    }

    @objc func memWrite(_ address: UInt64, data: UnsafeRawPointer, size: UInt64) -> Int32 {
        guard let fn = _memWrite, let eng = engine else { return -1 }
        return fn(eng, address, data, size)
    }

    @objc func regRead(_ regid: Int32, value: UnsafeMutableRawPointer) -> Int32 {
        guard let fn = _regRead, let eng = engine else { return -1 }
        return fn(eng, regid, value)
    }

    @objc func regWrite(_ regid: Int32, value: UnsafeRawPointer) -> Int32 {
        guard let fn = _regWrite, let eng = engine else { return -1 }
        return fn(eng, regid, value)
    }

    @objc func emuStart(_ begin: UInt64, until: UInt64, timeout: UInt64, count: UInt64) -> Int32 {
        guard let fn = _emuStart, let eng = engine else { return -1 }
        return fn(eng, begin, until, timeout, count)
    }

    @objc func emuStop() -> Int32 {
        guard let fn = _emuStop, let eng = engine else { return -1 }
        return fn(eng)
    }

    @objc private(set) var lastHook: UInt64 = 0

    @objc(hookAdd:callback:userData:begin:end:)
    func hookAdd(type: Int32, callback: UnsafeMutableRawPointer?, userData: UInt64, begin: UInt64, end: UInt64) -> Int32 {
        guard let fn = _hookAdd, let eng = engine else { return -1 }
        var hookPtr: UnsafeMutableRawPointer?
        let rc = fn(eng, &hookPtr, type, callback, userData, begin, end)
        if let ptr = hookPtr {
            lastHook = UInt64(Int(bitPattern: ptr))
        } else {
            lastHook = 0
        }
        return rc
    }

    @objc func hookDel(_ hook: UInt64) -> Int32 {
        guard let fn = _hookDel, let eng = engine else { return -1 }
        let ptr = UnsafeMutableRawPointer(bitPattern: Int(hook))
        return fn(eng, ptr)
    }

    @objc func strerror(_ code: Int32) -> String {
        guard let fn = _strerror else { return "unknown error" }
        return fn(code).map(String.init(cString:)) ?? "unknown error"
    }

    @objc func memWriteBytes(_ address: UInt64, bytes: [UInt8]) -> Int32 {
        return bytes.withUnsafeBufferPointer { buf in
            guard let ptr = buf.baseAddress else { return -1 }
            return memWrite(address, data: ptr, size: UInt64(bytes.count))
        }
    }

    @objc func memReadBytes(_ address: UInt64, count: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: count)
        let rc = buf.withUnsafeMutableBufferPointer { mbuf -> Int32 in
            guard let ptr = mbuf.baseAddress else { return -1 }
            return memRead(address, buffer: ptr, size: UInt64(count))
        }
        return rc == 0 ? buf : nil
    }

    @objc func regReadU64(_ regid: Int32) -> UInt64 {
        var val: UInt64 = 0
        _ = regRead(regid, value: &val)
        return val
    }

    @objc func regWriteU64(_ regid: Int32, _ value: UInt64) {
        var v = value
        _ = regWrite(regid, value: &v)
    }

    deinit {
        closeEngine()
        if let h = handle { dlclose(h) }
    }
}
