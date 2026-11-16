import Foundation
import Darwin

/// 本机 UDID 的三条获取路径，按可靠性从高到低依次尝试：
///
/// ① `DeviceUDID.fromLockdown()` —— 直接向本机 lockdownd 要 UniqueDeviceID。
///    这是签名工具通用的私有 API，成功则完全零操作。
/// ② 描述文件（Profile Service）—— 系统级、100% 可靠，但要用户点两下。
///    用 Safari 打开 docs/udid.mobileconfig，安装后自动跳回 `yzlsigner://`。
/// ③ 手动输入 / 导配对文件 —— 兜底。
enum DeviceUDID {

    // MARK: - ⓿ 从自己的描述文件里取

    /// 如果这个 App 是用「只有一台设备」的开发描述文件签的，
    /// 那 Profile 里的唯一 UDID 就是本机，零风险、零操作。
    /// 共享企业证书那种有几百台设备的，直接放弃（不做猜测）。
    static func fromOwnProfile() -> String? {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let raw = try? Data(contentsOf: url),
              let start = raw.range(of: Data("<?xml".utf8)),
              let end = raw.range(of: Data("</plist>".utf8)) else {
            return nil
        }
        let xml = raw.subdata(in: start.lowerBound..<end.upperBound)
        guard let dict = (try? PropertyListSerialization.propertyList(from: xml, format: nil)) as? [String: Any],
              let devices = dict["ProvisionedDevices"] as? [String],
              devices.count == 1,
              let only = devices.first,
              let value = normalize(only) else {
            return nil
        }
        return value
    }

    // MARK: - ① 私有 API

    /// dlopen liblockdown 读本机 UniqueDeviceID。
    /// 沙盒里可能被拒（返回 nil），所以调用侧必须容错。
    static func fromLockdown() -> String? {
        guard let handle = dlopen("/usr/lib/liblockdown.dylib", RTLD_NOW) else { return nil }
        defer { dlclose(handle) }

        typealias ConnectFn = @convention(c) () -> UnsafeMutableRawPointer?
        typealias CopyValueFn = @convention(c) (UnsafeMutableRawPointer?, CFString?, CFString?) -> Unmanaged<AnyObject>?
        typealias DisconnectFn = @convention(c) (UnsafeMutableRawPointer?) -> Void

        guard let connectSym = dlsym(handle, "lockdown_connect"),
              let copySym = dlsym(handle, "lockdown_copy_value") else {
            return nil
        }

        let connect = unsafeBitCast(connectSym, to: ConnectFn.self)
        let copyValue = unsafeBitCast(copySym, to: CopyValueFn.self)

        guard let conn = connect() else { return nil }
        defer {
            if let discardSym = dlsym(handle, "lockdown_disconnect") {
                unsafeBitCast(discardSym, to: DisconnectFn.self)(conn)
            }
        }

        // domain 传 NULL 表示 root domain
        guard let raw = copyValue(conn, nil, "UniqueDeviceID" as CFString) else { return nil }
        guard let value = raw.takeRetainedValue() as? String else { return nil }
        return normalize(value)
    }

    // MARK: - ② 描述文件回跳

    /// 处理 `yzlsigner://udid?...` 回跳。
    /// 设备安装 Profile Service 描述文件后，会把属性和 UDID 拼在 URL 后面，
    /// 具体拼法各系统版本略有差异，所以这里既认 query，也认整串正则。
    static func fromCallbackURL(_ url: URL) -> String? {
        guard url.scheme?.lowercased() == "yzlsigner" else { return nil }

        // 1) 标准 query：?UDID=00008110-...
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            for item in comps.queryItems ?? [] {
                let key = item.name.uppercased()
                if key == "UDID" || key == "U" || key == "UNIQUEIDENTIFIER" || key == "UNIQUEDEVICEID" {
                    if let v = item.value, let n = normalize(v) { return n }
                }
            }
        }

        // 2) 有些版本把 UDID 直接拼在 host/path 上
        let raw = url.absoluteString
        if let n = firstUDID(in: raw) { return n }
        return nil
    }

    // MARK: - ③ 配对文件 / 手动

    static func fromPairingFile(at url: URL) throws -> String {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: url)
        guard let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) else {
            throw SignError.message("不是有效的 plist 文件")
        }
        guard let dict = obj as? [String: Any] else {
            throw SignError.message("配对文件格式异常")
        }

        for key in ["UDID", "UniqueDeviceID", "udid", "UniqueDeviceIDString"] {
            if let v = dict[key] as? String, let n = normalize(v) { return n }
        }

        // StosVPN 那类隧道配置没有 UDID，提示用户换一份
        if dict["alt_irk"] != nil || dict["public_key"] != nil {
            throw SignError.message("这是 VPN 隧道配置，不是配对文件。请导入 StikDebug 导出的配对文件。")
        }
        throw SignError.message("文件里没有 UDID 字段")
    }

    // MARK: - 校验

    /// 校验并规范化。合法格式只有两种：
    /// - 40 位十六进制（iPhone X 及更早）
    /// - `8-16` 共 25 字符（iPhone XS 及之后，如 00008110-001A2C3E0AF8801E）
    static func normalize(_ raw: String) -> String? {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: " ", with: "")
            .uppercased()
        guard !t.isEmpty else { return nil }

        if t.count == 40, t.allSatisfy({ $0.isHexDigit }) {
            return t
        }

        let parts = t.split(separator: "-", omittingEmptySubsequences: false)
        if parts.count == 2, parts[0].count == 8, parts[1].count == 16,
           parts.allSatisfy({ $0.allSatisfy({ c in c.isHexDigit }) }) {
            return t
        }

        // 少数系统会带 `00008110-001A2C3E0AF8801E` 之外的变体，交给正则兜底
        if let n = firstUDID(in: t) { return n }
        return nil
    }

    static func firstUDID(in text: String) -> String? {
        let upper = text.uppercased()
        let patterns = [
            "[0-9A-F]{8}-[0-9A-F]{16}",
            "\\b[0-9A-F]{40}\\b",
        ]
        for p in patterns {
            if let re = try? NSRegularExpression(pattern: p) {
                let range = NSRange(upper.startIndex..<upper.endIndex, in: upper)
                if let m = re.firstMatch(in: upper, range: range),
                   let r = Range(m.range, in: upper) {
                    return String(upper[r])
                }
            }
        }
        return nil
    }
}

/// 外部 UDID 获取入口。
///
/// 说明：自己架 `Profile Service` 描述文件这条路在纯静态托管上走不通——
/// 系统把设备属性 **POST** 给回跳地址，GitHub Pages 对 POST 直接回 405，
/// 用户装完描述文件只会看到一页错误。所以这里改用有服务端处理的现成工具，
/// 用户拿到后回来粘贴即可。
enum UDIDProfile {
    static let profileURL = URL(string: "https://www.pgyer.com/tools/udid")!
    static let callbackScheme = "yzlsigner"
}
