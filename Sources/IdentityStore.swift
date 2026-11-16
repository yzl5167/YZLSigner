import Foundation
import SideSign

/// 本地保存自己的开发证书。
///
/// 免费 Apple ID 只有 2 个 Apple Development 证书名额。如果每次点「开始签名」
/// 都去新申请一个，第二次就会把第一次的撤销掉——用户在全能签里导入的那套
/// 证书也会同时失效。所以证书必须落地复用。
///
/// 存放位置：`Application Support/YZLSigner/`，随 App 沙盒的 Data Protection 加密。
final class IdentityStore: @unchecked Sendable {

    static let shared = IdentityStore()

    struct Meta: Codable {
        var serialNumber: String
        var teamIdentifier: String
        var expiryDate: Date
        var savedAt: Date
    }

    private let lock = NSLock()
    private let directory: URL

    private init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask)[0]
        directory = base.appendingPathComponent("YZLSigner", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutable = directory
        try? mutable.setResourceValues(values)
    }

    var p12URL: URL { directory.appendingPathComponent("identity.p12") }
    private var metaURL: URL { directory.appendingPathComponent("identity.json") }

    // MARK: - 读

    /// 读出可用的证书；过期、损坏、或不属于当前团队的一律当没有。
    func load(teamIdentifier: String? = nil) -> KeyStore? {
        lock.lock()
        defer { lock.unlock() }

        guard let metaData = try? Data(contentsOf: metaURL),
              let meta = try? JSONDecoder().decode(Meta.self, from: metaData),
              let p12 = try? Data(contentsOf: p12URL) else {
            return nil
        }

        // 过期前两天就当失效，别等到最后一刻
        guard meta.expiryDate.timeIntervalSinceNow > 2 * 86400 else { return nil }

        if let wanted = teamIdentifier,
           meta.teamIdentifier.caseInsensitiveCompare(wanted) != .orderedSame {
            return nil
        }

        guard let store = try? KeyStore(p12Data: p12, password: SignerDefaults.p12Password) else {
            return nil
        }
        // p12 里的证书和元数据必须对得上，避免文件被替换
        guard store.certificate.serialNumberHex.caseInsensitiveCompare(meta.serialNumber) == .orderedSame,
              store.certificate.expiryDate.timeIntervalSinceNow > 2 * 86400 else {
            return nil
        }
        return store
    }

    func savedMeta() -> Meta? {
        lock.lock()
        defer { lock.unlock() }
        guard let data = try? Data(contentsOf: metaURL) else { return nil }
        return try? JSONDecoder().decode(Meta.self, from: data)
    }

    // MARK: - 写

    func save(_ store: KeyStore, teamIdentifier: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let p12 = try store.exportP12(password: SignerDefaults.p12Password)
        try p12.write(to: p12URL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])

        let meta = Meta(serialNumber: store.certificate.serialNumberHex,
                        teamIdentifier: teamIdentifier,
                        expiryDate: store.certificate.expiryDate,
                        savedAt: Date())
        let data = try JSONEncoder().encode(meta)
        try data.write(to: metaURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        try? FileManager.default.removeItem(at: p12URL)
        try? FileManager.default.removeItem(at: metaURL)
    }

    /// 服务器上这张证书还在不在。被别的设备/工具撤销过就不能再用来签名。
    func isStillOnServer(_ store: KeyStore, team: Team, session: Session,
                         portal: DeveloperPortal) async -> Bool {
        guard let list = try? await portal.fetchCertificates(for: team, session: session) else {
            // 网络问题不该阻断签名，乐观放行
            return true
        }
        return list.contains {
            $0.serialNumberHex.caseInsensitiveCompare(store.certificate.serialNumberHex) == .orderedSame
        }
    }
}
