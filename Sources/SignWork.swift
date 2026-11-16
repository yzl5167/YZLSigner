import Foundation
import SideSign
import ZIPFoundation

struct SignResult: Sendable {
    let signedIPA: URL
    let p12: URL?
    let profile: URL?
    let bytes: Int
}

/// 从后台线程回主线程汇报用。全部是 @Sendable 闭包，实现方自己 dispatch。
struct SignHooks: Sendable {
    var log: @Sendable (String) -> Void
    var stage: @Sendable (String) -> Void
    var fraction: @Sendable (Double?) -> Void
}

/// 真正的签名流水线。
///
/// 这个类刻意不继承 MainActor：`CodeSigner.sign` 是同步阻塞的，一个 291MB
/// 的包要处理几千个文件，跑在主线程上界面会整段冻住，还会被系统 watchdog 杀掉。
/// 所有 UI 更新都通过 `SignHooks` 回抛。
final class SignWork: @unchecked Sendable {

    private let hooks: SignHooks
    private let lock = NSLock()
    private var cancelled = false

    init(hooks: SignHooks) {
        self.hooks = hooks
    }

    var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
    }

    // MARK: - 汇报

    private func log(_ s: String) { hooks.log(s) }
    private func stage(_ s: String) { hooks.stage(s) }
    private func fraction(_ v: Double?) { hooks.fraction(v) }

    private func checkCancel() throws {
        if isCancelled { throw SignError.message("已取消") }
    }

    // MARK: - 主流程

    func run(ipaURL: URL, udid: String, appleID: String, password: String,
             broker: CodeBroker) async throws -> SignResult {

        // ⓿ 磁盘空间：解压 + 签名 + 重新打包，峰值约 3 倍
        let ipaSize = (try? FileManager.default.attributesOfItem(atPath: ipaURL.path)[.size] as? Int) ?? 0
        let needed = Int(Double(ipaSize) * 3.2) + 200 * 1024 * 1024
        if let free = Self.freeSpace(), free < Int64(needed) {
            throw SignError.message("""
            存储空间不够：这个包约 \(Self.mb(ipaSize))，签名过程需要约 \(Self.mb(needed)) 可用空间，当前只剩 \(Self.mb(Int(free)))。
            先清一些空间再试。
            """)
        }

        // ① anisette
        stage("获取设备身份")
        log("① 获取设备身份数据…")
        let anisette = try await AnisetteClient.fetch()
        log("   成功")
        try checkCancel()

        // ② 登录
        stage("登录 Apple ID")
        log("② 登录 Apple ID…")
        let portal = DeveloperPortal()
        let auth = try await portal.authenticate(
            appleID: appleID,
            password: password,
            anisetteData: anisette,
            xcodeVersion: "16.0",
            verificationHandler: { _ in
                let code = await broker.requestCode()
                let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? .cancel : .verificationCode(trimmed)
            }
        )
        log("   登录成功")
        try checkCancel()

        // ③ 团队
        stage("读取团队")
        log("③ 读取团队…")
        let teams = try await portal.fetchTeams(for: auth.account, session: auth.session)
        guard let team = teams.first else {
            throw SignError.message("这个 Apple ID 下没有可用团队。先到 developer.apple.com 用同一账号登录并同意协议。")
        }
        log("   \(team.name)（\(team.type.displayName)）")
        if team.type == .free {
            log("   免费账号：证书 7 天有效，签出的包到期要重签")
        }
        try checkCancel()

        // ④ 解压
        stage("解压 ipa")
        log("④ 解压 ipa（\(Self.mb(ipaSize))，需要几分钟）…")
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("YZLSign-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: workDir) }

        try FileManager.default.unzipItem(at: ipaURL, to: workDir)
        try checkCancel()

        let payload = workDir.appendingPathComponent("Payload", isDirectory: true)
        let entries = try FileManager.default.contentsOfDirectory(at: payload, includingPropertiesForKeys: nil)
        guard let appURL = entries.first(where: { $0.pathExtension == "app" }) else {
            throw SignError.message("ipa 结构异常：Payload 里没有 .app")
        }
        let bundleID = try Self.readBundleID(appURL)
        log("   \(appURL.lastPathComponent)  \(bundleID)")

        // ⑤ 注册设备
        stage("注册设备")
        log("⑤ 注册本机 UDID…")
        let device = try await ensureDevice(portal: portal, udid: udid, team: team, session: auth.session)
        log("   \(device.identifier)")
        try checkCancel()

        // ⑥ 证书（优先复用本地，绝不重复新建）
        stage("准备证书")
        log("⑥ 准备开发证书…")
        let keyStore = try await ensureCertificate(portal: portal, team: team, session: auth.session)
        log("   证书就绪  \(abbreviate(keyStore.certificate.serialNumberHex))")
        try checkCancel()

        // ⑦ App ID
        stage("准备 App ID")
        log("⑦ 准备 App ID…")
        let appID = try await ensureAppID(portal: portal, bundleID: bundleID, team: team, session: auth.session)
        log("   \(appID.bundleIdentifier)")
        try checkCancel()

        // ⑧ 描述文件（本地有可用的就不去麻烦服务器）
        stage("生成描述文件")
        let profile: ProvisioningProfile
        if let cached = IdentityStore.shared.loadProfile(
            bundleID: bundleID,
            udid: device.identifier,
            certSerial: keyStore.certificate.serialNumberHex) {
            profile = cached
            log("⑧ 复用本机描述文件（\(Self.dateString(cached.expirationDate)) 到期），不新建")
        } else {
            log("⑧ 生成开发描述文件…")
            profile = try await portal.createProvisioningProfile(
                name: "YZL Dev \(Self.stamp())",
                appID: appID,
                certificateIDs: [keyStore.certificate.serialNumberHex],
                deviceIDs: [device.identifier],
                team: team,
                session: auth.session
            )
            IdentityStore.shared.saveProfile(profile)
            log("   有效期至 \(Self.dateString(profile.expirationDate))")
        }
        try checkCancel()

        // ⑨ 签名（长活，带心跳）
        stage("签名中")
        let total = Self.fileCount(appURL)
        log("⑨ 签名 \(total) 个文件…")
        try await signWithHeartbeat(appURL: appURL, team: team,
                                    keyStore: keyStore, profile: profile)
        log("   签名完成")
        try checkCancel()

        // ⑩ 校验
        stage("校验")
        log("⑩ 校验描述文件…")
        let facts = try Self.inspectProfile(in: appURL, udid: udid)
        log("   本机 UDID 在列表里：\(facts.hasDevice ? "是" : "否")")
        log("   get-task-allow：\(facts.entitlements["get-task-allow"] ?? "缺失")")
        log("   application-identifier：\(facts.entitlements["application-identifier"] ?? "缺失")")
        guard facts.hasDevice else {
            throw SignError.message("描述文件里没有本机 UDID（\(udid)），装上去会提示无法安装")
        }
        guard facts.getTaskAllow else {
            throw SignError.message("描述文件没带 get-task-allow，签出来 StikDebug 用不了 JIT")
        }

        // ⑪ 打包
        stage("打包")
        log("⑪ 打包 ipa…")
        try checkCancel()
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stem = ipaURL.deletingPathExtension().lastPathComponent
            .replacingOccurrences(of: "input-", with: "")
        let outURL = docs.appendingPathComponent("\(stem)-signed.ipa")
        try? FileManager.default.removeItem(at: outURL)
        try FileManager.default.zipItem(at: payload, to: outURL, shouldKeepParent: true)

        let size = (try? FileManager.default.attributesOfItem(atPath: outURL.path)[.size] as? Int) ?? 0

        // ⑫ 导出证书
        stage("导出证书")
        log("⑫ 导出证书…")
        let p12 = docs.appendingPathComponent("yzl-signing.p12")
        let prof = docs.appendingPathComponent("yzl-signing.mobileprovision")
        var p12Out: URL?
        var profOut: URL?
        do {
            try? FileManager.default.removeItem(at: p12)
            try? FileManager.default.removeItem(at: prof)
            try keyStore.exportP12(password: SignerDefaults.p12Password).write(to: p12)
            try profile.data.write(to: prof)
            p12Out = p12
            profOut = prof
            log("   yzl-signing.p12（密码 \(SignerDefaults.p12Password)）")
            log("   yzl-signing.mobileprovision")
        } catch {
            log("   证书导出失败：\(error.localizedDescription)")
        }

        log("")
        log("✅ 完成")
        log("   \(outURL.lastPathComponent)  \(Self.mb(size))")
        return SignResult(signedIPA: outURL, p12: p12Out, profile: profOut, bytes: size)
    }

    // MARK: - 签名 + 心跳

    /// Progress 会在签名线程里被 CodeSigner 更新，UI 线程又要读。
    /// 包一层，避免并发语义上的麻烦。
    private final class ProgressBox: @unchecked Sendable {
        private let lock = NSLock()
        private let progress = Progress(totalUnitCount: 1)

        var raw: Progress { progress }

        var fraction: Double {
            lock.lock(); defer { lock.unlock() }
            return progress.fractionCompleted
        }
    }

    private func signWithHeartbeat(appURL: URL, team: Team,
                                   keyStore: KeyStore,
                                   profile: ProvisioningProfile) async throws {
        let box = ProgressBox()
        let started = Date()

        let ticker = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        ticker.schedule(deadline: .now() + 4, repeating: 4)
        ticker.setEventHandler { [weak self] in
            guard let self else { return }
            let value = box.fraction
            if value.isFinite, value > 0 {
                self.fraction(min(value, 1.0))
            }
            let elapsed = Int(Date().timeIntervalSince(started))
            if elapsed % 20 < 5 {
                self.log("   仍在签名… \(elapsed) 秒")
            }
        }
        ticker.resume()
        defer { ticker.cancel() }

        let signer = AppBundleSigner(team: team, keyStore: keyStore)
        try await signer.signApp(at: appURL, provisioningProfiles: [profile], progress: box.raw)
    }

    // MARK: - 幂等化

    private func ensureDevice(portal: DeveloperPortal, udid: String,
                              team: Team, session: Session) async throws -> Device {
        if let list = try? await portal.fetchDevices(for: team, session: session),
           let hit = list.first(where: { $0.identifier.caseInsensitiveCompare(udid) == .orderedSame }) {
            log("   设备已注册，直接复用")
            return hit
        }
        do {
            return try await portal.registerDevice(name: "iPhone", identifier: udid,
                                                   type: .iPhone, team: team, session: session)
        } catch {
            if let list = try? await portal.fetchDevices(for: team, session: session),
               let hit = list.first(where: { $0.identifier.caseInsensitiveCompare(udid) == .orderedSame }) {
                log("   设备已注册，直接复用")
                return hit
            }
            throw error
        }
    }

    /// 优先复用本地保存的证书；只有真的没有可用证书时才去申请。
    private func ensureCertificate(portal: DeveloperPortal,
                                   team: Team, session: Session) async throws -> KeyStore {
        if let cached = IdentityStore.shared.load(teamIdentifier: team.identifier) {
            if await IdentityStore.shared.isStillOnServer(cached, team: team, session: session, portal: portal) {
                let days = Int(cached.certificate.expiryDate.timeIntervalSinceNow / 86400)
                log("   复用本机已保存的证书（还剩 \(days) 天），不占用新名额")
                return cached
            }
            log("   本地证书已被撤销，重新申请")
            IdentityStore.shared.clear()
        }

        // 名额是 2 个。只在建新证书前清理，平时不动别人的。
        if let list = try? await portal.fetchCertificates(for: team, session: session),
           list.count >= 2 {
            log("   证书名额已用 \(list.count) 个，撤销最旧的一个")
            if let oldest = list.sorted(by: { $0.creationDate < $1.creationDate }).first {
                _ = try? await portal.revokeCertificate(oldest, for: team, session: session)
            }
        }

        let store: KeyStore
        do {
            store = try await portal.addCertificate(machineName: "YZL Signer",
                                                    type: .development,
                                                    to: team, session: session)
        } catch {
            guard let list = try? await portal.fetchCertificates(for: team, session: session),
                  !list.isEmpty else { throw error }
            log("   名额仍占满，清空后重试…")
            for cert in list {
                _ = try? await portal.revokeCertificate(cert, for: team, session: session)
            }
            store = try await portal.addCertificate(machineName: "YZL Signer",
                                                    type: .development,
                                                    to: team, session: session)
        }

        do {
            try IdentityStore.shared.save(store, teamIdentifier: team.identifier)
            log("   新证书已保存到本机，下次直接复用")
        } catch {
            log("   ⚠️ 证书没能保存（\(error.localizedDescription)），下次会重新申请")
        }
        return store
    }

    private func ensureAppID(portal: DeveloperPortal, bundleID: String,
                             team: Team, session: Session) async throws -> AppID {
        if let list = try? await portal.fetchAppIDs(for: team, session: session),
           let hit = list.first(where: { $0.bundleIdentifier.caseInsensitiveCompare(bundleID) == .orderedSame }) {
            log("   App ID 已存在，直接复用")
            return hit
        }
        do {
            return try await portal.addAppID(withName: "YZL \(bundleID.suffix(28))",
                                             bundleIdentifier: bundleID,
                                             team: team, session: session)
        } catch {
            if let list = try? await portal.fetchAppIDs(for: team, session: session),
               let hit = list.first(where: { $0.bundleIdentifier.caseInsensitiveCompare(bundleID) == .orderedSame }) {
                log("   App ID 已存在，直接复用")
                return hit
            }
            throw error
        }
    }

    // MARK: - 工具

    struct ProfileFacts {
        var hasDevice: Bool
        var getTaskAllow: Bool
        var entitlements: [String: String]
    }

    static func readBundleID(_ appURL: URL) throws -> String {
        let data = try Data(contentsOf: appURL.appendingPathComponent("Info.plist"))
        guard let dict = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let bid = dict["CFBundleIdentifier"] as? String else {
            throw SignError.message("读不到 Info.plist 里的 CFBundleIdentifier")
        }
        return bid
    }

    /// 解析签名后真实写入的 embedded.mobileprovision，
    /// 直接确认「装得上」和「有 get-task-allow」，不靠猜。
    static func inspectProfile(in appURL: URL, udid: String) throws -> ProfileFacts {
        let raw = try Data(contentsOf: appURL.appendingPathComponent("embedded.mobileprovision"))
        guard let start = raw.range(of: Data("<?xml".utf8)),
              let end = raw.range(of: Data("</plist>".utf8)) else {
            throw SignError.message("描述文件不是可解析的 plist")
        }
        let xml = raw.subdata(in: start.lowerBound..<end.upperBound)
        guard let dict = (try? PropertyListSerialization.propertyList(from: xml, format: nil)) as? [String: Any] else {
            throw SignError.message("描述文件解析失败")
        }

        let devices = (dict["ProvisionedDevices"] as? [String]) ?? []
        let target = (dict["Entitlements"] as? [String: Any]) ?? [:]

        var flat: [String: String] = [:]
        for (k, v) in target {
            if let s = v as? String { flat[k] = s }
            else if let b = v as? Bool { flat[k] = b ? "true" : "false" }
            else if let arr = v as? [String] { flat[k] = arr.joined(separator: ", ") }
            else { flat[k] = String(describing: v) }
        }

        let allow = (target["get-task-allow"] as? Bool)
            ?? ((target["get-task-allow"] as? String)?.lowercased() == "true")
        let hasDevice = devices.contains { $0.caseInsensitiveCompare(udid) == .orderedSame }
        return ProfileFacts(hasDevice: hasDevice, getTaskAllow: allow, entitlements: flat)
    }

    static func freeSpace() -> Int64? {
        let url = URL(fileURLWithPath: NSHomeDirectory())
        guard let values = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]) else {
            return nil
        }
        return values.volumeAvailableCapacityForImportantUsage
    }

    static func fileCount(_ root: URL) -> Int {
        guard let e = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey],
                                                     options: [.skipsHiddenFiles]) else { return 0 }
        var n = 0
        for case let url as URL in e {
            if (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true { n += 1 }
        }
        return n
    }

    private func abbreviate(_ s: String) -> String {
        s.count > 16 ? String(s.prefix(16)) + "…" : s
    }

    static func mb(_ bytes: Int) -> String {
        String(format: "%.1f MB", Double(bytes) / 1048576.0)
    }

    static func dateString(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "MM-dd HH:mm"
        f.timeZone = TimeZone.current
        return f.string(from: date)
    }

    static func stamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "MMdd-HHmmss"
        f.timeZone = TimeZone.current
        return f.string(from: Date())
    }
}
