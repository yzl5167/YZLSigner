import Foundation
import Combine
import SideSign
import ZIPFoundation

enum SignerDefaults {
    /// 导出给第三方签名工具（全能签 / Feather / ESign）的 p12 密码。
    static let p12Password = "yzl123"
}

/// 在 2FA 处理闭包（@Sendable）与主线程 UI 之间传递验证码。
final class CodeBroker: @unchecked Sendable {
    private var continuation: CheckedContinuation<String, Never>?
    private let lock = NSLock()
    var onNeedCode: (@Sendable () -> Void)?

    func requestCode() async -> String {
        await withCheckedContinuation { (c: CheckedContinuation<String, Never>) in
            lock.lock()
            continuation = c
            lock.unlock()
            onNeedCode?()
        }
    }

    func supply(_ code: String) {
        lock.lock()
        let c = continuation
        continuation = nil
        lock.unlock()
        c?.resume(returning: code)
    }
}

@MainActor
final class SignerEngine: ObservableObject {
    @Published var logs: [String] = []
    @Published var busy = false
    @Published var needsCode = false
    @Published var outputPath: String?
    @Published var p12Path: String?
    @Published var profilePath: String?
    @Published var stage = ""

    /// 导出给第三方签名工具（全能签 / Feather / ESign）用的 p12 密码。
    static let p12Password = SignerDefaults.p12Password

    let broker = CodeBroker()

    func append(_ line: String) {
        logs.append(line)
        if logs.count > 800 { logs.removeFirst(logs.count - 800) }
    }

    func supply(code: String) {
        needsCode = false
        broker.supply(code)
    }

    func run(ipaURL: URL, udid: String, appleID: String, password: String) async {
        guard !busy else { return }
        busy = true
        outputPath = nil
        p12Path = nil
        profilePath = nil
        logs.removeAll()
        defer { busy = false; stage = "" }

        let brokerRef = broker
        broker.onNeedCode = { [weak self] in
            DispatchQueue.main.async {
                guard let self else { return }
                self.needsCode = true
                self.stage = "等待验证码"
                self.append("   ⚠️ 需要双重认证验证码，请查看受信任设备")
            }
        }

        do {
            try await perform(ipaURL: ipaURL, udid: udid, appleID: appleID,
                              password: password, broker: brokerRef)
        } catch {
            append("")
            append("❌ 失败：\(friendly(error))")
        }
    }

    private func friendly(_ error: Error) -> String {
        let text = error.localizedDescription
        if text.contains("No profiles") || text.contains("no team") {
            return text + "\n这个 Apple ID 还没开通开发者身份。先去 developer.apple.com 用同一账号登录并同意协议，再回来重试。"
        }
        if text.contains("maximum") || text.contains("Maximum") {
            return text + "\n账号名额满了。删掉一个旧 App ID 或旧证书再试。"
        }
        return text
    }

    private func perform(ipaURL: URL, udid: String, appleID: String,
                         password: String, broker: CodeBroker) async throws {

        // ① anisette
        stage = "获取设备身份"
        append("① 获取设备身份数据…")
        let anisette = try await AnisetteClient.fetch()
        append("   成功")

        // ② 登录
        stage = "登录 Apple ID"
        append("② 登录 Apple ID…")
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
        append("   登录成功")

        // ③ 团队
        stage = "读取团队"
        append("③ 读取团队…")
        let teams = try await portal.fetchTeams(for: auth.account, session: auth.session)
        guard let team = teams.first else {
            throw SignError.message("这个 Apple ID 下没有可用团队")
        }
        append("   \(team.name)")

        // ④ 解压 ipa
        stage = "解压 ipa"
        append("④ 解压 ipa…")
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("YZLSign-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        try FileManager.default.unzipItem(at: ipaURL, to: workDir)

        let payload = workDir.appendingPathComponent("Payload", isDirectory: true)
        let entries = try FileManager.default.contentsOfDirectory(at: payload, includingPropertiesForKeys: nil)
        guard let appURL = entries.first(where: { $0.pathExtension == "app" }) else {
            throw SignError.message("ipa 结构异常：Payload 里没有 .app")
        }
        let bundleID = try readBundleID(appURL)
        append("   \(appURL.lastPathComponent)  (\(bundleID))")

        // ⑤ 注册设备
        stage = "注册设备"
        append("⑤ 注册本机 UDID…")
        let device = try await ensureDevice(portal: portal, udid: udid,
                                            team: team, session: auth.session)
        append("   \(device.identifier)")

        // ⑥ 证书
        stage = "准备证书"
        append("⑥ 准备开发证书…")
        let keyStore = try await ensureCertificate(portal: portal,
                                                   team: team, session: auth.session)
        append("   证书就绪  \(keyStore.certificate.serialNumber)")

        // ⑦ App ID
        stage = "准备 App ID"
        append("⑦ 准备 App ID…")
        let appID = try await ensureAppID(portal: portal, bundleID: bundleID,
                                          team: team, session: auth.session)
        append("   \(appID.bundleIdentifier)")

        // ⑧ 描述文件
        stage = "生成描述文件"
        append("⑧ 生成开发描述文件…")
        let profile = try await portal.createProvisioningProfile(
            name: "YZL Dev \(Self.stamp())",
            appID: appID,
            certificateIDs: [keyStore.certificate.serialNumber],
            deviceIDs: [device.identifier],
            team: team,
            session: auth.session
        )
        append("   有效期至 \(profile.expirationDate)")

        // ⑨ 签名
        stage = "签名中"
        append("⑨ 签名（主程序 + frameworks）…")
        let signer = AppBundleSigner(team: team, keyStore: keyStore)
        try await signer.signApp(at: appURL, provisioningProfiles: [profile])
        append("   签名完成")

        // ⑩ 校验：装得上（UDID 在列）+ 有权限（get-task-allow）
        stage = "校验"
        append("⑩ 校验描述文件…")
        let facts = try inspectProfile(in: appURL, udid: udid)
        append("   本机 UDID 在列表里：\(facts.hasDevice ? "是" : "否")")
        append("   get-task-allow：\(facts.entitlements["get-task-allow"] ?? "缺失")")
        append("   application-identifier：\(facts.entitlements["application-identifier"] ?? "缺失")")
        guard facts.hasDevice else {
            throw SignError.message("描述文件里没有本机 UDID，装上去会提示无法安装")
        }
        guard facts.getTaskAllow else {
            throw SignError.message("描述文件没带 get-task-allow，签出来 StikDebug 用不了 JIT")
        }

        // ⑪ 打包
        stage = "打包"
        append("⑪ 打包 ipa…")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stem = ipaURL.deletingPathExtension().lastPathComponent
        let outURL = docs.appendingPathComponent("\(stem)-signed.ipa")
        try? FileManager.default.removeItem(at: outURL)
        try FileManager.default.zipItem(at: payload, to: outURL, shouldKeepParent: true)
        try? FileManager.default.removeItem(at: workDir)

        let size = (try? FileManager.default.attributesOfItem(atPath: outURL.path)[.size] as? Int) ?? 0
        append("")
        append("✅ 完成")
        append("   \(outURL.lastPathComponent)  (\(String(format: "%.1f", Double(size) / 1048576.0)) MB)")
        outputPath = outURL.path

        // ⑫ 顺手把「自己的证书 + 描述文件」导出，
        // 这样用全能签这类工具也能签出带 get-task-allow 的包。
        stage = "导出证书"
        append("⑫ 导出证书…")
        let p12 = docs.appendingPathComponent("yzl-signing.p12")
        let prof = docs.appendingPathComponent("yzl-signing.mobileprovision")
        try? FileManager.default.removeItem(at: p12)
        try? FileManager.default.removeItem(at: prof)
        do {
            try keyStore.exportP12(password: Self.p12Password).write(to: p12)
            try profile.data.write(to: prof)
            p12Path = p12.path
            profilePath = prof.path
            append("   yzl-signing.p12（密码 \(Self.p12Password)）")
            append("   yzl-signing.mobileprovision")
        } catch {
            append("   证书导出失败：\(error.localizedDescription)")
        }
    }

    // MARK: - 幂等化，第二次跑不会撞墙

    private func ensureDevice(portal: DeveloperPortal, udid: String,
                              team: Team, session: Session) async throws -> Device {
        if let list = try? await portal.fetchDevices(for: team, session: session),
           let hit = list.first(where: {
               $0.identifier.caseInsensitiveCompare(udid) == .orderedSame
           }) {
            append("   设备已注册，直接复用")
            return hit
        }
        do {
            return try await portal.registerDevice(name: "iPhone", identifier: udid,
                                                   type: .iPhone, team: team, session: session)
        } catch {
            // 并发或缓存导致「已注册」时，再拉一次列表
            if let list = try? await portal.fetchDevices(for: team, session: session),
               let hit = list.first(where: {
                   $0.identifier.caseInsensitiveCompare(udid) == .orderedSame
               }) {
                append("   设备已注册，直接复用")
                return hit
            }
            throw error
        }
    }

    private func ensureCertificate(portal: DeveloperPortal,
                                   team: Team, session: Session) async throws -> KeyStore {
        // 免费账号 Apple Development 证书名额很少，先看有没有占满
        if let list = try? await portal.fetchCertificates(for: team, session: session),
           list.count >= 2 {
            append("   证书名额已用 \(list.count) 个，先撤销最旧的一个")
            if let oldest = list.first {
                _ = try? await portal.revokeCertificate(oldest, for: team, session: session)
            }
        }
        do {
            return try await portal.addCertificate(machineName: "YZL Signer",
                                                   type: .development,
                                                   to: team, session: session)
        } catch {
            // 还满就把全部旧证书清掉再来一次
            guard let list = try? await portal.fetchCertificates(for: team, session: session),
                  !list.isEmpty else { throw error }
            append("   名额仍占满，清理旧证书后重试…")
            for cert in list {
                _ = try? await portal.revokeCertificate(cert, for: team, session: session)
            }
            return try await portal.addCertificate(machineName: "YZL Signer",
                                                   type: .development,
                                                   to: team, session: session)
        }
    }

    private func ensureAppID(portal: DeveloperPortal, bundleID: String,
                             team: Team, session: Session) async throws -> AppID {
        if let list = try? await portal.fetchAppIDs(for: team, session: session),
           let hit = list.first(where: {
               $0.bundleIdentifier.caseInsensitiveCompare(bundleID) == .orderedSame
           }) {
            append("   App ID 已存在，直接复用")
            return hit
        }
        do {
            return try await portal.addAppID(withName: "YZL \(bundleID.suffix(28))",
                                             bundleIdentifier: bundleID,
                                             team: team, session: session)
        } catch {
            if let list = try? await portal.fetchAppIDs(for: team, session: session),
               let hit = list.first(where: {
                   $0.bundleIdentifier.caseInsensitiveCompare(bundleID) == .orderedSame
               }) {
                append("   App ID 已存在，直接复用")
                return hit
            }
            throw error
        }
    }

    private static func stamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "MMdd-HHmmss"
        f.timeZone = TimeZone.current
        return f.string(from: Date())
    }

    // MARK: - 读回真实签名结果

    struct ProfileFacts {
        var hasDevice: Bool
        var getTaskAllow: Bool
        var entitlements: [String: String]
    }

    private func readBundleID(_ appURL: URL) throws -> String {
        let infoURL = appURL.appendingPathComponent("Info.plist")
        let data = try Data(contentsOf: infoURL)
        guard let dict = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let bid = dict["CFBundleIdentifier"] as? String else {
            throw SignError.message("读不到 Info.plist 里的 CFBundleIdentifier")
        }
        return bid
    }

    /// 解析签名后 App 里真实的 embedded.mobileprovision，
    /// 直接确认「装得上」和「有 get-task-allow」两件事，而不是靠祈祷。
    private func inspectProfile(in appURL: URL, udid: String) throws -> ProfileFacts {
        let url = appURL.appendingPathComponent("embedded.mobileprovision")
        let raw = try Data(contentsOf: url)

        guard let start = raw.range(of: Data("<?xml".utf8)),
              let end = raw.range(of: Data("</plist>".utf8)) else {
            throw SignError.message("描述文件不是可解析的 plist")
        }
        let xml = raw.subdata(in: start.lowerBound..<end.upperBound)
        guard let dict = (try PropertyListSerialization.propertyList(from: xml, format: nil)) as? [String: Any] else {
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
}
