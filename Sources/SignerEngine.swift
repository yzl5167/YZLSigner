import Foundation
import Combine
import SideSign
import ZIPFoundation

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
    @Published var stage = ""

    let broker = CodeBroker()

    func append(_ line: String) {
        logs.append(line)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }

    func supply(code: String) {
        needsCode = false
        broker.supply(code)
    }

    func run(ipaURL: URL, udid: String, appleID: String, password: String) async {
        guard !busy else { return }
        busy = true
        outputPath = nil
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
            return text + "\n这通常是 Apple ID 还没激活过开发者身份。先在 StikDebug/SideStore 里用同一个账号登录一次，或去 developer.apple.com 同意协议。"
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

        // ④ 解压 ipa（先解压才能读 bundle id）
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
        let device = try await portal.registerDevice(
            name: "iPhone",
            identifier: udid,
            type: .iPhone,
            team: team,
            session: auth.session
        )
        append("   \(device.identifier)")

        // ⑥ 申请证书
        stage = "申请证书"
        append("⑥ 申请开发证书…")
        let keyStore = try await portal.addCertificate(
            machineName: "YZL Signer",
            type: .development,
            to: team,
            session: auth.session
        )
        append("   证书就绪")

        // ⑦ App ID
        stage = "注册 App ID"
        append("⑦ 注册 App ID…")
        let appID = try await portal.addAppID(
            withName: "YZL Launcher",
            bundleIdentifier: bundleID,
            team: team,
            session: auth.session
        )
        append("   已注册")

        // ⑧ 描述文件
        stage = "生成描述文件"
        append("⑧ 生成开发描述文件…")
        let profile = try await portal.createProvisioningProfile(
            name: "YZL Dev Profile",
            appID: appID,
            certificateIDs: [keyStore.certificate.serialNumberHex],
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

        // ⑩ 打包
        stage = "打包"
        append("⑩ 打包 ipa…")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stem = ipaURL.deletingPathExtension().lastPathComponent
        let outURL = docs.appendingPathComponent("\(stem)-signed.ipa")
        try? FileManager.default.removeItem(at: outURL)
        try FileManager.default.zipItem(at: payload, to: outURL, shouldKeepParent: true)

        // ⑪ 校验
        stage = "校验"
        append("⑪ 校验签名完整性…")
        try verify(outURL)

        try? FileManager.default.removeItem(at: workDir)

        let size = (try? FileManager.default.attributesOfItem(atPath: outURL.path)[.size] as? Int) ?? 0
        append("")
        append("✅ 完成，包已保存到「文件 → 我的 iPhone → YZL签名器」")
        append("   \(outURL.lastPathComponent)  (\(String(format: "%.1f", Double(size) / 1048576.0)) MB)")
        outputPath = outURL.path
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

    private func verify(_ ipaURL: URL) throws {
        guard let archive = Archive(url: ipaURL, accessMode: .read) else {
            throw SignError.message("无法打开产出的 ipa")
        }
        var hasSig = false
        var hasProfile = false
        for entry in archive {
            if entry.path.hasSuffix("_CodeSignature/CodeResources") { hasSig = true }
            if entry.path.hasSuffix("embedded.mobileprovision") { hasProfile = true }
        }
        append("   _CodeSignature：\(hasSig ? "有" : "缺")")
        append("   embedded.mobileprovision：\(hasProfile ? "有" : "缺")")
        guard hasSig, hasProfile else {
            throw SignError.message("签名不完整，装上去会失败")
        }
    }
}
