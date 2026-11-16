import Foundation
import Combine

enum SignerDefaults {
    /// 本地保存证书、以及导出给第三方签名工具（全能签 / Feather / ESign）用的 p12 密码。
    static let p12Password = "yzl123"
}

/// `Result` 的失败类型必须遵循 Error，又不想把 any Error 带过并发边界。
struct SignFailure: Error, Sendable {
    let message: String
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

    /// 用户点取消时把等待解开，返回空串让上层按「取消」处理。
    func abandon() {
        supply("")
    }
}

/// 只负责界面状态。真正的活全在 `SignWork` 里跑后台线程。
@MainActor
final class SignerEngine: ObservableObject {
    @Published var logs: [String] = []
    @Published var busy = false
    @Published var needsCode = false
    @Published var outputPath: String?
    @Published var p12Path: String?
    @Published var profilePath: String?
    @Published var stage = ""
    @Published var fraction: Double? = nil
    @Published var identitySummary: String = ""

    static let p12Password = SignerDefaults.p12Password

    let broker = CodeBroker()
    private var work: SignWork?

    func append(_ line: String) {
        logs.append(line)
        if logs.count > 1200 { logs.removeFirst(logs.count - 1200) }
    }

    func supply(code: String) {
        needsCode = false
        broker.supply(code)
    }

    func cancel() {
        work?.cancel()
        broker.abandon()
        append("⏹ 已请求取消，正在收尾…")
    }

    func refreshIdentitySummary() {
        guard let meta = IdentityStore.shared.savedMeta() else {
            identitySummary = "本机还没有缓存证书，第一次签名会申请一张"
            return
        }
        let days = Int(meta.expiryDate.timeIntervalSinceNow / 86400)
        identitySummary = days > 0
            ? "已缓存证书 \(String(meta.serialNumber.prefix(12)))…，还剩 \(days) 天"
            : "缓存证书已过期，下次会重新申请"
    }

    func forgetIdentity() {
        IdentityStore.shared.clear()
        refreshIdentitySummary()
        append("已清除本机缓存的证书")
    }

    func run(ipaURL: URL, udid: String, appleID: String, password: String) async {
        guard !busy else { return }
        busy = true
        outputPath = nil
        p12Path = nil
        profilePath = nil
        fraction = nil
        logs.removeAll()
        stage = "准备中"

        let brokerRef = broker
        broker.onNeedCode = { [weak self] in
            DispatchQueue.main.async {
                guard let self else { return }
                self.needsCode = true
                self.stage = "等待验证码"
                self.append("   ⚠️ 需要双重认证验证码，请查看受信任设备")
            }
        }

        // 全部 UI 更新都回到主线程
        let hooks = SignHooks(
            log: { [weak self] line in
                DispatchQueue.main.async { self?.append(line) }
            },
            stage: { [weak self] text in
                DispatchQueue.main.async { self?.stage = text }
            },
            fraction: { [weak self] value in
                DispatchQueue.main.async { self?.fraction = value }
            }
        )

        let worker = SignWork(hooks: hooks)
        work = worker

        // 关键：脱离主线程，否则 291MB 的签名会把界面冻死
        let task = Task.detached(priority: .userInitiated) { () -> Result<SignResult, SignFailure> in
            do {
                let result = try await worker.run(ipaURL: ipaURL, udid: udid,
                                                 appleID: appleID, password: password,
                                                 broker: brokerRef)
                return .success(result)
            } catch {
                return .failure(SignFailure(message: error.localizedDescription))
            }
        }

        let outcome = await task.value
        work = nil
        busy = false
        needsCode = false
        stage = ""
        fraction = nil

        switch outcome {
        case .success(let result):
            outputPath = result.signedIPA.path
            p12Path = result.p12?.path
            profilePath = result.profile?.path
            refreshIdentitySummary()
        case .failure(let failure):
            append("")
            append("❌ 失败：\(friendly(failure.message))")
        }
    }

    private func friendly(_ text: String) -> String {
        if text.contains("No profiles") || text.contains("no team") {
            return text + "\n这个 Apple ID 还没开通开发者身份。先去 developer.apple.com 用同一账号登录并同意协议，再回来重试。"
        }
        if text.contains("maximum") || text.contains("Maximum") || text.contains("tooManyCertificates") {
            return text + "\n账号名额满了。删掉一个旧 App ID 或旧证书再试。"
        }
        if text.contains("incorrect") || text.contains("Incorrect") || text.contains("invalid credentials") {
            return text + "\n账号或密码不对。注意：如果你开了双重认证，这里要填的是 Apple ID 密码本身，验证码下一步会问。"
        }
        if text.contains("已取消") {
            return "已取消"
        }
        return text
    }
}
