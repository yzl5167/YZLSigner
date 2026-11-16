import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var engine = SignerEngine()

    @AppStorage("appleID") private var appleID = ""
    @State private var udid = ""
    @State private var udidStatus = ""
    @State private var password = ""
    @State private var ipaName = ""
    @State private var ipaURL: URL?
    @State private var code = ""

    @State private var showIPAImporter = false
    @State private var showPairingImporter = false
    @State private var showShare = false
    @State private var shareURL: URL?

    private var canStart: Bool {
        DeviceUDID.normalize(udid) != nil &&
        !appleID.trimmingCharacters(in: .whitespaces).isEmpty &&
        !password.isEmpty &&
        ipaURL != nil
    }

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("本机 UDID"),
                        footer: Text(udidStatus.isEmpty
                                     ? "签名必须绑定这台设备的 UDID，签出来的包才能装。"
                                     : udidStatus)) {
                    TextField("UDID（如 00008110-001A2C3E0AF8801E）", text: $udid)
                        .textInputAutocapitalization(.characters)
                        .disableAutocorrection(true)
                        .font(.system(.body, design: .monospaced))

                    Button {
                        autoDetect()
                    } label: {
                        Label("自动重新读取", systemImage: "arrow.clockwise")
                    }

                    Link(destination: UDIDProfile.profileURL) {
                        HStack {
                            Text("读不到？用系统描述文件获取")
                            Spacer()
                            Image(systemName: "safari")
                        }
                    }

                    Button("从配对文件导入") { showPairingImporter = true }
                }

                Section(header: Text("Apple ID"),
                        footer: Text("只用于向 Apple 后端申请开发证书和描述文件，不会上传到任何第三方服务器。验证码会发到你的受信任设备。")) {
                    TextField("邮箱", text: $appleID)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                    SecureField("密码", text: $password)
                }

                Section(header: Text("要签名的包")) {
                    Button {
                        showIPAImporter = true
                    } label: {
                        HStack {
                            Text(ipaName.isEmpty ? "选择 ipa 文件" : ipaName)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Image(systemName: "doc.badge.plus")
                        }
                    }
                }

                if engine.needsCode {
                    Section(header: Text("双重认证")) {
                        TextField("手机上收到的 6 位验证码", text: $code)
                            .keyboardType(.numberPad)
                        Button("提交验证码") {
                            let c = code
                            code = ""
                            engine.supply(code: c)
                        }
                        .disabled(code.count < 4)
                    }
                }

                Section {
                    Button {
                        start()
                    } label: {
                        HStack {
                            Spacer()
                            if engine.busy {
                                ProgressView().padding(.trailing, 8)
                            }
                            Text(engine.busy
                                 ? (engine.stage.isEmpty ? "处理中…" : engine.stage)
                                 : "开始签名")
                                .bold()
                            Spacer()
                        }
                    }
                    .disabled(engine.busy || !canStart)
                }

                if !engine.logs.isEmpty {
                    Section(header: Text("日志")) {
                        ScrollView {
                            Text(engine.logs.joined(separator: "\n"))
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                        .frame(height: 240)
                    }
                }

                if let path = engine.outputPath {
                    Section(header: Text("已签名")) {
                        Text((path as NSString).lastPathComponent)
                            .font(.system(.callout, design: .monospaced))
                        Button {
                            shareURL = URL(fileURLWithPath: path)
                            showShare = true
                        } label: {
                            Label("导出 / 分享这个 ipa", systemImage: "square.and.arrow.up")
                        }
                        Text("路径：文件 App → 我的 iPhone → YZL签名器")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if let p12 = engine.p12Path, let prof = engine.profilePath {
                    Section(header: Text("你自己的证书"),
                            footer: Text("p12 密码：\(SignerDefaults.p12Password)。把这套证书导进全能签，再用全能签签启动器，签出来的包就带 get-task-allow。")) {
                        Button {
                            shareURL = URL(fileURLWithPath: p12)
                            showShare = true
                        } label: {
                            Label("导出 yzl-signing.p12", systemImage: "key.fill")
                        }
                        Button {
                            shareURL = URL(fileURLWithPath: prof)
                            showShare = true
                        } label: {
                            Label("导出 yzl-signing.mobileprovision", systemImage: "doc.text.fill")
                        }
                    }
                }

                Section(header: Text("怎么用")) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("1. 本机 UDID 会自动读出来，读不到就点上面的描述文件。")
                        Text("2. 填 Apple ID 和密码，点开始签名。")
                        Text("3. 弹出验证码时输一次，等它跑完。")
                        Text("4. 用分享按钮把签好的 ipa 导出，直接安装即可。")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
            }
            .navigationTitle("YZL 签名器")
            .onAppear {
                if DeviceUDID.normalize(udid) == nil { autoDetect() }
            }
            .onOpenURL { url in
                if let value = DeviceUDID.fromCallbackURL(url) {
                    udid = value
                    udidStatus = "已通过系统描述文件读取本机 UDID"
                    engine.append("✅ 自动读取 UDID：\(value)")
                }
            }
            .fileImporter(
                isPresented: $showIPAImporter,
                allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first { importIPA(url) }
                case .failure(let err):
                    engine.append("选择文件失败：\(err.localizedDescription)")
                }
            }
            .fileImporter(
                isPresented: $showPairingImporter,
                allowedContentTypes: [.data, .xml, .propertyList],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    do {
                        let value = try DeviceUDID.fromPairingFile(at: url)
                        udid = value
                        udidStatus = "已从配对文件读取"
                        engine.append("已读取 UDID：\(value)")
                    } catch {
                        engine.append("读取配对文件失败：\(error.localizedDescription)")
                    }
                case .failure(let err):
                    engine.append("选择文件失败：\(err.localizedDescription)")
                }
            }
            .sheet(isPresented: $showShare) {
                if let url = shareURL {
                    ActivityView(items: [url])
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    // MARK: - UDID

    private func autoDetect() {
        if let cached = DeviceUDID.normalize(udid), !cached.isEmpty {
            udidStatus = "已读取：\(cached)"
            return
        }
        // ⓿ 自己就是被单一设备描述文件签的 —— 直接认
        if let own = DeviceUDID.fromOwnProfile() {
            udid = own
            udidStatus = "✅ 已自动读取本机 UDID"
            engine.append("✅ 自动读取 UDID：\(own)")
            return
        }
        // ① 直接问本机 lockdownd
        udidStatus = "正在读取…"
        DispatchQueue.global(qos: .userInitiated).async {
            let value = DeviceUDID.fromLockdown()
            DispatchQueue.main.async {
                if let v = value {
                    udid = v
                    udidStatus = "✅ 已自动读取本机 UDID"
                    engine.append("✅ 自动读取 UDID：\(v)")
                } else {
                    udidStatus = "系统没让直接读。点下面的「用系统描述文件获取」，两步就能拿到。"
                }
            }
        }
    }

    // MARK: - 动作

    private func start() {
        guard let ipa = ipaURL, let u = DeviceUDID.normalize(udid) else { return }
        let a = appleID.trimmingCharacters(in: .whitespacesAndNewlines)
        let p = password
        Task { await engine.run(ipaURL: ipa, udid: u, appleID: a, password: p) }
    }

    private func importIPA(_ url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }

        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("input-\(UUID().uuidString).ipa")
        do {
            if FileManager.default.fileExists(atPath: dest.path) {
                try FileManager.default.removeItem(at: dest)
            }
            try FileManager.default.copyItem(at: url, to: dest)
            ipaURL = dest
            ipaName = url.lastPathComponent
            let size = (try? FileManager.default.attributesOfItem(atPath: dest.path)[.size] as? Int) ?? 0
            engine.append("已选择：\(url.lastPathComponent)（\(String(format: "%.1f", Double(size) / 1048576.0)) MB）")
        } catch {
            engine.append("复制文件失败：\(error.localizedDescription)")
        }
    }
}

/// iOS 15 没有 ShareLink，用 UIKit 的分享面板。
struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
