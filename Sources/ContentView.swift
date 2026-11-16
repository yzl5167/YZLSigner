import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var engine = SignerEngine()

    @State private var udid = ""
    @State private var appleID = ""
    @State private var password = ""
    @State private var ipaName = ""
    @State private var ipaURL: URL?
    @State private var code = ""

    @State private var showIPAImporter = false
    @State private var showPairingImporter = false

    private var canStart: Bool {
        !udid.trimmingCharacters(in: .whitespaces).isEmpty &&
        !appleID.trimmingCharacters(in: .whitespaces).isEmpty &&
        !password.isEmpty &&
        ipaURL != nil
    }

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("目标设备")) {
                    TextField("UDID（如 00008110-001A2C3E0AF8801E）", text: $udid)
                        .textInputAutocapitalization(.characters)
                        .disableAutocorrection(true)
                        .font(.system(.body, design: .monospaced))

                    Button("从配对文件导入 UDID") { showPairingImporter = true }

                    Link(destination: URL(string: "https://www.pgyer.com/tools/udid")!) {
                        HStack {
                            Text("用 Safari 获取本机 UDID")
                            Spacer()
                            Image(systemName: "safari")
                        }
                    }
                }

                Section(header: Text("Apple ID")) {
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
                    Section(header: Text("产出位置")) {
                        Text(path)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                        Text("在「文件」App → 我的 iPhone → YZL签名器 里可以找到，用它去全能签安装。")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .navigationTitle("YZL 签名器")
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
                allowedContentTypes: [.data],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    do {
                        let value = try UDIDReader.read(from: url)
                        udid = value
                        engine.append("已读取 UDID：\(value)")
                    } catch {
                        engine.append("读取配对文件失败：\(error.localizedDescription)")
                    }
                case .failure(let err):
                    engine.append("选择文件失败：\(err.localizedDescription)")
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    private func start() {
        guard let ipa = ipaURL else { return }
        let u = udid.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
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
