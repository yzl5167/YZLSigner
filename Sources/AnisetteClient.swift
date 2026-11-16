import Foundation
import SideSign

enum SignError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let m): return m
        }
    }
}

/// 从远程 anisette 服务获取设备身份数据。
/// 用远程服务而不是本地 AOSKit，避免私有框架在非越狱设备上不可用。
enum AnisetteClient {
    static let servers = [
        "https://ani.sidestore.io",
        "https://anisette.sidestore.io",
    ]

    static func fetch() async throws -> AnisetteData {
        var lastError = "所有 anisette 服务都不可用"

        for server in servers {
            guard let url = URL(string: server) else { continue }
            do {
                var req = URLRequest(url: url)
                req.timeoutInterval = 25
                req.cachePolicy = .reloadIgnoringLocalCacheData
                req.setValue("application/json", forHTTPHeaderField: "Accept")

                let (data, resp) = try await URLSession.shared.data(for: req)
                guard let http = resp as? HTTPURLResponse,
                      (200...299).contains(http.statusCode) else {
                    lastError = "\(server) 返回 HTTP \((resp as? HTTPURLResponse)?.statusCode ?? -1)"
                    continue
                }

                let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
                func str(_ key: String, _ fallback: String = "") -> String {
                    dict[key] as? String ?? fallback
                }

                let otp = str("X-Apple-I-MD")
                guard !otp.isEmpty else {
                    lastError = "\(server) 返回的数据缺少 X-Apple-I-MD"
                    continue
                }

                let now = ISO8601DateFormatter().string(from: Date())
                return AnisetteData(
                    machineID: str("X-Apple-I-MD-M"),
                    oneTimePassword: otp,
                    localUserID: str("X-Apple-I-MD-LU"),
                    routingInfo: str("X-Apple-I-MD-RINFO", "17106176"),
                    deviceID: UUID().uuidString.uppercased(),
                    serialNumber: str("X-Apple-I-SRL-NO", "0"),
                    clientInfo: "{\"bootstrap\":true,\"icscrec\":true,\"pbe\":false,\"prkgen\":true,\"svct\":\"iCloud\",\"loc\":\"en_US\"}",
                    userAgent: "Xcode",
                    clientTime: str("X-Apple-I-Client-Time", now),
                    locale: "en_US",
                    timeZone: "GMT+8:00"
                )
            } catch {
                lastError = "\(server)：\(error.localizedDescription)"
            }
        }
        throw SignError.message(lastError)
    }
}
