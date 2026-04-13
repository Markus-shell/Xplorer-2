/*
 * Xplorer 2: The Privacy-Hardened Browser for iOS
 * Developed entirely on iPad with Swift Playgrounds
 * 
 * License: GNU General Public License v3.0
 * Copyright (c) 2026 [Sleath]
 *
 * "A gift to the Open-Source community."
 */
import Security
import UIKit
import WebKit
import PlaygroundSupport
import Network
import SecureElementCredential
import AppTrackingTransparency
import Dispatch
import UserNotifications
import CoreLocation
import ARKit
import AuthenticationServices
import Metal
import CryptoKit
import AVFoundation
class LeakFreeProxy: NSObject, WKScriptMessageHandler {
    weak var delegate: WKScriptMessageHandler?
    
    init(delegate: WKScriptMessageHandler) {
        self.delegate = delegate
        super.init()
    }
    
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        delegate?.userContentController(userContentController, didReceive: message)
    }
}
class PhishingManager {
    static let shared = PhishingManager()
    
    private let concurrentQueue = DispatchQueue(label: "com.xplorer.phishingList", attributes: .concurrent)
    private var _blacklistedDomains: Set<String> = []
    
    var blacklistedDomains: Set<String> {
        get {
            concurrentQueue.sync { _blacklistedDomains }
        }
        set {
            concurrentQueue.async(flags: .barrier) {
                self._blacklistedDomains = newValue
            }
        }
    }
    
    init() {
        loadStarterPack()
    }
    
    func loadStarterPack() {
        let commonTrackers = [
            "internet-banking-fake.com", "flurry.com", "doubleclick.net",
            "adservice.google.com", "googleadservices.com", "connect.facebook.net",
            "criteo.com", "taboola.com", "outbrain.com", "adnxs.com",
            "adsrvr.org", "amazon-adsystem.com", "moatads.com", "appsflyer.com"
        ]
        self.blacklistedDomains = Set(commonTrackers)
        print("🛡️ PROTECTION INITIALE : \(commonTrackers.count) sites.")
    }
    
    func downloadRealList() {
        let urlString = "https://cdn.jsdelivr.net/gh/StevenBlack/hosts@master/hosts"
        guard let url = URL(string: urlString) else { return }
        
        print("🚀 Démarrage téléchargement liste anti-phishing...")
        
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let data = try? Data(contentsOf: url),
                  let content = String(data: data, encoding: .utf8) else {
                print("❌ Échec téléchargement liste.")
                return
            }
            
            var newSet = Set<String>()
            let lines = content.components(separatedBy: .newlines)
            
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.starts(with: "0.0.0.0") {
                    let parts = trimmed.components(separatedBy: .whitespaces)
                    if parts.count >= 2 {
                        let domain = parts[1]
                        if domain != "0.0.0.0" {
                            newSet.insert(domain)
                        }
                    }
                }
            }
            self?.blacklistedDomains = newSet
            
            DispatchQueue.main.async {
                print("✅ LISTE MISE À JOUR : \(newSet.count) domaines bloqués")
            }
        }
    }
    
    // 3. VÉRIFICATION INSTANTANÉE (Complexité O(1))
    func isDangerous(url: URL) -> Bool {
        guard let host = url.host?.lowercased() else { return false }
        
        // On récupère une copie locale du set pour la lecture (Thread-safe)
        let domains = blacklistedDomains
        
        // A. Vérification exacte (ex: "malware.com") -> O(1) ultra rapide
        if domains.contains(host) { return true }
        
        // B. Vérification du domaine parent (ex: "sub.malware.com")
        // Au lieu de parcourir toute la liste (lent), on coupe le host
        let components = host.components(separatedBy: ".")
        if components.count > 2 {
            // On prend les 2 derniers morceaux (ex: "malware.com")
            let rootDomain = components.suffix(2).joined(separator: ".")
            if domains.contains(rootDomain) { return true }
        }
        
        return false
    }
}
// MARK: - Gestionnaire DNS Cloudflare (DoH)
class CloudflareDNS {
    static let shared = CloudflareDNS()
    
    // Structure pour décoder la réponse JSON de Cloudflare
    struct DoHResponse: Codable {
        struct Answer: Codable {
            let data: String
            let type: Int
        }
        let Answer: [Answer]?
    }
    
    // Interroge 1.1.1.1 via HTTPS
    func resolve(domain: String, completion: @escaping (String?) -> Void) {
        // On nettoie l'URL pour n'avoir que le domaine (ex: google.com)
        let cleanDomain = domain.replacingOccurrences(of: "https://", with: "")
                                .replacingOccurrences(of: "http://", with: "")
                                .split(separator: "/").first ?? ""
        
        guard let url = URL(string: "https://cloudflare-dns.com/dns-query?name=\(cleanDomain)&type=A") else {
            completion(nil)
            return
        }
        
        var request = URLRequest(url: url)
        request.addValue("application/dns-json", forHTTPHeaderField: "accept")
        
        URLSession.shared.dataTask(with: request) { data, _, error in
            guard let data = data, error == nil else {
                completion(nil)
                return
            }
            
            do {
                let response = try JSONDecoder().decode(DoHResponse.self, from: data)
                // Type 1 = Enregistrement A (IPv4)
                if let ip = response.Answer?.first(where: { $0.type == 1 })?.data {
                    completion(ip)
                } else {
                    completion(nil)
                }
            } catch {
                completion(nil)
            }
        }.resume()
    }
}
class DevToolsView: UIView, UITextFieldDelegate {
    
    // UI Elements
    let logView = UITextView()
    let inputField = UITextField()
    let runButton = UIButton(type: .system)
    let closeButton = UIButton(type: .system)
    let titleLabel = UILabel()
    
    // Callback quand on lance une commande
    var onCommand: ((String) -> Void)?
    var onClose: (() -> Void)?
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupUI()
    }
    
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    
    func setupUI() {
        self.backgroundColor = UIColor(red: 0.15, green: 0.15, blue: 0.15, alpha: 0.95) // Gris foncé Chrome
        self.layer.borderWidth = 1
        self.layer.borderColor = UIColor.gray.cgColor
        
        // Titre
        titleLabel.text = "DevTools - Console & Réseau"
        titleLabel.textColor = .lightGray
        titleLabel.font = UIFont.boldSystemFont(ofSize: 12)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        addSubview(titleLabel)
        
        // Bouton Fermer
        closeButton.setTitle("✕", for: .normal)
        closeButton.tintColor = .white
        closeButton.addTarget(self, action: #selector(closeTapped), for: .touchUpInside)
        closeButton.translatesAutoresizingMaskIntoConstraints = false
        addSubview(closeButton)
        
        // Zone de logs (Lecture seule)
        logView.backgroundColor = .black
        logView.textColor = .green
        logView.font = UIFont(name: "Menlo", size: 11)
        logView.isEditable = false
        logView.layoutManager.allowsNonContiguousLayout = false
        logView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(logView)
        
        // Champ de saisie
        inputField.backgroundColor = UIColor(white: 0.2, alpha: 1)
        inputField.textColor = .white
        inputField.font = UIFont(name: "Menlo", size: 12)
        inputField.placeholder = "> Tapez du JavaScript ici..."
        inputField.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 5, height: 1))
        inputField.leftViewMode = .always
        inputField.autocapitalizationType = .none
        inputField.autocorrectionType = .no
        inputField.delegate = self
        inputField.translatesAutoresizingMaskIntoConstraints = false
        addSubview(inputField)
        
        // Bouton Run
        runButton.setTitle("Exécuter", for: .normal)
        runButton.backgroundColor = .systemBlue
        runButton.setTitleColor(.white, for: .normal)
        runButton.layer.cornerRadius = 4
        runButton.addTarget(self, action: #selector(runTapped), for: .touchUpInside)
        runButton.translatesAutoresizingMaskIntoConstraints = false
        addSubview(runButton)
        
        // Contraintes
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: topAnchor, constant: 5),
            titleLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 10),
            
            closeButton.centerYAnchor.constraint(equalTo: titleLabel.centerYAnchor),
            closeButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -10),
            
            logView.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 5),
            logView.leadingAnchor.constraint(equalTo: leadingAnchor),
            logView.trailingAnchor.constraint(equalTo: trailingAnchor),
            logView.bottomAnchor.constraint(equalTo: inputField.topAnchor, constant: -5),
            
            inputField.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 5),
            inputField.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -5),
            inputField.heightAnchor.constraint(equalToConstant: 30),
            inputField.trailingAnchor.constraint(equalTo: runButton.leadingAnchor, constant: -5),
            
            runButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -5),
            runButton.centerYAnchor.constraint(equalTo: inputField.centerYAnchor),
            runButton.widthAnchor.constraint(equalToConstant: 70),
            runButton.heightAnchor.constraint(equalToConstant: 30)
        ])
    }
    
    // Ajouter une ligne dans la console
    func log(_ text: String, type: String = "info") {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        var prefix = ""
        var color: UIColor = .white
        
        switch type {
        case "network": prefix = "🔵 NET:"; color = .cyan
        case "error": prefix = "🔴 ERR:"; color = .red
        case "warn": prefix = "⚠️ WARN:"; color = .yellow
        case "js": prefix = "📜 JS:"; color = .lightGray
        case "result": prefix = "✅ <"; color = .green
        default: prefix = "ℹ️"; color = .white
        }
        
        let formattedText = "[\(timestamp)] \(prefix) \(text)\n"
        let attrString = NSAttributedString(string: formattedText, attributes: [.foregroundColor: color, .font: UIFont(name: "Menlo", size: 11)!])
        
        DispatchQueue.main.async {
            let mutable = NSMutableAttributedString(attributedString: self.logView.attributedText)
            mutable.append(attrString)
            self.logView.attributedText = mutable
            
            // Auto scroll en bas
            if self.logView.text.count > 0 {
                let bottom = NSRange(location: self.logView.text.count - 1, length: 1)
                self.logView.scrollRangeToVisible(bottom)
            }
        }
    }
    
    @objc func runTapped() {
        guard let text = inputField.text, !text.isEmpty else { return }
        log(text, type: "js")
        onCommand?(text)
        inputField.text = ""
    }
    
    @objc func closeTapped() {
        onClose?()
    }
    
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        runTapped()
        return true
    }
}
class BrowserViewController: UIViewController, WKScriptMessageHandler {
    // Caches en mémoire pour les scripts du Mode Lecture
        var domPurifyScriptCache: String?
        var readabilityScriptCache: String?
  static let sharedProcessPool = WKProcessPool()
    func loadContentFilterWarning(for url: URL) {
            let safeUrlString = url.absoluteString.replacingOccurrences(of: "'", with: "\\'")
            let hostname = url.host ?? "Ce site web"
            
            // Thème Violet/Indigio pour différencier du Phishing (Rouge)
            let warningHTML = """
            <!DOCTYPE html>
            <html lang="fr">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Accès Restreint - Xplorer</title>
                <style>
                    :root {
                        --bg-color: #ffffff;
                        --text-color: #202124;
                        --card-bg: #f8f9fa;
                        --filter-color: #512da8; /* Violet sombre pour les filtres */
                        --button-bg: #1a73e8;
                        --button-text: #ffffff;
                        --secondary-text: #5f6368;
                        --border-color: #dadce0;
                    }
                    
                    @media (prefers-color-scheme: dark) {
                        :root {
                            --bg-color: #202124;
                            --text-color: #e8eaed;
                            --card-bg: #303134;
                            --filter-color: #7e57c2; /* Violet clair pour le mode sombre */
                            --button-bg: #8ab4f8;
                            --button-text: #202124;
                            --secondary-text: #9aa0a6;
                            --border-color: #5f6368;
                        }
                    }

                    body {
                        margin: 0;
                        padding: 20px;
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background-color: var(--filter-color);
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        transition: background-color 0.3s;
                    }
                    
                    @media (prefers-color-scheme: dark) {
                        body { background-color: #1a0f35; }
                    }

                    .container {
                        background-color: var(--bg-color);
                        border-radius: 12px;
                        padding: 40px;
                        max-width: 500px;
                        width: 90%;
                        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                        text-align: center;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .header-icon { font-size: 60px; margin-bottom: 20px; animation: float 3s ease-in-out infinite; }
                    @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0px); } }

                    h1 { margin: 0 0 15px 0; font-size: 24px; color: var(--filter-color); font-weight: 700; }

                    p { margin: 0 0 25px 0; line-height: 1.6; color: var(--text-color); font-size: 16px; }

                    .domain-badge {
                        background-color: var(--card-bg);
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-family: 'Menlo', monospace;
                        font-weight: bold;
                        border: 1px solid var(--border-color);
                    }

                    .actions { display: flex; flex-direction: column; gap: 15px; }

                    .btn-safe {
                        background-color: var(--button-bg); color: var(--button-text); border: none;
                        padding: 12px 24px; border-radius: 24px; font-size: 16px; font-weight: 600;
                        cursor: pointer; transition: opacity 0.2s; text-decoration: none; display: inline-block;
                    }
                    .btn-safe:hover { opacity: 0.9; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }

                    details { margin-top: 30px; text-align: left; border-top: 1px solid var(--border-color); padding-top: 15px; }
                    summary { cursor: pointer; color: var(--secondary-text); font-size: 14px; user-select: none; }
                    .advanced-info { margin-top: 10px; font-size: 13px; color: var(--secondary-text); }
                    .unsafe-link { color: var(--secondary-text); text-decoration: underline; font-size: 12px; margin-top: 10px; display: block; text-align: right; cursor: pointer; }
                    .unsafe-link:hover { color: var(--filter-color); }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header-icon">✋</div>
                    <h1>Accès restreint par l'administrateur</h1>
                    <p>
                        Le chargement de <span class="domain-badge">\(hostname)</span> n'est pas autorisé.<br><br>
                        Cette page a été bloquée par la politique de sécurité de votre administrateur (ex: Jamf Trust, profil MDM) ou par les restrictions de contenu de votre appareil Apple.
                    </p>
                    
                    <div class="actions">
                        <button class="btn-safe" onclick="goBack()">Retourner en arrière</button>
                    </div>

                    <details>
                        <summary>Détails techniques</summary>
                        <div class="advanced-info">
                            <strong>URL bloquée :</strong> \(safeUrlString)<br>
                            <strong>Code d'erreur :</strong> MDM_CONTENT_FILTER_RESTRICTION (105)<br><br>
                            Cette erreur se produit lorsqu'un profil de gestion d'appareil (MDM) ou un filtre réseau d'entreprise interdit l'accès à cette catégorie de sites web.<br>
                            <a class="unsafe-link" onclick="bypass()">Forcer le contournement du filtre pour cet onglet</a>
                        </div>
                    </details>
                </div>

                <script>
                    function goBack() {
                        if (window.history.length > 1) { window.history.back(); }
                        else { window.webkit.messageHandlers.homeHandler.postMessage('goHome'); }
                    }
                    function bypass() {
                        window.webkit.messageHandlers.retryHandler.postMessage('bypass-filter:\(safeUrlString)');
                    }
                </script>
            </body>
            </html>
            """
            
            tabs[currentTabIndex].loadHTMLString(warningHTML, baseURL: nil)
        }
    func loadSSLWarning(for url: URL, errorCode: Int) {
        let safeUrlString = url.absoluteString.replacingOccurrences(of: "'", with: "\\'")
        let bypassURLString = url.absoluteString.replacingOccurrences(of: "https://", with: "bypass-ssl://").replacingOccurrences(of: "'", with: "\\'")
        let hostname = url.host ?? "Ce site web"
        
        // Traduction du code d'erreur technique en texte clair
        var errorName = "NET::ERR_CERT_INVALID"
        if errorCode == NSURLErrorServerCertificateUntrusted { errorName = "NET::ERR_CERT_AUTHORITY_INVALID" }
        else if errorCode == NSURLErrorServerCertificateHasBadDate { errorName = "NET::ERR_CERT_DATE_INVALID" }

        let warningHTML = """
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Erreur de confidentialité - Xplorer</title>
            <style>
                :root {
                    --bg-color: #ffffff;
                    --text-color: #202124;
                    --card-bg: #f8f9fa;
                    --danger-color: #b31412; /* Rouge sombre pour les erreurs SSL */
                    --button-bg: #1a73e8;
                    --button-text: #ffffff;
                    --secondary-text: #5f6368;
                    --border-color: #dadce0;
                }
                
                @media (prefers-color-scheme: dark) {
                    :root {
                        --bg-color: #202124;
                        --text-color: #e8eaed;
                        --card-bg: #303134;
                        --danger-color: #e25b59; /* Rouge clair pour le mode sombre */
                        --button-bg: #8ab4f8;
                        --button-text: #202124;
                        --secondary-text: #9aa0a6;
                        --border-color: #5f6368;
                    }
                }

                body {
                    margin: 0;
                    padding: 20px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    background-color: var(--danger-color);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    transition: background-color 0.3s;
                }
                
                @media (prefers-color-scheme: dark) {
                    body { background-color: #3b0d0c; }
                }

                .container {
                    background-color: var(--bg-color);
                    border-radius: 12px;
                    padding: 40px;
                    max-width: 500px;
                    width: 90%;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                    text-align: center;
                    position: relative;
                    overflow: hidden;
                }
                
                .header-icon { font-size: 60px; margin-bottom: 20px; animation: pulse 2s infinite; }
                @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.1); } 100% { transform: scale(1); } }

                h1 { margin: 0 0 15px 0; font-size: 24px; color: var(--danger-color); font-weight: 700; }

                p { margin: 0 0 25px 0; line-height: 1.6; color: var(--text-color); font-size: 16px; }

                .domain-badge {
                    background-color: var(--card-bg);
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-family: 'Menlo', monospace;
                    font-weight: bold;
                    border: 1px solid var(--border-color);
                }

                .actions { display: flex; flex-direction: column; gap: 15px; }

                .btn-safe {
                    background-color: var(--button-bg); color: var(--button-text); border: none;
                    padding: 12px 24px; border-radius: 24px; font-size: 16px; font-weight: 600;
                    cursor: pointer; transition: opacity 0.2s; text-decoration: none; display: inline-block;
                }
                .btn-safe:hover { opacity: 0.9; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }

                details { margin-top: 30px; text-align: left; border-top: 1px solid var(--border-color); padding-top: 15px; }
                summary { cursor: pointer; color: var(--secondary-text); font-size: 14px; user-select: none; }
                .advanced-info { margin-top: 10px; font-size: 13px; color: var(--secondary-text); }
                .unsafe-link { color: var(--secondary-text); text-decoration: underline; font-size: 12px; margin-top: 10px; display: block; text-align: right; cursor: pointer; }
                .unsafe-link:hover { color: var(--danger-color); }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header-icon">🛑</div>
                <h1>Votre connexion n'est pas privée</h1>
                <p>
                    Des individus malveillants tentent peut-être de subtiliser vos informations sur <span class="domain-badge">\(hostname)</span>.<br><br>
                    Le certificat de sécurité de ce site est invalide ou auto-signé.
                </p>
                
                <div class="actions">
                    <button class="btn-safe" onclick="goBack()">Retourner en sécurité</button>
                </div>

                <details>
                    <summary>Détails avancés</summary>
                    <div class="advanced-info">
                        <strong>URL bloquée :</strong> \(safeUrlString)<br>
                        <strong>Code d'erreur :</strong> \(errorName)<br><br>
                        Ce serveur n'a pas pu prouver qu'il est bien \(hostname). Son certificat de sécurité n'est pas approuvé par le système d'exploitation de votre appareil.<br>
                        <a class="unsafe-link" onclick="bypass()">Ignorer l'avertissement et accéder au site (Dangereux)</a>
                    </div>
                </details>
            </div>

            <script>
                function goBack() {
                    if (window.history.length > 1) { window.history.back(); }
                    else { window.webkit.messageHandlers.homeHandler.postMessage('goHome'); }
                }
                function bypass() {
                    // Envoi du message chiffré à Swift !
                    window.webkit.messageHandlers.retryHandler.postMessage('bypass-ssl:\(safeUrlString)');
                }
            </script>
        </body>
        </html>
        """
        
        tabs[currentTabIndex].loadHTMLString(warningHTML, baseURL: nil)
    }
    func loadHTTPWarning(for url: URL) {
            // 1. Préparation des variables (comme pour le phishing)
            let safeUrlString = url.absoluteString.replacingOccurrences(of: "'", with: "\\'")
            let bypassURLString = url.absoluteString.replacingOccurrences(of: "http://", with: "bypass-http://").replacingOccurrences(of: "'", with: "\\'")
            let hostname = url.host ?? "Ce site web"
            
            // 2. LE CODE HTML (Un copier-coller du Phishing, mais en Orange "Warning")
            let warningHTML = """
            <!DOCTYPE html>
            <html lang="fr">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Site non sécurisé - Xplorer</title>
                <style>
                    :root {
                        --bg-color: #ffffff;
                        --text-color: #202124;
                        --card-bg: #f8f9fa;
                        --warning-color: #e37400; /* Orange vif au lieu du rouge danger */
                        --button-bg: #1a73e8;
                        --button-text: #ffffff;
                        --secondary-text: #5f6368;
                        --border-color: #dadce0;
                    }
                    
                    @media (prefers-color-scheme: dark) {
                        :root {
                            --bg-color: #202124;
                            --text-color: #e8eaed;
                            --card-bg: #303134;
                            --warning-color: #f29900; /* Orange adapté au mode sombre */
                            --button-bg: #8ab4f8;
                            --button-text: #202124;
                            --secondary-text: #9aa0a6;
                            --border-color: #5f6368;
                        }
                    }

                    body {
                        margin: 0;
                        padding: 20px;
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background-color: var(--warning-color);
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        transition: background-color 0.3s;
                    }
                    
                    @media (prefers-color-scheme: dark) {
                        body { background-color: #331a00; } /* Marron/Orange très foncé pour le fond */
                    }

                    .container {
                        background-color: var(--bg-color);
                        border-radius: 12px;
                        padding: 40px;
                        max-width: 500px;
                        width: 90%;
                        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                        text-align: center;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .header-icon { font-size: 60px; margin-bottom: 20px; animation: pulse 2s infinite; }
                    @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.1); } 100% { transform: scale(1); } }

                    h1 { margin: 0 0 15px 0; font-size: 24px; color: var(--warning-color); font-weight: 700; }

                    p { margin: 0 0 25px 0; line-height: 1.6; color: var(--text-color); font-size: 16px; }

                    .domain-badge {
                        background-color: var(--card-bg);
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-family: 'Menlo', monospace;
                        font-weight: bold;
                        border: 1px solid var(--border-color);
                    }

                    .actions { display: flex; flex-direction: column; gap: 15px; }

                    .btn-safe {
                        background-color: var(--button-bg); color: var(--button-text); border: none;
                        padding: 12px 24px; border-radius: 24px; font-size: 16px; font-weight: 600;
                        cursor: pointer; transition: opacity 0.2s; text-decoration: none; display: inline-block;
                    }
                    .btn-safe:hover { opacity: 0.9; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }

                    details { margin-top: 30px; text-align: left; border-top: 1px solid var(--border-color); padding-top: 15px; }
                    summary { cursor: pointer; color: var(--secondary-text); font-size: 14px; user-select: none; }
                    .advanced-info { margin-top: 10px; font-size: 13px; color: var(--secondary-text); }
                    .unsafe-link { color: var(--secondary-text); text-decoration: underline; font-size: 12px; margin-top: 10px; display: block; text-align: right; cursor: pointer; }
                    .unsafe-link:hover { color: var(--warning-color); }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header-icon">🔓</div>
                    <h1>Connexion non sécurisée</h1>
                    <p>
                        Xplorer 2 a bloqué l'accès à <span class="domain-badge">\(hostname)</span>.<br><br>
                        Ce site utilise une connexion <strong>HTTP non chiffrée</strong>. Les informations que vous envoyez ou recevez peuvent être interceptées par des tiers.
                    </p>
                    
                    <div class="actions">
                        <button class="btn-safe" onclick="goBack()">Retourner en sécurité</button>
                    </div>

                    <details>
                        <summary>Détails avancés</summary>
                        <div class="advanced-info">
                            <strong>URL bloquée :</strong> \(safeUrlString)<br>
                            <strong>Code d'erreur :</strong> HTTPS_DOWNGRADE_FALLBACK<br><br>
                            Si vous comprenez les risques et souhaitez tout de même accéder à ce site non sécurisé :
                            <a class="unsafe-link" onclick="bypass()">Ignorer l'avertissement et continuer (Risqué)</a>
                        </div>
                    </details>
                </div>

                <script>
                    function goBack() {
                        if (window.history.length > 1) { window.history.back(); }
                        else { window.webkit.messageHandlers.homeHandler.postMessage('goHome'); }
                    }
                    function bypass() { window.webkit.messageHandlers.retryHandler.postMessage('bypass-http:\(safeUrlString)'); }
                </script>
            </body>
            </html>
            """
            
            // 3. CHARGEMENT (Toujours avec baseURL: nil pour la sécurité antiboucle)
            tabs[currentTabIndex].loadHTMLString(warningHTML, baseURL: nil)
        }
    func getAntiFingerprintScript() -> String {
            // --- Variables générées côté SWIFT (Constantes pendant toute la session de l'onglet) ---
            let randomMemory = [4, 8].randomElement() ?? 8
            let randomThreads = [4, 8, 12, 16].randomElement() ?? 8
            let randomPluginCount = Int.random(in: 2...5)
            
            // Bruit fixe (très léger) pour fausser les hashs Canvas sans être détecté comme "aléatoire"
            let canvasNoiseR = Int.random(in: -2...2)
            let canvasNoiseG = Int.random(in: -2...2)
            let canvasNoiseB = Int.random(in: -2...2)
            
            let audioNoise = Double.random(in: 0.0000001...0.0000005)
            let rectNoise = Double.random(in: -0.0001...0.0001)

            // Faux matériels graphiques plausibles
            let webGLVendors = ["Apple Inc."]
            let webGLRenderers = ["Apple M1", "Apple M2"]
            let randomVendor = webGLVendors.randomElement()!
            let randomRenderer = webGLRenderers.randomElement()!

            return """
            (function() {
                try {
                    // 1. Matériel (Hardware)
                    Object.defineProperty(navigator, 'deviceMemory', { get: () => \(randomMemory) });
                    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => \(randomThreads) });
                    Object.defineProperty(navigator, 'languages', { get: () =>['fr-FR', 'fr', 'en-US', 'en'] });

                    // 2. Empreinte Canvas (Bruit CONSTANT)
                    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                    CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                        const image = originalGetImageData.apply(this, arguments);
                        const res = image.data;
                        for (let i = 0; i < res.length; i += 4) {
                            res[i] = Math.min(255, Math.max(0, res[i] + \(canvasNoiseR)));     // R
                            res[i+1] = Math.min(255, Math.max(0, res[i+1] + \(canvasNoiseG))); // G
                            res[i+2] = Math.min(255, Math.max(0, res[i+2] + \(canvasNoiseB))); // B
                        }
                        return image;
                    };

                    // Indispensable : Intercepter toDataURL qui est très utilisé pour le hachage Canvas
                    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                    HTMLCanvasElement.prototype.toDataURL = function() {
                        const ctx = this.getContext('2d');
                        if (ctx) {
                            // Forcer l'application du bruit avant de générer l'URL
                            const imgData = ctx.getImageData(0, 0, this.width, this.height);
                            ctx.putImageData(imgData, 0, 0); 
                        }
                        return originalToDataURL.apply(this, arguments);
                    };

                    // 3. Audio Fingerprint
                    const originalGetChannelData = AudioBuffer.prototype.getChannelData;
                    AudioBuffer.prototype.getChannelData = function() {
                        const data = originalGetChannelData.apply(this, arguments);
                        for (let i = 0; i < data.length; i += 50) {
                            data[i] += \(audioNoise);
                        }
                        return data;
                    };

                    // 4. Protection WebGL (Masquer la carte graphique)
                    const getParameterProxy = function(original) {
                        return function(parameter) {
                            // 37445 = UNMASKED_VENDOR_WEBGL, 37446 = UNMASKED_RENDERER_WEBGL
                            if (parameter === 37445) return '\(randomVendor)';
                            if (parameter === 37446) return '\(randomRenderer)';
                            return original.apply(this, arguments);
                        };
                    };
                    
                    if (window.WebGLRenderingContext) {
                        WebGLRenderingContext.prototype.getParameter = getParameterProxy(WebGLRenderingContext.prototype.getParameter);
                    }
                    if (window.WebGL2RenderingContext) {
                        WebGL2RenderingContext.prototype.getParameter = getParameterProxy(WebGL2RenderingContext.prototype.getParameter);
                    }

                    // 5. ClientRects Fingerprinting (Bloquer l'empreinte par les polices d'écriture)
                    const originalGetClientRects = Element.prototype.getClientRects;
                    Element.prototype.getClientRects = function() {
                        const rects = originalGetClientRects.apply(this, arguments);
                        if (!rects || rects.length === 0) return rects;
                        // On utilise un Proxy pour imiter parfaitement la classe DOMRectList native
                        return new Proxy(rects, {
                            get(target, prop) {
                                if (typeof target[prop] === 'function') return target[prop].bind(target);
                                if (!isNaN(prop)) {
                                    const rect = target[prop];
                                    return {
                                        top: rect.top + \(rectNoise),
                                        right: rect.right + \(rectNoise),
                                        bottom: rect.bottom + \(rectNoise),
                                        left: rect.left + \(rectNoise),
                                        width: rect.width + \(rectNoise),
                                        height: rect.height + \(rectNoise),
                                        x: rect.x + \(rectNoise),
                                        y: rect.y + \(rectNoise),
                                        toJSON: () => rect.toJSON()
                                    };
                                }
                                return target[prop];
                            }
                        });
                    };

                    // 6. Masquer WebDriver et simuler des plugins aléatoires
                    Object.defineProperty(navigator, 'webdriver', { get: () => false });
                    const fakePlugins = Array.from({length: \(randomPluginCount)}, (_, i) => ({
                        name: 'PDF Viewer ' + i,
                        description: 'Portable Document Format',
                        filename: 'internal-pdf-viewer'
                    }));
                    Object.defineProperty(navigator, 'plugins', { get: () => fakePlugins });

                    // 7. Uniformiser la résolution d'écran reportée
                    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
                    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });

                } catch (e) { console.error("Anti-FP Error:", e); }
            })();
            """
        }
    func loadPhishingWarning(for url: URL) {
        // 1. DÉCLARATION DES VARIABLES
        // On sécurise l'URL pour éviter les bugs dans le JS
        let safeUrlString = url.absoluteString.replacingOccurrences(of: "'", with: "\\'")
        
        // On récupère le nom de domaine ou on met un texte par défaut
        let hostname = url.host ?? "Ce site web"
        
        // 2. LE CODE HTML
        let warningHTML = """
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Site Trompeur - Xplorer</title>
            <style>
                :root {
                    --bg-color: #ffffff;
                    --text-color: #202124;
                    --card-bg: #f8f9fa;
                    --danger-color: #d93025;
                    --button-bg: #1a73e8;
                    --button-text: #ffffff;
                    --secondary-text: #5f6368;
                    --border-color: #dadce0;
                }
                
                @media (prefers-color-scheme: dark) {
                    :root {
                        --bg-color: #202124;
                        --text-color: #e8eaed;
                        --card-bg: #303134;
                        --danger-color: #f28b82;
                        --button-bg: #8ab4f8;
                        --button-text: #202124;
                        --secondary-text: #9aa0a6;
                        --border-color: #5f6368;
                    }
                }

                body {
                    margin: 0;
                    padding: 20px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    background-color: var(--danger-color);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    transition: background-color 0.3s;
                }
                
                @media (prefers-color-scheme: dark) {
                    body { background-color: #2b0a0a; }
                }

                .container {
                    background-color: var(--bg-color);
                    border-radius: 12px;
                    padding: 40px;
                    max-width: 500px;
                    width: 90%;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                    text-align: center;
                    position: relative;
                    overflow: hidden;
                }
                
                .header-icon { font-size: 60px; margin-bottom: 20px; animation: pulse 2s infinite; }
                @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.1); } 100% { transform: scale(1); } }

                h1 { margin: 0 0 15px 0; font-size: 24px; color: #d93025; font-weight: 700; }
                @media (prefers-color-scheme: dark) { h1 { color: #f28b82; } }

                p { margin: 0 0 25px 0; line-height: 1.6; color: var(--text-color); font-size: 16px; }

                .domain-badge {
                    background-color: var(--card-bg);
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-family: 'Menlo', monospace;
                    font-weight: bold;
                    border: 1px solid var(--border-color);
                }

                .actions { display: flex; flex-direction: column; gap: 15px; }

                .btn-safe {
                    background-color: var(--button-bg); color: var(--button-text); border: none;
                    padding: 12px 24px; border-radius: 24px; font-size: 16px; font-weight: 600;
                    cursor: pointer; transition: opacity 0.2s; text-decoration: none; display: inline-block;
                }
                .btn-safe:hover { opacity: 0.9; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }

                details { margin-top: 30px; text-align: left; border-top: 1px solid var(--border-color); padding-top: 15px; }
                summary { cursor: pointer; color: var(--secondary-text); font-size: 14px; user-select: none; }
                .advanced-info { margin-top: 10px; font-size: 13px; color: var(--secondary-text); }
                .unsafe-link { color: var(--secondary-text); text-decoration: underline; font-size: 12px; margin-top: 10px; display: block; text-align: right; cursor: pointer; }
                .unsafe-link:hover { color: var(--danger-color); }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header-icon">🛡️</div>
                <h1>Site trompeur détecté</h1>
                <p>
                    Xplorer 2 a bloqué l'accès à <span class="domain-badge">\(hostname)</span>.<br><br>
                    Ce site a été signalé comme étant du <strong>phishing</strong>. Il tente probablement de dérober vos mots de passe ou vos informations bancaires.
                </p>
                
                <div class="actions">
                    <button class="btn-safe" onclick="goBack()">Retourner en lieu sûr</button>
                </div>

                <details>
                    <summary>Détails avancés</summary>
                    <div class="advanced-info">
                        <strong>URL bloquée :</strong> \(safeUrlString)<br>
                        <strong>Code d'erreur :</strong> PHISHING_DETECTED_LOCAL_DB<br><br>
                        Si vous comprenez les risques et souhaitez tout de même accéder à ce site dangereux :
                        <a class="unsafe-link" onclick="bypass()">Ignorer l'avertissement et continuer (Dangereux)</a>
                    </div>
                </details>
            </div>

            <script>
                function goBack() {
                    if (window.history.length > 1) { window.history.back(); }
                    else { window.webkit.messageHandlers.homeHandler.postMessage('goHome'); }
                }
                function bypass() {
                    // Envoi du message chiffré à Swift !
                    window.webkit.messageHandlers.retryHandler.postMessage('bypass-phishing:\(safeUrlString)');
                }
            </script>
        </body>
        </html>
        """
        
        // 3. CHARGEMENT
        tabs[currentTabIndex].loadHTMLString(warningHTML, baseURL: url)
    }
    func toggleDevTools() {
        if isDevToolsOpen {
            // Fermer
            devToolsView?.removeFromSuperview()
            devToolsView = nil
            isDevToolsOpen = false
        } else {
            // Ouvrir
            let height: CGFloat = 250 // Hauteur de la console
            let frame = CGRect(x: 0, y: view.frame.height - height, width: view.frame.width, height: height)
            
            let tools = DevToolsView(frame: frame)
            tools.autoresizingMask = [.flexibleWidth, .flexibleTopMargin] // S'adapte si on tourne l'iPad
            
            // Action quand on tape du code
            tools.onCommand = { [weak self] code in
                self?.tabs[self?.currentTabIndex ?? 0].evaluateJavaScript(code) { res, err in
                    if let err = err {
                        tools.log(err.localizedDescription, type: "error")
                    } else if let res = res {
                        tools.log("\(res)", type: "result")
                    } else {
                        tools.log("Exécuté.", type: "result")
                    }
                }
            }
            
            // Action fermer
            tools.onClose = { [weak self] in
                self?.toggleDevTools()
            }
            
            view.addSubview(tools)
            devToolsView = tools
            isDevToolsOpen = true
            
            // On injecte le script d'espionnage immédiatement si ce n'est pas déjà fait
            let script = getDevToolsScript()
            tabs[currentTabIndex].evaluateJavaScript(script)
        }
    }
    func getDevToolsScript() -> String {
        return """
        (function() {
            // 1. Espionner la Console
            var oldLog = console.log;
            console.log = function(message) {
                window.webkit.messageHandlers.devTools.postMessage({type: 'log', content: message + ''});
                oldLog.apply(console, arguments);
            };
            var oldError = console.error;
            console.error = function(message) {
                window.webkit.messageHandlers.devTools.postMessage({type: 'error', content: message + ''});
                oldError.apply(console, arguments);
            };

            // 2. Espionner le Réseau (Fetch API)
            var oldFetch = window.fetch;
            window.fetch = async function(...args) {
                var url = args[0];
                window.webkit.messageHandlers.devTools.postMessage({type: 'network', content: 'REQ: ' + url});
                try {
                    const response = await oldFetch(...args);
                    window.webkit.messageHandlers.devTools.postMessage({type: 'network', content: 'RESP [' + response.status + ']: ' + url});
                    return response;
                } catch (e) {
                    window.webkit.messageHandlers.devTools.postMessage({type: 'error', content: 'NET FAIL: ' + url});
                    throw e;
                }
            };
            
            // 3. Espionner XHR (AJAX classique)
            var oldXHR = window.XMLHttpRequest;
            function newXHR() {
                var realXHR = new oldXHR();
                realXHR.addEventListener('load', function() {
                    window.webkit.messageHandlers.devTools.postMessage({type: 'network', content: 'XHR [' + realXHR.status + ']: ' + realXHR.responseURL});
                });
                return realXHR;
            }
            window.XMLHttpRequest = newXHR;
        })();
        """
    }
    func openConsole() {
        let alert = UIAlertController(title: "Console JS", message: "Exécuter du JavaScript", preferredStyle: .alert)
        
        alert.addTextField { tf in
            tf.placeholder = "ex: document.body.style.background = 'red'"
            tf.autocorrectionType = .no
            tf.autocapitalizationType = .none
        }
        
        let runAction = UIAlertAction(title: "Exécuter", style: .default) { _ in
            if let code = alert.textFields?.first?.text, !code.isEmpty {
                self.tabs[self.currentTabIndex].evaluateJavaScript(code) { result, error in
                    var message = ""
                    if let error = error {
                        message = "❌ Erreur : \(error.localizedDescription)"
                    } else if let result = result {
                        message = "✅ Résultat : \(result)"
                    } else {
                        message = "✅ Exécuté (Pas de retour)"
                    }
                    
                    // On affiche le résultat
                    let resultAlert = UIAlertController(title: "Console", message: message, preferredStyle: .alert)
                    resultAlert.addAction(UIAlertAction(title: "OK", style: .cancel))
                    self.present(resultAlert, animated: true)
                }
            }
        }
        
        alert.addAction(runAction)
        alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
        present(alert, animated: true)
    }
    func shareCurrentPage() {
        guard let url = tabs[currentTabIndex].url else { return }
        
        // On prépare ce qu'on veut partager (L'URL et le Titre du site)
        let itemsToShare: [Any] = [url, tabs[currentTabIndex].title ?? "Site Web"]
        
        // On crée la vue système de partage (standard iOS)
        let activityVC = UIActivityViewController(activityItems: itemsToShare, applicationActivities: nil)
        
        // IMPORTANT SUR IPAD : Il faut dire d'où sort la petite fenêtre (popover)
        // Sinon ça crash sur iPad !
        if let popover = activityVC.popoverPresentationController {
            popover.sourceView = self.menuButton // La fenêtre sortira du bouton Menu
        }
        
        self.present(activityVC, animated: true)
    }
    func viewSourceCode() {
            // 1. Récupération du HTML de la page actuelle
            tabs[currentTabIndex].evaluateJavaScript("document.documentElement.outerHTML.toString()") { result, error in
                
                guard let html = result as? String, error == nil else {
                    self.showAlert(title: "Erreur", message: "Impossible de lire le code.")
                    return
                }
                
                // 2. Création de la vue
                let sourceViewer = UIViewController()
                sourceViewer.title = "Code Source HTML"
                
                // 3. NOUVEAU : On utilise une WKWebView dédiée pour afficher Prism.js
                let webView = WKWebView(frame: sourceViewer.view.bounds)
                webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
                // Petit fond sombre par défaut pendant le chargement
                webView.backgroundColor = UIColor(red: 0.17, green: 0.17, blue: 0.17, alpha: 1)
                webView.isOpaque = false
                sourceViewer.view.addSubview(webView)
                
                // ÉTAPE CRUCIALE : On échappe les balises HTML pour qu'elles s'affichent
                // au lieu d'être interprétées comme du vrai code par la nouvelle WebView.
                let escapedHTML = html
                    .replacingOccurrences(of: "&", with: "&amp;")
                    .replacingOccurrences(of: "<", with: "&lt;")
                    .replacingOccurrences(of: ">", with: "&gt;")
                
                // 4. LE MOTEUR PRISM.JS
                let prismHTML = """
                <!DOCTYPE html>
                <html lang="fr">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
                    <title>Code Source</title>
                    <!-- Thème sombre Prism.js (Tomorrow Night) -->
                    <link href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
                    <style>
                        body { 
                            margin: 0; 
                            background-color: #2d2d2d; /* Matche exactement le fond du thème Tomorrow */
                        }
                        /* Forcer le conteneur de code à prendre tout l'écran */
                        pre[class*="language-"] { 
                            margin: 0 !important; 
                            padding: 15px !important;
                            border-radius: 0 !important; 
                            font-size: 13px;
                            min-height: 100vh;
                            box-sizing: border-box;
                        }
                    </style>
                </head>
                <body>
                    <!-- On indique à Prism qu'il s'agit de HTML (markup) -->
                    <pre><code class="language-markup">\(escapedHTML)</code></pre>
                    
                    <!-- Le moteur Javascript de Prism -->
                    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js"></script>
                </body>
                </html>
                """
                
                // On charge notre magnifique visionneuse de code
                webView.loadHTMLString(prismHTML, baseURL: nil)
                
                // 5. Ajout du Bouton Fermer dans la barre de navigation supérieure
                let closeAction = UIAction { _ in
                    sourceViewer.dismiss(animated: true)
                }
                sourceViewer.navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Fermer", primaryAction: closeAction)
                
                // 6. On emballe le tout pour avoir un bel affichage sur iPad
                let navController = UINavigationController(rootViewController: sourceViewer)
                
                // On force un look sombre pour la barre de navigation pour matcher Prism
                navController.navigationBar.barStyle = .black
                navController.navigationBar.tintColor = .white
                navController.navigationBar.titleTextAttributes = [.foregroundColor: UIColor.white]
                navController.navigationBar.barTintColor = UIColor(red: 0.17, green: 0.17, blue: 0.17, alpha: 1)
                
                navController.modalPresentationStyle = .pageSheet
                
                self.present(navController, animated: true)
            }
        }
    // Fonction utilitaire pour configurer proprement n'importe quel onglet
    func setupConfigurationForNewTab(_ config: WKWebViewConfiguration, isPrivate: Bool) {
        // --- AJOUTEZ CE BLOC AU DÉBUT DE LA FONCTION ---
            // Si ce n'est pas un onglet privé, on partage le processus mémoire
            if !isPrivate {
                config.processPool = BrowserViewController.sharedProcessPool
            }
        // 1. Réglage des préférences (Correction du warning iOS 14+)
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        config.defaultWebpagePreferences = prefs
        config.preferences.javaScriptCanOpenWindowsAutomatically = true
        
        // 2. Persistance des données (Privé ou non)
        config.websiteDataStore = isPrivate ? WKWebsiteDataStore.nonPersistent() : WKWebsiteDataStore.default()
        
        // 3. Recréation des Scripts (UserAgent & Anti-fingerprinting)
        // On les recrée à neuf au lieu de les copier pour éviter le crash
        let modernUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15"
        let uaScript = WKUserScript(
            source: "navigator.userAgent = '\(modernUserAgent)';",
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        config.userContentController.addUserScript(uaScript)

        let modernFeaturesScript = """
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
            window.chrome = { runtime: {} };
            Object.defineProperty(window, 'outerWidth', { get: () => 1920 });
            Object.defineProperty(window, 'outerHeight', { get: () => 1080 });
            navigator.plugins = [{ name: 'Chrome PDF Viewer' }];
        """
        let featuresScript = WKUserScript(
            source: modernFeaturesScript,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        config.userContentController.addUserScript(featuresScript)
        // AJOUT DE L'ANTI-FINGERPRINTING
            let afScriptSource = getAntiFingerprintScript()
            let afScript = WKUserScript(
                source: afScriptSource,
                injectionTime: .atDocumentStart, // Indispensable : avant que le site ne charge
                forMainFrameOnly: false          // On protège aussi les pubs/iframes
            )
            config.userContentController.addUserScript(afScript)
        // 4. Ré-ajout des Message Handlers (Indispensable pour que vos boutons marchent !)
        // Note : Dans un vrai projet, utilisez WeakScriptMessageHandler ici aussi pour éviter les fuites de mémoire.
        // Pour le Playground, ceci suffit :
        let handlers = ["retryHandler", "fetchBridge", "engineHandler", "customizeHandler", "homeHandler"]
        for name in handlers {
            // On enlève l'ancien s'il existe pour éviter les doublons
            config.userContentController.removeScriptMessageHandler(forName: name)
            config.userContentController.add(self, name: name)
        }
        if let adBlockRules = AdBlockManager.shared.compiledRuleList {
                config.userContentController.add(adBlockRules)
                print("Bloqueur de pub appliqué au nouvel onglet")
            }
        // Ajout du script DevTools
        let devScript = WKUserScript(source: getDevToolsScript(), injectionTime: .atDocumentStart, forMainFrameOnly: false)
        config.userContentController.addUserScript(devScript)
    }
    // MARK: - Analyse SSL
    func extractCertificateData(trust: SecTrust) -> [String: String] {
        var info: [String: String] = [:]
        
        guard let cert0 = SecTrustGetCertificateAtIndex(trust, 0) else { return info }
        
        // 1. Sujet
        if let subject = SecCertificateCopySubjectSummary(cert0) as String? {
            info["Sujet"] = subject
        }
        
        // 2. Émetteur (Via la chaîne de confiance)
        if SecTrustGetCertificateCount(trust) > 1,
           let cert1 = SecTrustGetCertificateAtIndex(trust, 1),
           let issuer = SecCertificateCopySubjectSummary(cert1) as String? {
            info["Émetteur"] = issuer
        } else {
            info["Émetteur"] = "Certificat Racine / Auto-signé"
        }
        
        // 3. Expiration (Extraction manuelle des données brutes)
        if let expirationDate = findExpirationDateInRawData(certificate: cert0) {
            info["Expiration"] = expirationDate
        } else {
            info["Expiration"] = "Non trouvée"
        }
        
        return info
    }

    // Fonction auxiliaire pour fouiller dans le code binaire du certificat
    private func findExpirationDateInRawData(certificate: SecCertificate) -> String? {
        let data = SecCertificateCopyData(certificate) as Data
        var datesFound: [String] = []
        
        var index = 0
        // On parcourt les octets du fichier
        while index < data.count - 15 {
            // Le marqueur 0x17 signifie "UTCTime" (Format YYMMDDHHMMSSZ)
            // C'est le standard pour les certificats SSL web
            if data[index] == 0x17 {
                let length = Int(data[index + 1]) // La longueur suit le marqueur
                
                // Une date UTCTime fait standardement 13 caractères
                if length == 13, index + 2 + length < data.count {
                    if let dateString = String(data: data.subdata(in: (index + 2)..<(index + 2 + length)), encoding: .ascii) {
                        datesFound.append(dateString)
                    }
                }
            }
            index += 1
        }
        
        // Dans un certificat, la 1ère date est "Début de validité", la 2ème est "Expiration"
        if datesFound.count >= 2 {
            let rawDate = datesFound[1] // ex: 250521120000Z
            return formatRawDate(rawDate)
        }
        
        return nil
    }

    // Fonction pour rendre la date jolie (de 250101... à "01/01/2025")
    private func formatRawDate(_ raw: String) -> String {
        // Format brut: YYMMDDHHMMSSZ (ex: 250111235959Z)
        guard raw.count >= 6 else { return raw }
        
        let year = "20" + raw.prefix(2)
        let month = raw.dropFirst(2).prefix(2)
        let day = raw.dropFirst(4).prefix(2)
        
        return "\(day)/\(month)/\(year)"
    }
    
    // MARK: - Propriétés
    var devToolsView: DevToolsView?
    var isDevToolsOpen = false
    let webView: WKWebView
    let addressBar = UITextField()
    let goButton = UIButton(type: .system)
    let backButton = UIButton(type: .system)
    let forwardButton = UIButton(type: .system)
    let refreshButton = UIButton(type: .system)
    let progressBar = UIProgressView(progressViewStyle: .default)
    let menuButton = UIButton(type: .system)
    let securityIcon = UIImageView()
    var tabs: [WKWebView] = []
    var currentTabIndex = 0
    let tabBar = UIScrollView()
    var tabButtons: [UIButton] = []
    // Variables pour la gestion des téléchargements
        var oneTimeAuthorizedURL: String?
        var currentNativeDownloadURL: URL?
    // Mémorise les sites HTTP dangereux que l'utilisateur a accepté de visiter et 
    // mémorise les sites HTTP dangereux de façon permanente
        var bypassedHTTPHosts: Set<String> {
            get { Set(UserDefaults.standard.stringArray(forKey: "bypassedHTTPHosts") ?? []) }
            set { UserDefaults.standard.set(Array(newValue), forKey: "bypassedHTTPHosts") }
        }
    struct HistoryEntry {
        let url: URL
        let timestamp: Date 
    }
    var history: [[HistoryEntry]] = [[]]
    var bookmarks: [(title: String, url: URL)] = []
    var isFullScreen = false
    var isDarkMode: Bool = false
    var isPrivateMode: Bool = false
    var customBackgroundColor: UIColor = .systemGray6
    var currentSearchEngine: String = "google"
    // Mémorise les sites dont on a accepté le certificat SSL invalide
    var bypassedSSLHosts: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: "bypassedSSLHosts") ?? []) }
        set { UserDefaults.standard.set(Array(newValue), forKey: "bypassedSSLHosts") }
    }
    // Mémorise les sites de phishing bypassés de façon permanente
       var bypassedPhishingHosts: Set<String> {
           get { Set(UserDefaults.standard.stringArray(forKey: "bypassedPhishingHosts") ?? []) }
           set { UserDefaults.standard.set(Array(newValue), forKey: "bypassedPhishingHosts") }
       }
    let networkMonitor = NWPathMonitor()
    var isNetworkAvailable: Bool = true
    var allowedInlineFiles: Set<String> = []
        
        // Pour mémoriser le téléchargement en cours (permet de l'annuler)
        var currentDownloadTask: URLSessionDownloadTask?
    var lastFailedURL: String?
    var lastNetworkError: Error?
    var sslCertificateInfo: [String: Any]?
    var cfError: CFError?
    weak var viewController: UIViewController?
        var certificateInfo: [String: String]?
        var completionHandler: ((URLCredential?) -> Void)?
    
    let faviconCache: NSCache<NSString, UIImage> = {
        let cache = NSCache<NSString, UIImage>()
        cache.countLimit = 50
        cache.totalCostLimit = 10 * 1024 * 1024
        return cache
    }()
    let maxTabs = 50
    
    // MARK: - Gestion des erreurs (tu peux ajouter ce commentaire pour organiser ton code)

        private func displayErrorMessage(message: String) {
            let alertController = UIAlertController(title: "Erreur", message: message, preferredStyle: .alert)
            let okAction = UIAlertAction(title: "OK", style: .default)
            alertController.addAction(okAction)
            present(alertController, animated: true)
        }
    
    let privateWebConfiguration: WKWebViewConfiguration = {
        let config = WKWebViewConfiguration()
        config.processPool = BrowserViewController.sharedProcessPool
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
       config.applicationNameForUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15"
        let preferences = WKPreferences()
        preferences.javaScriptEnabled = true
        preferences.javaScriptCanOpenWindowsAutomatically = true
        config.preferences = preferences
        let modernUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15"
        config.userContentController.addUserScript(
            WKUserScript(
                source: "navigator.userAgent = '\(modernUserAgent)';",
                injectionTime: .atDocumentStart,
                forMainFrameOnly: true
            )
        )
        let modernFeaturesScript = """
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
            window.chrome = { runtime: {} };
            Object.defineProperty(window, 'outerWidth', { get: () => 1920 });
            Object.defineProperty(window, 'outerHeight', { get: () => 1080 });
            navigator.plugins = [{ name: 'Chrome PDF Viewer' }];
        """
        config.userContentController.addUserScript(
            WKUserScript(
                source: modernFeaturesScript,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: true
            )
        )
        return config
    }()
    
    let webConfiguration: WKWebViewConfiguration = {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore.default()
        config.applicationNameForUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15"
        let preferences = WKPreferences()
        let webpagePreferences = WKWebpagePreferences()
        webpagePreferences.allowsContentJavaScript = true
        config.defaultWebpagePreferences = webpagePreferences
        preferences.javaScriptCanOpenWindowsAutomatically = true
        config.preferences = preferences
        let modernUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15"
        config.userContentController.addUserScript(
            WKUserScript(
                source: "navigator.userAgent = '\(modernUserAgent)';",
                injectionTime: .atDocumentStart,
                forMainFrameOnly: true
            )
        )
        let modernFeaturesScript = """
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
            window.chrome = { runtime: {} };
            Object.defineProperty(window, 'outerWidth', { get: () => 1920 });
            Object.defineProperty(window, 'outerHeight', { get: () => 1080 });
            navigator.plugins = [{ name: 'Chrome PDF Viewer' }];
        """
        config.userContentController.addUserScript(
            WKUserScript(
                source: modernFeaturesScript,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: true
            )
        )
        return config
    }()
    
    // MARK: - Autocomplétion UI
    let suggestionView: UIView = {
        let view = UIView()
        view.backgroundColor = .white
        view.layer.cornerRadius = 8
        view.layer.shadowColor = UIColor.black.cgColor
        view.layer.shadowOpacity = 0.2
        view.layer.shadowOffset = CGSize(width: 0, height: 2)
        view.layer.shadowRadius = 4
        view.isHidden = true
        return view
    }()
    
    let suggestionTableView: UITableView = {
        let tableView = UITableView()
        tableView.backgroundColor = .clear
        tableView.layer.cornerRadius = 8
        tableView.isScrollEnabled = true
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "SuggestionCell")
        return tableView
    }()
    
    var suggestions: [String] = []
    
    // MARK: - HTML Pages
    var newTabHTML: String {
            let backgroundColor = UIColorToHex(color: customBackgroundColor)
            let textColor = isDarkMode ? "#e8eaed" : "#202124"
            let searchBarBgColor = isDarkMode ? "#303134" : "#FFFFFF"
            let borderColor = isDarkMode ? "#5f6368" : "#dfe1e5"
            let shortcutBgColor = isDarkMode ? "#303134" : "#FFFFFF"
            let logoStrokeColor = isDarkMode ? "#e8eaed" : "#666"
            let privateModeText = isPrivateMode ? "(Privé)" : ""
            let darkModeChecked = isDarkMode ? "checked" : ""
            // Si internet est là = Vert. Sinon = Rouge/Gris
            let statusColor = isNetworkAvailable ? "#34a853" : "#ea4335" 
            let shadowColor = isNetworkAvailable ? "rgba(52, 168, 83, 0.4)" : "rgba(234, 67, 53, 0.4)"
            let shieldText = isNetworkAvailable ? "Bouclier Actif" : "Bouclier (Local)"
            let dohText = isNetworkAvailable ? "DoH Cloudflare" : "DNS Hors ligne"
                let calendar = Calendar.current
                let components = calendar.dateComponents([.month, .day], from: Date())
        let isAprilFools = (components.month == 4 && components.day == 1)
                
                // On remplace le texte et même le logo SVG par un emoji géant !
                let mainTitle = isAprilFools ? "🐟 Truite d'Avril !" : "Xplorer 2"
                let logoHTML = isAprilFools ? 
                    "<div style='font-size: 70px; animation: pulse 2s infinite;'>🐟</div>" : 
                    """
                    <svg class="logo" width="80" height="80" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="50" cy="50" r="45" fill="none" stroke="#4285f4" stroke-width="4"/>
                        <path d="M30 30 L70 70 M70 30 L30 70" stroke="\(logoStrokeColor)" stroke-width="8" stroke-linecap="round"/>
                        <circle cx="50" cy="10" r="5" fill="#4285f4"/>
                        <circle cx="50" cy="90" r="5" fill="#4285f4"/>
                        <circle cx="10" cy="50" r="5" fill="#4285f4"/>
                        <circle cx="90" cy="50" r="5" fill="#4285f4"/>
                    </svg>
                    """

            return """
                <!DOCTYPE html>
                <html lang="fr">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Nouvel onglet - Xplorer 2</title>
                    <style>
                        body {
                            margin: 0;
                            padding: 0;
                            font-family: 'Roboto', Arial, sans-serif;
                            background-color: \(backgroundColor);
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            height: 100vh;
                            color: \(textColor);
                            overflow: hidden;
                            animation: fadeIn 0.5s ease-in; /* Animation d’entrée */
                        }
                        @keyframes fadeIn {
                            from { opacity: 0; }
                            to { opacity: 1; }
                        }
                        
                        /* BADGES DE SÉCURITÉ ULTRA DISCRETS (SANS GROSSES BORDURES) */
                        .security-status {
                            position: absolute;
                            top: 15px;
                            left: 20px;
                            display: flex;
                            gap: 15px;
                            font-size: 11px;
                            font-weight: 500;
                            opacity: 0.4; /* Ultra transparent pour se fondre dans le décor */
                            pointer-events: none; /* Pour ne pas gêner les clics */
                            color: \(textColor);
                        }
                        .badge {
                            display: flex;
                            align-items: center;
                            gap: 6px;
                        }
                        .dot-status {
                            width: 6px;
                            height: 6px;
                            background-color: \(statusColor);
                            border-radius: 50%;
                            box-shadow: 0 0 4px \(shadowColor);
                        }

                        .logo-container {
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            margin-bottom: 20px;
                        }
                        .logo {
                            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.1));
                            animation: pulse 2s infinite; /* Animation dynamique pour l’icône */
                        }
                        @keyframes pulse {
                            0%, 100% { transform: scale(1); }
                            50% { transform: scale(1.05); }
                        }
                        .title {
                            font-size: 36px;
                            font-weight: 700;
                            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                        }
                        .search-container {
                            width: 60%;
                            max-width: 600px;
                            margin-bottom: 40px;
                            position: relative;
                            display: flex; /* Ajout de flex pour aligner l'icône */
                            align-items: center; /* Aligner verticalement l'icône */
                        }
                        .search-bar {
                            width: 100%;
                            padding: 12px 40px 12px 20px;
                            font-size: 16px;
                            border: 1px solid \(borderColor);
                            border-radius: 24px;
                            box-shadow: 0 1px 6px rgba(32, 33, 36, 0.28);
                            outline: none;
                            background-color: \(searchBarBgColor);
                            color: \(textColor);
                            box-sizing: border-box;
                        }
                        .search-icon {
                            position: absolute;
                            right: 15px;
                            color: \(isDarkMode ? "#bdc1c6" : "#9aa0a6");
                            cursor: pointer;
                        }
                        .search-bar:focus {
                            border-color: #4285f4;
                        }
                        .suggestions {
                                                    position: absolute;
                                                    top: calc(100% + 8px); /* Crée un petit espace élégant sous la barre */
                                                    left: 0;
                                                    width: 100%;
                                                    background-color: \(searchBarBgColor);
                                                    border: 1px solid \(borderColor);
                                                    border-radius: 16px; /* Des bords bien arrondis partout */
                                                    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12); /* Ombre plus douce, large et "Apple-like" */
                                                    max-height: 250px;
                                                    overflow-y: auto;
                                                    display: none;
                                                    z-index: 100; /* S'assure que la boîte passe au-dessus du reste */
                                                    padding: 8px 0; /* Ajoute de l'air en haut et en bas de la liste */
                                                    box-sizing: border-box;
                                                }
                                                
                                                .suggestion {
                                                    padding: 12px 20px; /* Un peu plus haut pour faciliter le clic au doigt sur iPad */
                                                    cursor: pointer;
                                                    font-size: 16px;
                                                    transition: background-color 0.15s ease; /* Transition douce quand on passe la souris/le doigt */
                                                }
                                                
                                                .suggestion:hover {
                                                    background-color: \(isDarkMode ? "#424548" : "#f1f3f4");
                                                }
                        .suggestion:hover {
                            background-color: \(isDarkMode ? "#424548" : "#f1f3f4");
                        }
                        .shortcuts {
                            display: grid;
                            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
                            gap: 20px;
                            width: 60%;
                            max-width: 600px;
                        }
                        .shortcut {
                            text-align: center;
                            background-color: \(shortcutBgColor);
                            padding: 10px;
                            border-radius: 8px;
                            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                            cursor: pointer;
                            transition: transform 0.2s ease, box-shadow 0.2s ease;
                        }
                        .shortcut:hover {
                            transform: scale(1.05);
                            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                        }
                        .shortcut img {
                            width: 48px;
                            height: 48px;
                            border-radius: 50%;
                        }
                        .shortcut p {
                            margin: 5px 0 0;
                            font-size: 14px;
                        }
                        .customize-btn {
                            position: absolute;
                            top: 10px;
                            right: 10px;
                            padding: 8px 16px;
                            background-color: #4285f4;
                            color: white;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            transition: background-color 0.2s ease;
                        }
                        .customize-btn:hover {
                            background-color: #357abd;
                        }
                        .customize-menu {
                            display: none;
                            position: absolute;
                            top: 50px;
                            right: 10px;
                            background-color: \(shortcutBgColor);
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
                            z-index: 1000;
                            width: 250px;
                        }
                        .customize-menu h3 {
                            margin: 0 0 15px;
                            font-size: 16px;
                            font-weight: 500;
                        }
                        .customize-menu label {
                            display: block;
                            margin: 10px 0;
                            font-size: 14px;
                        }
                        .customize-menu input[type="checkbox"],
                        .customize-menu input[type="text"],
                        .customize-menu input[type="url"] {
                            margin-left: 5px;
                            vertical-align: middle;
                        }
                        .customize-menu input[type="color"] {
                            vertical-align: middle;
                            width: 40px;
                            height: 25px;
                            border: none;
                            padding: 0;
                            cursor: pointer;
                        }
                        .customize-menu select {
                            width: 100%;
                            padding: 5px;
                            margin-top: 5px;
                        }
                        .customize-menu button {
                            padding: 6px 12px;
                            margin: 5px 5px 0 0;
                            background-color: #4285f4;
                            color: white;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                        }
                        .customize-menu button:hover {
                            background-color: #357abd;
                        }
                        .customize-menu button:last-child {
                            background-color: transparent;
                            color: #4285f4;
                            border: 1px solid #4285f4;
                        }
                        .customize-menu button:last-child:hover {
                            background-color: rgba(66, 133, 244, 0.1);
                        }
                        @media (max-width: 600px) {
                            .search-container, .shortcuts {
                                width: 90%;
                            }
                            .title {
                                font-size: 28px;
                            }
                            .shortcut img {
                                width: 36px;
                                height: 36px;
                            }
                            .shortcut p {
                                font-size: 12px;
                            }
                        }
                    </style>
                </head>
                <body>
                    <div class="security-status">
                        <div class="badge"><div class="dot-status"></div> \(shieldText)</div>
                        <div class="badge"><div class="dot-status"></div> \(dohText)</div>
                    </div>

                    <div class="logo-container">
                        \(logoHTML)
                        <div class="title">\(mainTitle) \(privateModeText)</div>
                    </div>
                    <div class="search-container">
                        <input type="text" class="search-bar" placeholder="Rechercher ou entrer une URL" autofocus>
                        <span class="search-icon" onclick="loadUrl()">
                                🔍
                            </span>
                <div class="suggestions" id="suggestions"></div>
                    </div>
                    <div class="shortcuts" id="shortcuts">
                        <div class="shortcut" data-url="https://www.google.com">
                            <img src="https://www.google.com/favicon.ico" alt="Google" loading="lazy">
                            <p>Google</p>
                        </div>
                        <div class="shortcut" data-url="https://www.youtube.com">
                            <img src="https://www.gstatic.com/images/branding/product/1x/youtube_64dp.png" alt="YouTube" loading="lazy">
                            <p>YouTube</p>
                        </div>
                        <div class="shortcut" data-url="https://fr.wikipedia.org">
                            <img src="https://www.wikipedia.org/favicon.ico" alt="Wikipédia" loading="lazy">
                            <p>Wikipédia</p>
                        </div>
                        <div class="shortcut" data-url="https://open.spotify.com">
                            <img src="https://upload.wikimedia.org/wikipedia/commons/1/19/Spotify_logo_without_text.svg" alt="Spotify" loading="lazy">
                            <p>Spotify</p>
                        </div>
                <div class="shortcut" data-url="https://notebooklm.google.com">
                                <img src="https://www.gstatic.com/images/branding/productlogos/notebooklm/v1/web-64dp/logo_notebooklm_color_1x_web_64dp.png" alt="NotebookLM" loading="lazy">
                                <p>NotebookLM</p>
                            </div>
                <div class="shortcut" data-url="https://aistudio.google.com">
                                    <img src="https://upload.wikimedia.org/wikipedia/commons/b/b5/Google_ai_studio_logo.png" alt="Google AI Studio" loading="lazy">
                                    <p>Google AI Studio</p>
                                </div>
                    </div>
                    <button class="customize-btn">Personnaliser</button>
                    <div class="customize-menu" id="customize-menu">
                        <h3>Personnalisation</h3>
                        <label>Mode sombre:
                            <input type="checkbox" id="darkMode" \(darkModeChecked)>
                        </label>
                        <label>Couleur de fond:
                            <input type="color" id="bgColor" value="\(backgroundColor)">
                        </label>
                        <label>Thème:
                            <select id="themeSelect">
                                <option value="default">Par défaut</option>
                                <option value="ocean">Océan</option>
                                <option value="forest">Forêt</option>
                            </select>
                        </label>
                        <h3>Ajouter un raccourci</h3>
                        <label>Nom:
                            <input type="text" id="shortcutName" placeholder="Nom du site">
                        </label>
                        <label>URL:
                            <input type="url" id="shortcutUrl" placeholder="https://exemple.com">
                        </label>
                        <label>Icône (URL):
                            <input type="url" id="shortcutIcon" placeholder="https://exemple.com/favicon.ico">
                        </label>
                        <button onclick="addShortcut()">Ajouter</button>
                        <button onclick="closeCustomization()">Fermer</button>
                    </div>
                    <script>
                function applyColorScheme() {
                    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    const body = document.body;
                    const searchBar = document.querySelector('.search-bar');
                    const suggestionsDiv = document.getElementById('suggestions');
                    const shortcuts = document.querySelectorAll('.shortcut');
                    const logoPath = document.querySelector('.logo path');

                    if (prefersDark) {
                        body.style.backgroundColor = '#303134';
                        body.style.color = '#e8eaed';
                        if (searchBar) {
                            searchBar.style.backgroundColor = '#303134';
                            searchBar.style.color = '#e8eaed';
                            searchBar.style.borderColor = '#5f6368';
                        }
                        if (suggestionsDiv) {
                            suggestionsDiv.style.backgroundColor = '#303134';
                            suggestionsDiv.style.borderColor = '#5f6368';
                        }
                        shortcuts.forEach(shortcut => {
                            shortcut.style.backgroundColor = '#303134';
                            shortcut.style.color = '#e8eaed';
                        });
                        if (logoPath) {
                            logoPath.setAttribute('stroke', '#e8eaed');
                        }
                    } else {
                        body.style.backgroundColor = '#FFFFFF';
                        body.style.color = '#202124';
                        if (searchBar) {
                            searchBar.style.backgroundColor = '#FFFFFF';
                            searchBar.style.color = '#202124';
                            searchBar.style.borderColor = '#dfe1e5';
                        }
                        if (suggestionsDiv) {
                            suggestionsDiv.style.backgroundColor = '#FFFFFF';
                            suggestionsDiv.style.borderColor = '#dfe1e5';
                        }
                        shortcuts.forEach(shortcut => {
                            shortcut.style.backgroundColor = '#FFFFFF';
                            shortcut.style.color = '#202124';
                        });
                        if (logoPath) {
                            logoPath.setAttribute('stroke', '#666');
                        }
                    }
                }

                applyColorScheme();
                window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyColorScheme);
                        const searchBar = document.querySelector('.search-bar');
                        const suggestionsDiv = document.getElementById('suggestions');
                        const customizeBtn = document.querySelector('.customize-btn');
                        const customizeMenu = document.getElementById('customize-menu');
                        const shortcutsContainer = document.getElementById('shortcuts');
                        const darkModeCheckbox = document.getElementById('darkMode');
                        const bgColorInput = document.getElementById('bgColor');
                        const themeSelect = document.getElementById('themeSelect');
                        const shortcutName = document.getElementById('shortcutName');
                        const shortcutUrl = document.getElementById('shortcutUrl');
                        const shortcutIcon = document.getElementById('shortcutIcon');

                        const themes = {
                            'default': { bg: '\(backgroundColor)', text: '\(textColor)', logoStroke: '\(logoStrokeColor)' },
                            'ocean': { bg: '#1e90ff', text: '#ffffff', logoStroke: '#ffffff' },
                            'forest': { bg: '#228b22', text: '#ffffff', logoStroke: '#ffffff' }
                        };

                        //Fonction qui fait le pont avec Swift pour contourner le CORS
                                        window.nativeFetchJSON = function(url) {
                                            return new Promise((resolve, reject) => {
                                                // On crée un ID unique pour cette requête
                                                const callbackId = 'cb_' + Math.random().toString(36).substr(2, 9);
                                                
                                                // Swift appellera cette fonction quand la requête sera finie
                                                window[callbackId] = function(data) {
                                                    delete window[callbackId]; // Nettoyage de la mémoire
                                                    if (data && data.error) {
                                                        reject("Erreur Réseau Swift");
                                                    } else {
                                                        resolve(data); // On renvoie l'objet JSON propre
                                                    }
                                                };
                                                
                                                // On envoie l'ordre au Swift
                                                window.webkit.messageHandlers.fetchBridge.postMessage({
                                                    url: url,
                                                    callbackId: callbackId
                                                });
                                            });
                                        };

                                        searchBar.addEventListener('input', async function() {
                                            const query = this.value.trim();
                                            if (query) {
                                                try {
                                                    // On utilise nativeFetchJSON au lieu de fetch standard
                                                    const url = `https://suggestqueries.google.com/complete/search?client=firefox&q=${encodeURIComponent(query)}`;
                                                    const suggestions = await window.nativeFetchJSON(url);
                                                    
                                                    // Affichage des suggestions
                                                    suggestionsDiv.innerHTML = suggestions[1].map(s => `<div class="suggestion" onclick="searchBar.value='${s}'; loadUrl()">${s}</div>`).join('');
                                                    suggestionsDiv.style.display = 'block';
                                                } catch (e) {
                                                    console.error("Erreur Autocomplétion :", e);
                                                    suggestionsDiv.style.display = 'none';
                                                }
                                            } else {
                                                suggestionsDiv.style.display = 'none';
                                            }
                                        });
                        searchBar.addEventListener('blur', () => setTimeout(() => suggestionsDiv.style.display = 'none', 100));

                        searchBar.addEventListener('keydown', function(event) {
                            if (event.key === 'Enter') {
                                loadUrl();
                            }
                        });

                        function loadUrl() {
                            const value = searchBar.value.trim();
                            if (value) {
                                const url = value.includes('.') ? 
                                    (value.match(/^\\s*https?:\\/\\//) ? value : 'https://' + value) : 
                                    'https://www.google.com/search?q=' + encodeURIComponent(value);
                                window.location.href = url;
                            }
                        }

                        shortcutsContainer.addEventListener('click', function(event) {
                            const shortcut = event.target.closest('.shortcut');
                            if (shortcut) {
                                const url = shortcut.getAttribute('data-url');
                                if (url) window.location.href = url;
                            }
                        });

                        function addShortcut() {
                            const name = shortcutName.value.trim();
                            const url = shortcutUrl.value.trim();
                            const icon = shortcutIcon.value.trim() || 'https://www.google.com/favicon.ico';
                            if (name && url) {
                                const shortcut = document.createElement('div');
                                shortcut.className = 'shortcut';
                                shortcut.setAttribute('data-url', url);
                                shortcut.innerHTML = `<img src="${icon}" alt="${name}" loading="lazy"><p>${name}</p>`;
                                shortcutsContainer.appendChild(shortcut);
                                shortcutName.value = '';
                                shortcutUrl.value = '';
                                shortcutIcon.value = '';
                            }
                        }

                        customizeBtn.addEventListener('click', function() {
                            customizeMenu.style.display = 'block';
                        });

                        function closeCustomization() {
                            customizeMenu.style.display = 'none';
                        }

                        function applyTheme(themeName) {
                            const theme = themes[themeName] || themes['default'];
                            document.body.style.backgroundColor = theme.bg;
                            document.body.style.color = theme.text;
                            document.querySelector('.logo path:nth-child(2)').setAttribute('stroke', theme.logoStroke);
                            searchBar.style.backgroundColor = darkModeCheckbox.checked ? '#303134' : '#FFFFFF';
                            searchBar.style.color = theme.text;
                            searchBar.style.borderColor = darkModeCheckbox.checked ? '#5f6368' : '#dfe1e5';
                            document.querySelectorAll('.shortcut').forEach(s => {
                                s.style.backgroundColor = darkModeCheckbox.checked ? '#303134' : '#FFFFFF';
                            });
                            document.querySelector('.title').style.color = theme.text;
                        }

                        function updateCustomization() {
                            const darkMode = darkModeCheckbox.checked;
                            const bgColor = bgColorInput.value;
                            document.body.style.backgroundColor = bgColor;
                            document.body.style.color = darkMode ? '#e8eaed' : '#202124';
                            searchBar.style.backgroundColor = darkMode ? '#303134' : '#FFFFFF';
                            searchBar.style.color = darkMode ? '#e8eaed' : '#202124';
                            searchBar.style.borderColor = darkMode ? '#5f6368' : '#dfe1e5';
                            document.querySelectorAll('.shortcut').forEach(s => {
                                s.style.backgroundColor = darkMode ? '#303134' : '#FFFFFF';
                            });
                            document.querySelector('.title').style.color = darkMode ? '#e8eaed' : '#202124';
                            document.querySelector('.logo path:nth-child(2)').setAttribute('stroke', darkMode ? '#e8eaed' : '#666');
                        }

                        updateCustomization();
                        darkModeCheckbox.addEventListener('change', updateCustomization);
                        bgColorInput.addEventListener('input', updateCustomization);
                        themeSelect.addEventListener('change', () => applyTheme(themeSelect.value));
                    </script>
                </body>
                </html>
                """
        }
    
    var offlineHTML: String {
        let lastURLMessage = lastFailedURL != nil ? "Impossible de se connecter à <strong>\(lastFailedURL!)</strong>." : "Impossible de charger la page."
        let errorMessage = lastNetworkError != nil ? "<br>Erreur : \(lastNetworkError!.localizedDescription)" : ""
        let errorCode = lastNetworkError != nil ? (lastNetworkError! as NSError).code : nil
        let errorCodeMessage = errorCode != nil ? "<br>Code d'erreur : \(errorCode!)" : ""
        var errorSuggestion = errorCode == NSURLErrorNotConnectedToInternet ? "<br><strong>Suggestion :</strong> Vérifiez votre Wi-Fi ou données mobiles." : ""
        let escapedLastURL = lastFailedURL?.replacingOccurrences(of: "'", with: "\\'") ?? ""
        
        
        return """
        <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Pas de connexion - Xplorer</title>
                    <style>
                        body {
                            margin: 0;
                            padding: 20px;
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; /* Police moderne */
                            background-color: \(isDarkMode ? "#1e1e1e" : "#f9f9f9"); /* Gris foncé ou très clair */
                            color: \(isDarkMode ? "#d4d4d4" : "#333");
                            height: 100vh;
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            text-align: center;
                            overflow: hidden;
                            transition: background-color 0.3s, color 0.3s; /* Transition douce pour le mode sombre */
                        }
                        .container {
                            max-width: 600px;
                            width: 90%;
                            padding: 30px; /* Augmentation du padding */
                            box-sizing: border-box;
                            background-color: \(isDarkMode ? "#252526" : "#fff"); /* Fond plus clair en mode clair */
                            border-radius: 12px; /* Bords plus arrondis */
                            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1); /* Ombre plus douce */
                        }
                        .icon {
                            width: 70px;
                            height: 70px;
                            margin-bottom: 25px;
                            animation: pulse 2s infinite;
                            fill: none;
                            stroke: \(isDarkMode ? "#d4d4d4" : "#6c757d"); /* Gris plus moderne pour l'icône */
                            stroke-width: 2;
                        }
                        .icon path[stroke="red"] {
                            stroke: #dc3545; /* Rouge alerte modernisé */
                            stroke-width: 3;
                        }
                        @keyframes pulse {
                            0% { transform: scale(1); opacity: 0.8; }
                            50% { transform: scale(1.05); opacity: 1; }
                            100% { transform: scale(1); opacity: 0.8; }
                        }
                        .title {
                            font-size: 32px; /* Titre plus grand */
                            font-weight: 600; /* Poids de police plus moderne */
                            color: #dc3545; /* Couleur d'alerte modernisée */
                            margin-bottom: 20px;
                            letter-spacing: 0.5px;
                            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2); /* Ombre plus subtile */
                        }
                        .message {
                            font-size: 18px; /* Message légèrement plus grand */
                            color: \(isDarkMode ? "#acb1b8" : "#555"); /* Gris plus doux */
                            margin-bottom: 25px;
                            line-height: 1.6; /* Meilleure lisibilité */
                        }
                        .message strong {
                            font-weight: 700;
                            color: \(isDarkMode ? "#fff" : "#333");
                        }
                        .suggestions {
                            text-align: left;
                            font-size: 15px;
                            color: \(isDarkMode ? "#acb1b8" : "#6c757d"); /* Gris plus doux */
                            margin-bottom: 30px;
                            padding: 15px 25px;
                            background-color: \(isDarkMode ? "#3a3a3b" : "#f0f0f0"); /* Fond plus discret */
                            border-radius: 8px;
                            border: 1px solid \(isDarkMode ? "#444" : "#eee"); /* Bordure légère */
                        }
                        .suggestions li {
                            margin: 12px 0;
                            list-style-type: disc; /* Puces plus discrètes */
                            margin-left: 20px;
                        }
                        .actions {
                            display: flex;
                            gap: 15px;
                            justify-content: center;
                            flex-wrap: wrap;
                            margin-bottom: 20px;
                        }
                        .retry-button, .home-button, .game-button {
                            padding: 12px 28px;
                            font-size: 16px;
                            border-radius: 6px; /* Bords légèrement plus arrondis */
                            cursor: pointer;
                            transition: background-color 0.2s, color 0.2s, box-shadow 0.2s; /* Transitions plus complètes */
                            border: none;
                            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05); /* Ombre légère au repos */
                        }
                        .retry-button {
                            color: white;
                            background-color: #007bff; /* Bleu moderne */
                        }
                        .retry-button:hover {
                            background-color: #0056b3; /* Bleu plus foncé au survol */
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Ombre au survol */
                        }
                        .home-button {
                            color: #007bff;
                            background-color: transparent;
                            border: 1px solid #007bff;
                        }
                        .home-button:hover {
                            background-color: rgba(0, 123, 255, 0.1);
                        }
                        .game-button {
                            color: \(isDarkMode ? "#d4d4d4" : "#495057"); /* Gris bleuté */
                            background-color: \(isDarkMode ? "#3a3a3b" : "#e9ecef"); /* Gris clair */
                        }
                        .game-button:hover {
                            background-color: \(isDarkMode ? "#4a4b4c" : "#dee2e6"); /* Légèrement plus foncé/clair au survol */
                        }
                        .countdown {
                            margin-top: 15px;
                            font-size: 15px;
                            color: \(isDarkMode ? "#acb1b8" : "#6c757d"); /* Gris plus doux */
                        }
                        .game-container {
                            display: none;
                            position: relative;
                            width: 100%;
                            max-width: 600px;
                            height: 200px;
                            background-color: \(isDarkMode ? "#252526" : "#fff"); /* Fond plus clair en mode clair */
                            border-radius: 12px;
                            overflow: hidden;
                            margin-top: 25px;
                            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.08); /* Ombre légère */
                        }
                        #gameCanvas {
                            width: 100%;
                            height: 100%;
                        }
                        @media (max-width: 400px) {
                            .title { font-size: 26px; }
                            .message { font-size: 15px; }
                            .suggestions { font-size: 13px; padding: 10px 15px; }
                            .retry-button, .home-button, .game-button { padding: 10px 22px; font-size: 14px; }
                            .game-container { height: 150px; }
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <svg class="icon" viewBox="0 0 24 24">
                            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                            <path d="M3 3l18 18" stroke="red" stroke-width="3"/>
                        </svg>
                        <div class="title">Hmm... nous n'arrivons pas à accéder à la page</div>
                        <div class="message">
                            \(lastURLMessage) \(errorMessage) \(errorCodeMessage) \(errorSuggestion)
                        </div>
                        <ul class="suggestions">
                            <li>Vérifiez votre câble réseau ou votre connexion Wi-Fi.</li>
                            <li>Assurez-vous que l’adresse est correcte.</li>
                            <li>Essayez d’actualiser la page quand la connexion sera rétablie.</li>
                        </ul>
                        <div class="actions">
                            <button class="retry-button" onclick="retryConnection()">Réessayer</button>
                            <button class="home-button" onclick="window.webkit.messageHandlers.homeHandler.postMessage('')">Page d'accueil</button>
                            <button class="game-button" onclick="startGame()">Jouer au Dino</button>
                        </div>
                        <div class="countdown" id="countdown">Tentative possible dans <span id="timer">5</span>s</div>
                        <div class="game-container" id="gameContainer">
                            <canvas id="gameCanvas"></canvas>
                        </div>
                    </div>
                    <script>
                        // Compte à rebours (sans réactualisation automatique)
                        let timeLeft = 5;
                        const timerElement = document.getElementById('timer');
                        const countdown = setInterval(() => {
                            timeLeft--;
                            timerElement.textContent = timeLeft;
                            if (timeLeft <= 0) {
                                clearInterval(countdown);
                                document.getElementById('countdown').textContent = 'Vous pouvez réessayer maintenant.';
                            }
                        }, 1000);

                        function retryConnection() {
                            window.webkit.messageHandlers.retryHandler.postMessage('\(escapedLastURL)');
                        }

                        // Mini-jeu Dino
                        let gameActive = false;
                        const gameContainer = document.getElementById('gameContainer');
                        const canvas = document.getElementById('gameCanvas');
                        const ctx = canvas.getContext('2d');
                        let dinoY = 150;
                        let velocity = 0;
                        let gravity = 0.8;
                        let obstacles = [];
                        let score = 0;
                        let gameSpeed = 5;

                        function startGame() {
                            if (!gameActive) {
                                gameContainer.style.display = 'block';
                                gameActive = true;
                                canvas.width = gameContainer.offsetWidth;
                                canvas.height = 200; // Hauteur fixe pour le jeu
                                // Recalculer dinoY en fonction de la nouvelle hauteur du canvas si nécessaire
                                dinoY = canvas.height - 50; 
                                obstacles = [];
                                score = 0;
                                velocity = 0;
                                requestAnimationFrame(gameLoop);
                            }
                        }
                        
                        function jump() {
                            if (gameActive && dinoY >= canvas.height - 50) { // Vérifier si le dino est au sol
                                velocity = -15;
                            }
                        }

                        document.addEventListener('keydown', (e) => {
                            if (e.code === 'Space') {
                                jump();
                            }
                        });
                        
                        canvas.addEventListener('mousedown', jump);
                        canvas.addEventListener('touchstart', function(e) {
                            e.preventDefault(); // Empêche le comportement tactile par défaut (zoom, défilement)
                            jump();
                        });

                        function spawnObstacle() {
                            const obstacleHeight = Math.random() * 50 + 20;
                            obstacles.push({
                                x: canvas.width,
                                y: canvas.height - obstacleHeight, // Positionné sur le sol
                                width: 20,
                                height: obstacleHeight
                            });
                        }

                        function gameLoop() {
                            if (!gameActive) return;

                            ctx.clearRect(0, 0, canvas.width, canvas.height);

                            // Physique du Dino
                            velocity += gravity;
                            dinoY += velocity;

                            // Empêcher le dino de passer à travers le sol
                            if (dinoY > canvas.height - 50) {
                                dinoY = canvas.height - 50;
                                velocity = 0;
                            }
                            
                            // Dessin du sol
                            ctx.fillStyle = '\(isDarkMode ? "#4a4b4c" : "#ddd")';
                            ctx.fillRect(0, canvas.height - 50, canvas.width, 50);

                            // Dessin du Dino
                            ctx.fillStyle = '\(isDarkMode ? "#d4d4d4" : "#333")';
                            ctx.fillRect(50, dinoY, 20, 20); // Position Y ajustée pour dessiner le dino sur le sol

                            // Gestion des obstacles
                            if (Math.random() < 0.02 && obstacles.length < 3) { // Limiter le nombre d'obstacles
                                spawnObstacle();
                            }

                            ctx.fillStyle = '\(isDarkMode ? "#acb1b8" : "#6c757d")';
                            for (let i = obstacles.length - 1; i >= 0; i--) {
                                let obs = obstacles[i];
                                obs.x -= gameSpeed;
                                ctx.fillRect(obs.x, obs.y, obs.width, obs.height);

                                // Détection de collision
                                if (obs.x < 50 + 20 && obs.x + obs.width > 50 &&
                                    dinoY < obs.y + obs.height && dinoY + 20 > obs.y) {
                                    gameActive = false;
                                    alert('Game Over ! Score : ' + Math.floor(score / 10));
                                    gameContainer.style.display = 'none';
                                    return; // Arrêter la boucle de jeu
                                }

                                // Supprimer les obstacles hors de l'écran
                                if (obs.x + obs.width < 0) {
                                    obstacles.splice(i, 1);
                                }
                            }

                            // Score
                            score++;
                            ctx.fillStyle = '\(isDarkMode ? "#d4d4d4" : "#333")';
                            ctx.font = '16px "Segoe UI"';
                            ctx.fillText('Score: ' + Math.floor(score / 10), 10, 20);

                            requestAnimationFrame(gameLoop);
                        }
                    </script>
                </body>
                </html>
        """
    } 
    
    
     
    var welcomeHTML: String {
            return """
            <!DOCTYPE html>
            <html lang="fr">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Bienvenue dans Xplorer 2</title>
                <style>
                    :root {
                        --bg-gradient-light: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                        --bg-gradient-dark: linear-gradient(135deg, #1f2023 0%, #2b2e33 100%);
                        --card-bg: #ffffff;
                        --text-main: #202124;
                        --text-secondary: #5f6368;
                        --accent-color: #1a73e8;
                        --accent-hover: #1557b0;
                        --icon-color: #1a73e8;
                        --border-color: #dadce0;
                    }
                    
                    @media (prefers-color-scheme: dark) {
                        :root {
                            --card-bg: #303134;
                            --text-main: #e8eaed;
                            --text-secondary: #9aa0a6;
                            --accent-color: #8ab4f8;
                            --accent-hover: #aecbfa;
                            --icon-color: #8ab4f8;
                            --border-color: #5f6368;
                        }
                    }

                    body {
                        margin: 0;
                        padding: 0;
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background: \(isDarkMode ? "var(--bg-gradient-dark)" : "var(--bg-gradient-light)");
                        color: var(--text-main);
                        height: 100vh;
                        overflow: hidden;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                    }

                    .window {
                        background-color: var(--card-bg);
                        border-radius: 20px;
                        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
                        width: 90%;
                        max-width: 600px;
                        height: 80%;
                        max-height: 650px;
                        overflow: hidden;
                        display: flex;
                        flex-direction: column;
                        position: relative;
                    }

                    .slider {
                        width: 100%;
                        height: 100%;
                        position: relative;
                        overflow: hidden;
                        flex-grow: 1;
                    }

                    .slides {
                        display: flex;
                        width: 700%; /* 7 slides = 700% */
                        height: 100%;
                        transition: transform 0.6s cubic-bezier(0.25, 1, 0.5, 1);
                    }

                    .slide {
                        width: 14.2857%; /* 100% / 7 */
                        height: 100%;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                        text-align: center;
                        padding: 40px;
                        box-sizing: border-box;
                    }

                    .slide h1 {
                        font-size: 28px;
                        margin-bottom: 15px;
                        font-weight: 700;
                        color: var(--text-main);
                    }

                    .slide p {
                        font-size: 16px;
                        line-height: 1.6;
                        color: var(--text-secondary);
                        margin-bottom: 25px;
                        max-width: 450px;
                    }

                    .slide ul {
                        text-align: left;
                        font-size: 15px;
                        color: var(--text-secondary);
                        line-height: 1.8;
                        padding-left: 20px;
                        margin-bottom: 30px;
                    }

                    .slide li strong {
                        color: var(--text-main);
                    }

                    .icon-container {
                        width: 90px;
                        height: 90px;
                        background-color: rgba(26, 115, 232, 0.1);
                        border-radius: 50%;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        margin-bottom: 25px;
                    }

                    .icon {
                        width: 50px;
                        height: 50px;
                        fill: none;
                        stroke: var(--icon-color);
                        stroke-width: 2;
                        stroke-linecap: round;
                        stroke-linejoin: round;
                    }

                    .nav-dots {
                        position: absolute;
                        bottom: 25px;
                        left: 0;
                        right: 0;
                        display: flex;
                        justify-content: center;
                        gap: 10px;
                        z-index: 10;
                    }

                    .dot {
                        width: 10px;
                        height: 10px;
                        background-color: var(--border-color);
                        border-radius: 50%;
                        cursor: pointer;
                        transition: all 0.3s ease;
                    }

                    .dot.active {
                        background-color: var(--accent-color);
                        transform: scale(1.3);
                    }

                    .btn-container {
                        margin-top: auto;
                        margin-bottom: 40px;
                        height: 50px;
                    }

                    button {
                        font-family: inherit;
                        padding: 12px 28px;
                        font-size: 16px;
                        font-weight: 600;
                        border-radius: 25px;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        border: none;
                    }

                    .next-btn, .accept-btn {
                        background-color: var(--accent-color);
                        color: #fff;
                        box-shadow: 0 4px 10px rgba(26, 115, 232, 0.3);
                    }

                    .next-btn:hover, .accept-btn:hover {
                        background-color: var(--accent-hover);
                        transform: translateY(-2px);
                    }

                    .next-btn:disabled {
                        background-color: var(--border-color);
                        cursor: not-allowed;
                        transform: none;
                        box-shadow: none;
                    }

                    .skip-btn {
                        position: absolute;
                        top: 20px;
                        right: 20px;
                        background-color: transparent;
                        color: var(--text-secondary);
                        font-size: 14px;
                        padding: 8px 15px;
                        z-index: 20;
                    }

                    .skip-btn:hover {
                        color: var(--text-main);
                        background-color: rgba(0,0,0,0.05);
                    }

                    /* Grille des moteurs de recherche */
                    .search-engine-options {
                        display: grid;
                        grid-template-columns: 1fr;
                        gap: 12px;
                        width: 100%;
                        max-width: 300px;
                        margin-bottom: 25px;
                    }

                    .search-option {
                        padding: 14px;
                        background-color: transparent;
                        border: 2px solid var(--border-color);
                        color: var(--text-main);
                        border-radius: 12px;
                        font-size: 16px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 10px;
                    }

                    .search-option.selected {
                        border-color: var(--accent-color);
                        background-color: rgba(26, 115, 232, 0.05);
                        color: var(--accent-color);
                    }

                    .terms-box {
                        background-color: rgba(0,0,0,0.03);
                        border: 1px solid var(--border-color);
                        border-radius: 10px;
                        padding: 15px;
                        font-size: 13px;
                        text-align: left;
                        height: 180px;
                        overflow-y: auto;
                        color: var(--text-secondary);
                        margin-bottom: 20px;
                        width: 100%;
                    }
                    
                    @media (prefers-color-scheme: dark) {
                        .terms-box { background-color: rgba(255,255,255,0.03); }
                    }
                </style>
            </head>
            <body>
                <div class="window">
                    <button class="skip-btn" onclick="goToSlide(totalSlides - 1)">Passer</button>
                    
                    <div class="slider">
                        <div class="slides" id="slides">
                            
                            <!-- Slide 1 : Accueil -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="11" r="3"/></svg>
                                </div>
                                <h1>Xplorer 2</h1>
                                <p>Bienvenue dans votre nouveau navigateur.<br>Conçu pour allier une vitesse fulgurante et une protection avancée de votre vie privée.</p>
                                <div class="btn-container"><button class="next-btn" onclick="nextSlide()">Découvrir</button></div>
                            </div>

                            <!-- Slide 2 : Anti-Fingerprinting -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/><line x1="2" y1="2" x2="22" y2="22" stroke="currentColor" stroke-width="2"/></svg>
                                </div>
                                <h1>Navigation Fantôme</h1>
                                <p>Les traqueurs ne vous voient plus. Xplorer génère une empreinte numérique aléatoire (Randomized Fingerprint) à chaque lancement.</p>
                                <ul>
                                    <li><strong>Bruit Canvas & Audio</strong> : Impossible à pister.</li>
                                    <li><strong>User-Agent Purifié</strong> : Identité standardisée.</li>
                                </ul>
                                <div class="btn-container"><button class="next-btn" onclick="nextSlide()">Suivant</button></div>
                            </div>

                            <!-- Slide 3 : Sécurité Active (HTTPS + Phishing) -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                </div>
                                <h1>Bouclier Actif</h1>
                                <p>Votre sécurité n'est plus une option. Xplorer intercepte et bloque les menaces avant qu'elles ne s'affichent.</p>
                                <ul>
                                    <li><strong>Base Anti-Phishing</strong> : Analyse locale en temps réel.</li>
                                    <li><strong>Smart HTTPS</strong> : Mise à niveau de sécurité automatique.</li>
                                </ul>
                                <div class="btn-container"><button class="next-btn" onclick="nextSlide()">Suivant</button></div>
                            </div>

                            <!-- Slide 4 : Cloudflare DNS -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                                </div>
                                <h1>DNS Chiffré (DoH)</h1>
                                <p>Votre fournisseur d'accès ne peut plus espionner vos recherches grâce au tunnel sécurisé Cloudflare 1.1.1.1.</p>
                                <ul>
                                    <li><strong>Résolution Chiffrée</strong> : Navigation 100% privée.</li>
                                    <li><strong>Audit IP</strong> : Vérifiez les adresses dans le menu de sécurité.</li>
                                </ul>
                                <div class="btn-container"><button class="next-btn" onclick="nextSlide()">Suivant</button></div>
                            </div>

                            <!-- Slide 5 : DevTools -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                </div>
                                <h1>Outils Professionnels</h1>
                                <p>Pour les passionnés et les développeurs. Inspectez le web directement depuis votre iPad.</p>
                                <ul>
                                    <li><strong>Console JS</strong> : Exécutez et lisez les logs en direct.</li>
                                    <li><strong>Interception Réseau</strong> : Analysez les requêtes XHR/Fetch.</li>
                                </ul>
                                <div class="btn-container"><button class="next-btn" onclick="nextSlide()">Suivant</button></div>
                            </div>

                            <!-- Slide 6 : Moteur de recherche -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                </div>
                                <h1>Votre Moteur</h1>
                                <p>Choisissez l'outil qui vous accompagnera dans vos recherches web.</p>
                                
                                <div class="search-engine-options">
                                    <button class="search-option" data-engine="google" onclick="selectEngine('google')">Google</button>
                                    <button class="search-option" data-engine="bing" onclick="selectEngine('bing')">Bing</button>
                                    <button class="search-option" data-engine="duckduckgo" onclick="selectEngine('duckduckgo')">DuckDuckGo</button>
                                </div>
                                
                                <div class="btn-container">
                                    <button class="next-btn" id="finishBtn" onclick="nextSlide()" disabled>Continuer</button>
                                </div>
                            </div>

                            <!-- Slide 7 : Conditions et Démarrage -->
                            <div class="slide">
                                <div class="icon-container">
                                    <svg class="icon" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                                </div>
                                <h1>Prêt à explorer</h1>
                                
                                <div class="terms-box">
                                    <strong>1. Confidentialité Totale</strong><br>
                                    Xplorer ne collecte, ne stocke et ne revend aucune de vos données personnelles. Tout est traité localement sur votre appareil.<br><br>
                                    <strong>2. Responsabilité</strong><br>
                                    Le navigateur fournit des outils de sécurité avancés (Anti-Phishing, Smart HTTPS). Toutefois, la vigilance humaine reste la meilleure défense. Ne saisissez jamais vos informations sur un site signalé comme dangereux.<br><br>
                                    <strong>3. Outils de Développement</strong><br>
                                    L'utilisation de la console JS et des outils réseau est réservée à un usage personnel et éducatif.
                                </div>
                                
                                <div class="btn-container">
                                    <button class="accept-btn" onclick="finishSetup()">J'accepte et je démarre</button>
                                </div>
                            </div>

                        </div>
                    </div>
                    
                    <div class="nav-dots" id="dots-container">
                        <!-- Les points sont générés par le Javascript -->
                    </div>
                </div>

                <script>
                    const totalSlides = 7;
                    let currentSlide = 0;
                    let selectedEngine = null;
                    
                    const slides = document.getElementById('slides');
                    const dotsContainer = document.getElementById('dots-container');
                    const finishBtn = document.getElementById('finishBtn');

                    // 1. Génération automatique des points de navigation
                    for(let i = 0; i < totalSlides; i++) {
                        let dot = document.createElement('div');
                        dot.className = i === 0 ? 'dot active' : 'dot';
                        dot.onclick = () => goToSlide(i);
                        dotsContainer.appendChild(dot);
                    }
                    const dots = document.querySelectorAll('.dot');

                    // 2. Mise à jour de l'affichage
                    function updateSlide() {
                        const translateValue = -currentSlide * (100 / totalSlides);
                        slides.style.transform = `translateX(${translateValue}%)`;
                        
                        dots.forEach((dot, index) => {
                            dot.className = index === currentSlide ? 'dot active' : 'dot';
                        });

                        // Cacher le bouton Passer sur la dernière slide
                        const skipBtn = document.querySelector('.skip-btn');
                        if (skipBtn) {
                            skipBtn.style.display = currentSlide === totalSlides - 1 ? 'none' : 'block';
                        }
                    }

                    function nextSlide() {
                        if (currentSlide < totalSlides - 1) {
                            currentSlide++;
                            updateSlide();
                        }
                    }

                    function goToSlide(index) {
                        if (index >= 0 && index < totalSlides) {
                            currentSlide = index;
                            updateSlide();
                        }
                    }

                    // 3. Gestion de la sélection du moteur (Slide 6)
                    function selectEngine(engine) {
                        selectedEngine = engine;
                        document.querySelectorAll('.search-option').forEach(btn => {
                            if (btn.dataset.engine === engine) {
                                btn.classList.add('selected');
                            } else {
                                btn.classList.remove('selected');
                            }
                        });
                        
                        // Activer le bouton Continuer
                        if (finishBtn) finishBtn.disabled = false;
                    }

                    // 4. Terminer et envoyer au code Swift (Slide 7)
                    function finishSetup() {
                        let engineToUse = selectedEngine ? selectedEngine : 'google';
                        // Communication INTACTE avec ton code Swift
                        window.webkit.messageHandlers.engineHandler.postMessage(engineToUse);
                    }

                    updateSlide();
                </script>
            </body>
            </html>
            """
        }
    
    // MARK: - Initialisation
    override init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: Bundle?) {
        webView = WKWebView(frame: .zero, configuration: webConfiguration)
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
        setupMessageHandlers()
        webConfiguration.userContentController.add(self, name: "homeHandler")
        privateWebConfiguration.userContentController.add(self, name: "homeHandler")
        
    }
    
    required init?(coder: NSCoder) {
        webView = WKWebView(frame: .zero, configuration: webConfiguration)
        super.init(coder: coder)
        setupMessageHandlers()
    }
    
    private func setupMessageHandlers() {
        webConfiguration.userContentController.add(self, name: "retryHandler")
        webConfiguration.userContentController.add(self, name: "engineHandler")
        webConfiguration.userContentController.add(self, name: "customizeHandler")
        webConfiguration.userContentController.add(self, name: "fetchBridge")
        privateWebConfiguration.userContentController.add(self, name: "retryHandler")
        privateWebConfiguration.userContentController.add(self, name: "engineHandler")
        privateWebConfiguration.userContentController.add(self, name: "customizeHandler")
        privateWebConfiguration.userContentController.add(self, name: "fetchBridge")
    }
    
    // MARK: - Lifecycle
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        PhishingManager.shared.downloadRealList()
        setupConstraints()
        setupNetworkMonitoring()
        setupGestures()
        addressBar.delegate = self
        webView.uiDelegate = self
        webView.navigationDelegate = self
        webView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
        webView.addObserver(self, forKeyPath: #keyPath(WKWebView.isLoading), options: .new, context: nil)
        tabs.append(webView)
        webView.addObserver(self, forKeyPath: #keyPath(WKWebView.canGoBack), options: .new, context: nil)
            webView.addObserver(self, forKeyPath: #keyPath(WKWebView.canGoForward), options: .new, context: nil)
        
        let isFirstLaunch = !UserDefaults.standard.bool(forKey: "hasLaunchedBefore")
        if isFirstLaunch || !UserDefaults.standard.bool(forKey: "welcomeCompleted") {
            tabs[currentTabIndex].loadHTMLString(welcomeHTML, baseURL: nil)
            UserDefaults.standard.set(true, forKey: "hasLaunchedBefore")
        } else {
            loadNewTabPage()
        }
        
        setupSecurityIcon()
        updateTabBar()
        
        // Setup suggestion view
        suggestionTableView.dataSource = self
        suggestionTableView.delegate = self
        suggestionView.addSubview(suggestionTableView)
        view.addSubview(suggestionView)
        setupSuggestionConstraints()
        // Lancer la compilation du bloqueur de pubs en arrière-plan
            AdBlockManager.shared.compileRules { [weak self] ruleList in
                guard let self = self, let ruleList = ruleList else { return }
                
                // Appliquer le bloqueur aux onglets DÉJÀ ouverts
                DispatchQueue.main.async {
                    for tab in self.tabs {
                        tab.configuration.userContentController.add(ruleList)
                    }
                    // Optionnel : Recharger l'onglet actif pour appliquer le blocage tout de suite
                    // self.tabs[self.currentTabIndex].reload()
                }
            }
        
        
    }
    
    deinit {
        for tab in tabs {
            cleanupWebView(tab)
        }
        networkMonitor.cancel()
        webConfiguration.userContentController.removeAllScriptMessageHandlers()
        privateWebConfiguration.userContentController.removeAllScriptMessageHandlers()
        URLSession.shared.getAllTasks { tasks in tasks.forEach { $0.cancel() } }
    }
    
    // MARK: - Setup UI
    func setupUI() {
        view.backgroundColor = isPrivateMode ? .gray : customBackgroundColor
        addressBar.placeholder = "Rechercher avec \(currentSearchEngine.capitalized) ou entrer une URL"
        addressBar.borderStyle = .roundedRect
        addressBar.autocapitalizationType = .none
        addressBar.autocorrectionType = .no
        addressBar.keyboardType = .URL
        addressBar.clearButtonMode = .whileEditing
        addressBar.layer.cornerRadius = 8
        addressBar.delegate = self
        view.addSubview(addressBar)
        
        goButton.setImage(UIImage(systemName: "arrow.right.circle"), for: .normal)
        goButton.addTarget(self, action: #selector(loadWebsite), for: .touchUpInside)
        goButton.accessibilityLabel = "Aller à la page"
        view.addSubview(goButton)
        
        backButton.setImage(UIImage(systemName: "arrow.left"), for: .normal)
        backButton.addTarget(self, action: #selector(goBack), for: .touchUpInside)
        backButton.accessibilityLabel = "Retour"
        view.addSubview(backButton)
        
        forwardButton.setImage(UIImage(systemName: "arrow.right"), for: .normal)
        forwardButton.addTarget(self, action: #selector(goForward), for: .touchUpInside)
        forwardButton.accessibilityLabel = "Avancer"
        view.addSubview(forwardButton)
        
        refreshButton.setImage(UIImage(systemName: "arrow.clockwise"), for: .normal)
        refreshButton.tintColor = .systemBlue
        refreshButton.addTarget(self, action: #selector(refresh), for: .touchUpInside)
        refreshButton.accessibilityLabel = "Actualiser"
        view.addSubview(refreshButton)
        
        menuButton.setImage(UIImage(systemName: "ellipsis"), for: .normal)
        menuButton.menu = createMenu()
        menuButton.showsMenuAsPrimaryAction = true
        menuButton.accessibilityLabel = "Menu"
        view.addSubview(menuButton)
        
        progressBar.progressTintColor = .blue
        progressBar.alpha = 0
        view.addSubview(progressBar)
        
        tabBar.showsHorizontalScrollIndicator = false
        view.addSubview(tabBar)
        
        securityIcon.contentMode = .scaleAspectFit
        view.addSubview(securityIcon)
        view.addSubview(webView)
    }
    
    func setupConstraints() {
        [addressBar, goButton, webView, backButton, forwardButton, refreshButton, menuButton, progressBar, tabBar, securityIcon].forEach { $0.translatesAutoresizingMaskIntoConstraints = false }
        
        NSLayoutConstraint.activate([
            tabBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 5),
            tabBar.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 5),
            tabBar.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -5),
            tabBar.heightAnchor.constraint(equalToConstant: 40),
            
            backButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 10),
            backButton.centerYAnchor.constraint(equalTo: addressBar.centerYAnchor),
            backButton.widthAnchor.constraint(equalToConstant: 40),
            
            forwardButton.leadingAnchor.constraint(equalTo: backButton.trailingAnchor, constant: 5),
            forwardButton.centerYAnchor.constraint(equalTo: addressBar.centerYAnchor),
            forwardButton.widthAnchor.constraint(equalToConstant: 40),
            
            refreshButton.leadingAnchor.constraint(equalTo: forwardButton.trailingAnchor, constant: 5),
            refreshButton.centerYAnchor.constraint(equalTo: addressBar.centerYAnchor),
            refreshButton.widthAnchor.constraint(equalToConstant: 40),
            
            securityIcon.leadingAnchor.constraint(equalTo: refreshButton.trailingAnchor, constant: 10),
            securityIcon.centerYAnchor.constraint(equalTo: addressBar.centerYAnchor),
            securityIcon.widthAnchor.constraint(equalToConstant: 20),
            securityIcon.heightAnchor.constraint(equalToConstant: 20),
            
            addressBar.topAnchor.constraint(equalTo: tabBar.bottomAnchor, constant: 10),
            addressBar.leadingAnchor.constraint(equalTo: securityIcon.trailingAnchor, constant: 10),
            addressBar.trailingAnchor.constraint(equalTo: menuButton.leadingAnchor, constant: -10),
            addressBar.heightAnchor.constraint(equalToConstant: 40),
            
            menuButton.trailingAnchor.constraint(equalTo: goButton.leadingAnchor, constant: -10),
            menuButton.centerYAnchor.constraint(equalTo: addressBar.centerYAnchor),
            menuButton.widthAnchor.constraint(equalToConstant: 40),
            
            goButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -10),
            goButton.centerYAnchor.constraint(equalTo: addressBar.centerYAnchor),
            goButton.widthAnchor.constraint(equalToConstant: 40),
            
            progressBar.topAnchor.constraint(equalTo: addressBar.bottomAnchor, constant: 2),
            progressBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            progressBar.heightAnchor.constraint(equalToConstant: 2),
            
            webView.topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 10),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }
    
    func setupSuggestionConstraints() {
        suggestionView.translatesAutoresizingMaskIntoConstraints = false
        suggestionTableView.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            suggestionView.topAnchor.constraint(equalTo: addressBar.bottomAnchor, constant: 5),
            suggestionView.leadingAnchor.constraint(equalTo: addressBar.leadingAnchor),
            suggestionView.trailingAnchor.constraint(equalTo: addressBar.trailingAnchor),
            suggestionView.heightAnchor.constraint(lessThanOrEqualToConstant: 150),
            
            suggestionTableView.topAnchor.constraint(equalTo: suggestionView.topAnchor, constant: 5),
            suggestionTableView.leadingAnchor.constraint(equalTo: suggestionView.leadingAnchor, constant: 5),
            suggestionTableView.trailingAnchor.constraint(equalTo: suggestionView.trailingAnchor, constant: -5),
            suggestionTableView.bottomAnchor.constraint(equalTo: suggestionView.bottomAnchor, constant: -5)
        ])
    }
    
    // MARK: - Gestion réseau
    func setupNetworkMonitoring() {
        networkMonitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.isNetworkAvailable = path.status == .satisfied
                if !self.isNetworkAvailable {
                    self.lastFailedURL = self.tabs[self.currentTabIndex].url?.absoluteString
                    self.lastNetworkError = NSError(domain: "Network", code: -1, userInfo: [NSLocalizedDescriptionKey: "Connexion Internet perdue"])
                    self.loadOfflinePage()
                } else if let url = self.lastFailedURL {
                    self.loadURL(url)
                    self.lastFailedURL = nil
                    self.lastNetworkError = nil
                }
            }
        }
        networkMonitor.start(queue: DispatchQueue.global(qos: .background))
    }
    
    // MARK: - Gestes Multi-Touch
    func setupGestures() {
        let swipeLeft = UISwipeGestureRecognizer(target: self, action: #selector(goForward))
        swipeLeft.direction = .left
        swipeLeft.numberOfTouchesRequired = 2
        view.addGestureRecognizer(swipeLeft)
        
        let swipeRight = UISwipeGestureRecognizer(target: self, action: #selector(goBack))
        swipeRight.direction = .right
        swipeRight.numberOfTouchesRequired = 2
        view.addGestureRecognizer(swipeRight)
        
        let swipeUp = UISwipeGestureRecognizer(target: self, action: #selector(exitFullScreen))
        swipeUp.direction = .up
        view.addGestureRecognizer(swipeUp)
        
    }
    
    // MARK: - WKScriptMessageHandler
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {

        if message.name == "retryHandler", let msg = message.body as? String {
            
            //RÉCEPTION DES ORDRES DE BYPASS SÉCURISÉS
            if msg.hasPrefix("bypass-http:") {
                let urlString = String(msg.dropFirst("bypass-http:".count))
                if let url = URL(string: urlString), let host = url.host {
                    self.bypassedHTTPHosts.insert(host) // Autorisation HTTP
                    self.loadURL(urlString)
                }
            } 
                         //BYPASS DU FILTRE ADBLOCK 
                        else if msg.hasPrefix("bypass-filter:") {
                            let urlString = String(msg.dropFirst("bypass-filter:".count))
                            if let url = URL(string: urlString) {
                                // On supprime temporairement les règles AdBlock de CET onglet spécifique
                                if let ruleList = AdBlockManager.shared.compiledRuleList {
                                    self.tabs[self.currentTabIndex].configuration.userContentController.remove(ruleList)
                                }
                                print("🔓 Filtre désactivé pour l'onglet actuel. Rechargement de \(url.host ?? "")")
                                self.loadURL(urlString)
                            }
                        }
            else if msg.hasPrefix("bypass-ssl:") {
                let urlString = String(msg.dropFirst("bypass-ssl:".count))
                if let url = URL(string: urlString), let host = url.host {
                    var currentSet = self.bypassedSSLHosts
                                        currentSet.insert(host)
                                        self.bypassedSSLHosts = currentSet // Sauvegarde sur disque
                    self.bypassedSSLHosts.insert(host) // Autorisation SSL
                    self.loadURL(urlString)
                    self.updateSecurityIcon(url: url) // <--- Force l'icône noire immédiatement
                }
            }
            else if msg.hasPrefix("bypass-phishing:") {
                let urlString = String(msg.dropFirst("bypass-phishing:".count))
                if let url = URL(string: urlString), let host = url.host {
                    self.bypassedPhishingHosts.insert(host) // Autorisation Phishing
                    self.loadURL(urlString)
                }
            } 
            else if !msg.isEmpty {
                // Bouton "Réessayer" classique (hors-ligne)
                if isNetworkAvailable { loadURL(msg) } else { loadOfflinePage() }
            }
            
        } 
        else if message.name == "engineHandler", let engine = message.body as? String {
            currentSearchEngine = engine
            addressBar.placeholder = "Rechercher avec \(engine.capitalized) ou entrer une URL"
            UserDefaults.standard.set(true, forKey: "welcomeCompleted")
            loadNewTabPage()
        } 
        else if message.name == "customizeHandler", let dict = message.body as? [String: Any] {
            if let darkMode = dict["darkMode"] as? Bool {
                isDarkMode = darkMode
                view.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
                suggestionView.backgroundColor = isDarkMode ? .darkGray : .white
                suggestionTableView.reloadData()
            }
            if let bgColorHex = dict["bgColor"] as? String, let color = UIColor(hex: bgColorHex) {
                customBackgroundColor = color
                view.backgroundColor = isPrivateMode ? .lightGray : color
            }
            loadNewTabPage()
        } 
        else if message.name == "homeHandler" {
            loadNewTabPage()
        }
        else if message.name == "fetchBridge", let dict = message.body as? [String: Any],
                        let urlString = dict["url"] as? String,
                        let callbackId = dict["callbackId"] as? String,
                        let url = URL(string: urlString) {
                    
                    // 1. On prévient tes DevTools (côté Swift)
                    DispatchQueue.main.async {
                        self.devToolsView?.log("NATIVE REQ: \(urlString)", type: "network")
                    }
                    
                    URLSession.shared.dataTask(with: url) { data, response, error in
                        guard let data = data, error == nil else {
                            DispatchQueue.main.async {
                                self.devToolsView?.log("NATIVE ERR: \(error?.localizedDescription ?? "Inconnue")", type: "error")
                                message.webView?.evaluateJavaScript("if(window['\(callbackId)']) window['\(callbackId)']({error: true});")
                            }
                            return
                        }
                        
                        // 2. On encode en Base64 pour éviter que des guillemets ne fassent planter le JavaScript
                        let base64String = data.base64EncodedString()
                        
                        DispatchQueue.main.async {
                            self.devToolsView?.log("NATIVE RESP[200]: \(urlString)", type: "network")
                            
                            // 3. Le JS décode le Base64 (atob) et le parse en JSON proprement
                            let js = """
                            if(window['\(callbackId)']) {
                                try {
                                    // Decode Base64 en texte, puis Parse en JSON
                                    const jsonText = decodeURIComponent(escape(atob('\(base64String)')));
                                    const jsonData = JSON.parse(jsonText);
                                    window['\(callbackId)'](jsonData);
                                } catch(e) {
                                    console.error("Erreur de parsing JSON natif:", e);
                                    window['\(callbackId)']({error: true});
                                }
                            }
                            """
                            message.webView?.evaluateJavaScript(js)
                        }
                    }.resume()
                
        }
    }
    
    // MARK: - Menu Contextuel
    func createMenu() -> UIMenu {
        // 1. Crée l'action "Code Source"
            // L'icône "chevron.left.forwardslash.chevron.right" représente les balises < />
        let devToolsAction = UIAction(title: "Outils de développement", image: UIImage(systemName: "hammer.fill")) { _ in self.toggleDevTools() }
        // Ajoute-le au menu
        let readerModeAction = UIAction(title: "Readability", image: UIImage(systemName: "book.fill")) { _ in self.activateReaderMode() }
        let shareAction = UIAction(title: "Partager...", image: UIImage(systemName: "square.and.arrow.up")) { _ in 
            self.shareCurrentPage() 
        }
        let viewSource = UIAction(title: "Voir le code source", image: UIImage(systemName: "chevron.left.forwardslash.chevron.right")) { _ in 
                self.viewSourceCode() 
            }
        let newTab = UIAction(title: "Nouvel onglet", image: UIImage(systemName: "plus")) { _ in self.addNewTab() }
        let newPrivateTab = UIAction(title: "Nouvel onglet privé", image: UIImage(systemName: "eye.slash")) { _ in self.addPrivateTab() }
        let closeTab = UIAction(title: "Fermer l'onglet", image: UIImage(systemName: "xmark"), attributes: .destructive) { _ in self.closeCurrentTab() }
        let closeAllTabs = UIAction(title: "Fermer tous les onglets", image: UIImage(systemName: "xmark.circle"), attributes: .destructive) { _ in self.closeAllTabs() }
        let addBookmark = UIAction(title: "Ajouter aux favoris", image: UIImage(systemName: "star")) { _ in self.addToBookmarks() }
        let showBookmarks = UIAction(title: "Voir les favoris", image: UIImage(systemName: "star.fill")) { _ in self.showBookmarks() }
        let showHistory = UIAction(title: "Voir l'historique", image: UIImage(systemName: "clock")) { _ in self.showHistory() }
        let translate = UIAction(title: "Traduire la page", image: UIImage(systemName: "globe")) { _ in self.translatePage() }
        let find = UIAction(title: "Rechercher dans la page", image: UIImage(systemName: "magnifyingglass")) { _ in self.showFindInPage() }
        let settings = UIAction(title: "Réglages", image: UIImage(systemName: "gear")) { _ in self.showSettings() }
        let fullScreen = UIAction(title: isFullScreen ? "Quitter le plein écran" : "Plein écran", image: UIImage(systemName: isFullScreen ? "arrow.down.right.and.arrow.up.left" : "arrow.up.left.and.arrow.down.right")) { _ in self.toggleFullScreen() }
        
        return UIMenu(title: "Menu", children: [newTab, newPrivateTab, closeTab, closeAllTabs, readerModeAction, addBookmark, showBookmarks, showHistory, translate, find, settings, fullScreen,viewSource,shareAction,devToolsAction])
    }
    
    // MARK: - Actions
    // MARK: - Lecteur PDF Mozilla (Texte, Liens, Recherche & Formulaires)
    class PDFViewController: UIViewController {
        var pdfURL: URL?
        var isDarkMode: Bool = false
        var webView: WKWebView!
        
        override func viewDidLoad() {
            super.viewDidLoad()
            title = pdfURL?.lastPathComponent ?? "Document PDF"
            view.backgroundColor = isDarkMode ? .black : .white
            
            webView = WKWebView(frame: view.bounds)
            webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            webView.isOpaque = false
            webView.backgroundColor = .clear
            view.addSubview(webView)
            
            guard let url = pdfURL else { return }
            
            let html = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=3.0, user-scalable=yes">
                <!-- 1. Cœur de PDF.js -->
                <script src="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js"></script>
                <!-- 2. CSS Officiel pour que le texte, les liens et les FORMULAIRES s'alignent parfaitement -->
                <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/web/pdf_viewer.min.css">
                
                <style>
                    body { 
                        margin: 0; padding: 0; 
                        background-color: \(isDarkMode ? "#1a1a1a" : "#eeeeee"); 
                        font-family: -apple-system, sans-serif; 
                    }
                    #viewer-container { 
                        display: flex; flex-direction: column; align-items: center; padding: 20px; padding-top: 60px;
                    }
                    /* Conteneur de chaque page (Image + Texte + Annotations/Formulaires) */
                    .page-wrapper {
                        position: relative;
                        margin-bottom: 30px;
                        background-color: white;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.4);
                        border-radius: 4px;
                        overflow: hidden;
                    }
                    canvas { display: block; }
                    
                    /* Amélioration visuelle pour les champs de formulaire interactifs */
                    .annotationLayer input, 
                    .annotationLayer textarea, 
                    .annotationLayer select {
                        background-color: rgba(0, 122, 255, 0.1);
                        border: 1px solid rgba(0, 122, 255, 0.4);
                        border-radius: 2px;
                    }
                    .annotationLayer input:focus, 
                    .annotationLayer textarea:focus {
                        background-color: rgba(0, 122, 255, 0.2);
                        outline: none;
                    }

                    /* Barre de recherche flottante */
                    #search-bar {
                        position: fixed; top: -60px; left: 50%; transform: translateX(-50%);
                        background: \(isDarkMode ? "rgba(40,40,40,0.95)" : "rgba(255,255,255,0.95)");
                        padding: 10px 20px; border-radius: 30px;
                        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
                        display: flex; gap: 10px; align-items: center;
                        transition: top 0.3s ease; z-index: 1000;
                        backdrop-filter: blur(10px);
                    }
                    #search-input {
                        border: none; background: transparent; font-size: 16px; outline: none;
                        color: \(isDarkMode ? "white" : "black"); width: 200px;
                    }
                    #search-btn {
                        background: #007aff; color: white; border: none; padding: 6px 15px;
                        border-radius: 15px; font-weight: bold; cursor: pointer;
                    }
                    
                    /* Compteur de pages */
                    .page-info { 
                        position: fixed; bottom: 25px; right: 25px; 
                        background: \(isDarkMode ? "rgba(40,40,40,0.9)" : "rgba(255,255,255,0.9)");
                        color: \(isDarkMode ? "#eee" : "#222");
                        padding: 10px 18px; border-radius: 25px; font-size: 15px; font-weight: 600;
                        backdrop-filter: blur(15px); border: 1px solid rgba(128,128,128,0.3);
                        box-shadow: 0 4px 12px rgba(0,0,0,0.2); z-index: 100;
                    }
                    
                    /* Amélioration de la sélection iOS */
                    ::selection { background: rgba(0, 122, 255, 0.4); }
                </style>
            </head>
            <body>
                <!-- Barre de recherche -->
                <div id="search-bar">
                    <input type="text" id="search-input" placeholder="Rechercher dans le PDF..." onkeypress="if(event.key === 'Enter') searchNext();">
                    <button id="search-btn" onclick="searchNext()">Suivant</button>
                    <button id="close-btn" onclick="toggleSearch()" style="background:transparent; border:none; font-size:18px; color:gray;">✕</button>
                </div>

                <div id="viewer-container"></div>
                <div class="page-info" id="page-counter">Initialisation...</div>

                <script>
                    const url = '\(url.absoluteString)';
                    const pdfjsLib = window['pdfjs-dist/build/pdf'];
                    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';

                    let pdfDoc = null;
                    const container = document.getElementById('viewer-container');
                    const pixelRatio = window.devicePixelRatio || 1; 

                    // Chargement du document
                    pdfjsLib.getDocument(url).promise.then(pdf => {
                        pdfDoc = pdf;
                        document.getElementById('page-counter').textContent = '1 / ' + pdf.numPages;
                        for (let i = 1; i <= pdf.numPages; i++) { renderPage(i); }
                    }).catch(err => {
                        document.getElementById('page-counter').textContent = "Erreur de chargement";
                    });

                    function renderPage(num) {
                        pdfDoc.getPage(num).then(page => {
                            const viewport = page.getViewport({ scale: 1.5 });
                            
                            // 1. Conteneur principal de la page
                            const pageWrapper = document.createElement('div');
                            pageWrapper.className = 'page-wrapper';
                            pageWrapper.style.width = viewport.width + "px";
                            pageWrapper.style.height = viewport.height + "px";
                            container.appendChild(pageWrapper);

                            // 2. Couche Graphique (Canvas HD)
                            const canvas = document.createElement('canvas');
                            const ctx = canvas.getContext('2d');
                            canvas.height = viewport.height * pixelRatio;
                            canvas.width = viewport.width * pixelRatio;
                            canvas.style.width = "100%";
                            canvas.style.height = "100%";
                            ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
                            pageWrapper.appendChild(canvas);

                            // 3. Rendu de l'image
                            page.render({ canvasContext: ctx, viewport: viewport }).promise.then(() => {
                                
                                // 4. Couche de Texte (Pour sélection et recherche)
                                return page.getTextContent();
                            }).then(textContent => {
                                const textLayerDiv = document.createElement('div');
                                textLayerDiv.className = 'textLayer';
                                textLayerDiv.style.width = "100%";
                                textLayerDiv.style.height = "100%";
                                pageWrapper.appendChild(textLayerDiv);

                                pdfjsLib.renderTextLayer({
                                    textContent: textContent,
                                    container: textLayerDiv,
                                    viewport: viewport,
                                    textDivs:[]
                                });
                                
                                // 5. Couche d'Annotations (Pour les Liens cliquables ET les FORMULAIRES)
                                return page.getAnnotations();
                            }).then(annotations => {
                                if (annotations.length === 0) return;
                                const annotationLayerDiv = document.createElement('div');
                                annotationLayerDiv.className = 'annotationLayer';
                                annotationLayerDiv.style.width = "100%";
                                annotationLayerDiv.style.height = "100%";
                                pageWrapper.appendChild(annotationLayerDiv);

                                pdfjsLib.AnnotationLayer.render({
                                    viewport: viewport.clone({ dontFlip: true }),
                                    div: annotationLayerDiv,
                                    annotations: annotations,
                                    page: page,
                                    renderInteractiveForms: true, // 👈 LE DÉTAIL MAGIQUE QUI ACTIVE LES FORMULAIRES
                                    linkService: { getDestinationHash: (dest) => dest, getAnchorUrl: (url) => url },
                                    downloadManager: null
                                });
                            });
                        });
                    }

                    // Fonction de Recherche Native
                    function searchNext() {
                        const query = document.getElementById('search-input').value;
                        if (query) {
                            window.find(query, false, false, true, false, false, false);
                        }
                    }

                    // Afficher/Cacher la barre
                    function toggleSearch() {
                        const bar = document.getElementById('search-bar');
                        if (bar.style.top === '15px') {
                            bar.style.top = '-60px';
                            window.getSelection().removeAllRanges(); // Efface le surlignage
                        } else {
                            bar.style.top = '15px';
                            document.getElementById('search-input').focus();
                        }
                    }

                    // Détecter la page au scroll
                    window.onscroll = function() {
                        const scrollPos = window.scrollY + 300;
                        const wrappers = document.getElementsByClassName('page-wrapper');
                        for (let i = 0; i < wrappers.length; i++) {
                            if (wrappers[i].offsetTop < scrollPos && (wrappers[i].offsetTop + wrappers[i].offsetHeight) > scrollPos) {
                                document.getElementById('page-counter').textContent = (i + 1) + ' / ' + pdfDoc.numPages;
                                break;
                            }
                        }
                    };
                </script>
            </body>
            </html>
            """
            
            webView.loadHTMLString(html, baseURL: nil)
            
            // --- BOUTONS DE LA BARRE DE NAVIGATION ---
            
            // Bouton Fermer (Droite)
            let closeAction = UIAction { _ in self.dismiss(animated: true) }
            let closeBtn = UIBarButtonItem(title: "Fermer", primaryAction: closeAction)
            
            // Bouton Recherche (Loupe) (Droite)
            let searchBtn = UIBarButtonItem(systemItem: .search, primaryAction: UIAction { _ in
                self.webView.evaluateJavaScript("toggleSearch()")
            })
            navigationItem.rightBarButtonItems = [closeBtn, searchBtn]
            
            // Bouton Partager "Fichiers" (Gauche)
            let shareBtn = UIBarButtonItem(systemItem: .action, primaryAction: UIAction { _ in
                self.downloadAndShare(url: url)
            })
            navigationItem.leftBarButtonItem = shareBtn
        }
        
        // Fonction de téléchargement en arrière-plan pour le partage
        func downloadAndShare(url: URL) {
            let task = URLSession.shared.downloadTask(with: url) { localURL, _, _ in
                guard let tempURL = localURL else { return }
                let destURL = FileManager.default.temporaryDirectory.appendingPathComponent(url.lastPathComponent)
                try? FileManager.default.removeItem(at: destURL)
                try? FileManager.default.moveItem(at: tempURL, to: destURL)
                
                DispatchQueue.main.async {
                    let activity = UIActivityViewController(activityItems: [destURL], applicationActivities: nil)
                    if let popover = activity.popoverPresentationController { 
                        popover.barButtonItem = self.navigationItem.leftBarButtonItem 
                    }
                    self.present(activity, animated: true)
                }
            }
            task.resume()
        }
    }
     @objc func activateReaderMode() {
        // Fonction interne qui exécute Readability une fois le script disponible
        func executeReadability(script: String) {
            let js = """
            // 1. On injecte le script de Mozilla en toute sécurité
            var module = { exports: {} }; // Polyfill pour éviter les erreurs de module
            \(script)
            
            // 2. On exécute l'algorithme
            (function() {
                try {
                    // Readability a besoin d'un clone parfait du document pour ne rien casser
                    var documentClone = document.cloneNode(true);
                    
                    // On récupère la classe (selon comment le CDN l'a chargée)
                    var ReadabilityClass = typeof Readability !== 'undefined' ? Readability : module.exports;
                    
                    var reader = new ReadabilityClass(documentClone);
                    var article = reader.parse();
                    
                    if (article && article.content) {
                        return {
                            "title": article.title,
                            "content": article.content,
                            "excerpt": article.excerpt || ""
                        };
                    } else {
                        return null; // Pas assez de texte trouvé
                    }
                } catch (e) {
                    return { "error": e.toString() };
                }
            })();
            """
            
            tabs[currentTabIndex].evaluateJavaScript(js) { result, error in
                if let err = error {
                    self.showAlert(title: "Erreur", message: "Échec de l'injection : \(err.localizedDescription)")
                    return
                }
                
                guard let data = result as? [String: Any],
                      let title = data["title"] as? String,
                      let content = data["content"] as? String else {
                    self.showAlert(title: "Readability", message: "Impossible d'extraire un article lisible sur cette page avec Readability.")
                    return
                }
                
                // Succès ! On affiche le lecteur.
                let readerVC = ReaderViewController()
                readerVC.articleTitle = title
                readerVC.articleContent = content
                readerVC.isDarkMode = self.isDarkMode
                
                let navVC = UINavigationController(rootViewController: readerVC)
                navVC.modalPresentationStyle = .pageSheet
                self.present(navVC, animated: true)
            }
        }
        
        // --- LOGIQUE DE TÉLÉCHARGEMENT ---
        // 1. Si on a déjà téléchargé le script, on l'utilise instantanément
        if let cachedScript = readabilityScriptCache {
            executeReadability(script: cachedScript)
            return
        }
        
        // 2. Sinon, on le télécharge (1 seule fois par session)
        progressBar.alpha = 1
        progressBar.setProgress(0.5, animated: true)
        
        // URL officielle du CDN jsDelivr pour le script Mozilla
        guard let url = URL(string: "https://cdn.jsdelivr.net/npm/@mozilla/readability@0.5.0/Readability.min.js") else { return }
        
        URLSession.shared.dataTask(with: url) { data, response, error in
            DispatchQueue.main.async {
                self.progressBar.setProgress(1.0, animated: true)
                UIView.animate(withDuration: 0.3) { self.progressBar.alpha = 0 }
                
                if let data = data, let scriptString = String(data: data, encoding: .utf8) {
                    print("✅ Script Mozilla Readability téléchargé et mis en cache.")
                    self.readabilityScriptCache = scriptString
                    executeReadability(script: scriptString)
                } else {
                    self.showAlert(title: "Erreur réseau", message: "Impossible de télécharger le moteur de lecture.")
                }
            }
        }.resume()
    }
    @objc func loadWebsite() {
        
        guard let text = addressBar.text?.trimmingCharacters(in: .whitespaces), !text.isEmpty else {
            showAlert(title: "Erreur", message: "Veuillez entrer une adresse ou une recherche.")
            return
        }
        let cleanedText = text.lowercased()
        let isPotentialURL = cleanedText.contains(".") || cleanedText.hasPrefix("http://") || cleanedText.hasPrefix("https://")
        
        if isPotentialURL {
            var urlString = cleanedText
            if !urlString.hasPrefix("http://") && !urlString.hasPrefix("https://") {
                urlString = "https://" + urlString
            }
            loadURL(urlString)
        } else {
            let searchQuery = text.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? text
            let searchURL: String
            switch currentSearchEngine {
            case "bing": searchURL = "https://www.bing.com/search?q=\(searchQuery)"
            case "duckduckgo": searchURL = "https://duckduckgo.com/?q=\(searchQuery)"
            default: searchURL = "https://www.google.com/search?q=\(searchQuery)"
            }
            loadURL(searchURL)
        }
        hideSuggestions()
    }
    
    func loadURL(_ urlString: String) {
        if let url = URL(string: urlString), url.scheme != nil, url.host != nil {
            // L'entrée ressemble à une URL valide (schéma et hôte présents), essayons de la charger
            var request = URLRequest(url: url)
            request.addValue("fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", forHTTPHeaderField: "Accept-Language")
            request.addValue("gzip, deflate, br", forHTTPHeaderField: "Accept-Encoding")
            request.addValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
            // On interroge Cloudflare pour info (Ne bloque pas le chargement)
                        CloudflareDNS.shared.resolve(domain: urlString) { [weak self] ip in
                            guard let self = self, let ip = ip else { return }
                            
                            let host = url.host ?? "Inconnu"
                            let message = "🔍 DNS Cloudflare : \(host) = \(ip)"
                            
                            print(message) // Affiche dans la console Xcode
                            
                            // Affiche dans votre console visuelle DevTools si ouverte
                            DispatchQueue.main.async {
                                self.devToolsView?.log(message, type: "network")
                            }
                        }
            tabs[currentTabIndex].load(request)
            animateLoadingFeedback()
        } else {
            // L'entrée ne ressemble pas à une URL valide complète, effectuons une recherche Google
            let encodedSearchTerm = urlString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? urlString
            let googleSearchURLString = "https://www.google.com/search?q=\(encodedSearchTerm)"
            if let googleSearchURL = URL(string: googleSearchURLString) {
                tabs[currentTabIndex].load(URLRequest(url: googleSearchURL))
                animateLoadingFeedback()
            } else {
                lastFailedURL = urlString
                lastNetworkError = NSError(domain: "URLValidation", code: -1, userInfo: [NSLocalizedDescriptionKey: "Impossible de créer l'URL de recherche Google pour : \(urlString)"])
                showAlert(title: "Erreur", message: "Recherche Google impossible pour : \(urlString).")
                loadOfflinePage()
            }
        }
        
        
    }
    
    func loadNewTabPage() {
        let currentWebView = tabs[currentTabIndex]
        currentWebView.loadHTMLString(newTabHTML, baseURL: nil)
        addressBar.text = ""
        updateSecurityIcon(url: nil)
        updateTabBar()
    }
    
    func loadOfflinePage() {
        tabs[currentTabIndex].loadHTMLString(offlineHTML, baseURL: nil)
        addressBar.text = "Hors ligne"
        updateSecurityIcon(url: nil)
        updateTabBar()
    }
    
    @objc func goBack() {
        if tabs[currentTabIndex].canGoBack { tabs[currentTabIndex].goBack() }
    }
    
    @objc func goForward() {
        if tabs[currentTabIndex].canGoForward { tabs[currentTabIndex].goForward() }
    }
    
    @objc func refresh() {
        // 1. Si on est en train de télécharger, la croix annule le téléchargement !
                if let task = currentDownloadTask {
                    task.cancel()
                    currentDownloadTask = nil
                    // L'UI va se remettre d'aplomb automatiquement via le bloc d'erreur "Annulé" plus haut
                    return
                }
        if isNetworkAvailable {
            tabs[currentTabIndex].reload()
            animateLoadingFeedback()
        } else {
            loadOfflinePage()
        }
    }
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        // Vérifie que l'observateur concerne bien l'onglet actif
        guard let currentWebView = object as? WKWebView, currentWebView == tabs[currentTabIndex] else { return }

        if keyPath == #keyPath(WKWebView.estimatedProgress) {
            let progress = Float(currentWebView.estimatedProgress)
            progressBar.setProgress(progress, animated: true)
            UIView.animate(withDuration: 0.3) {
                self.progressBar.alpha = (progress == 1.0 && !self.isFullScreen) ? 0 : 1
            }
        } 
        else if keyPath == #keyPath(WKWebView.isLoading) {
            let isLoading = currentWebView.isLoading
            refreshButton.setImage(UIImage(systemName: isLoading ? "xmark" : "arrow.clockwise"), for: .normal)
            refreshButton.tintColor = isLoading ? .red : .systemBlue
            if !isLoading { refreshButton.layer.removeAnimation(forKey: "rotate") }
        }
        else if keyPath == #keyPath(WKWebView.canGoBack) {
            backButton.isEnabled = currentWebView.canGoBack
            backButton.tintColor = currentWebView.canGoBack ? .systemBlue : .systemGray4
        }
        else if keyPath == #keyPath(WKWebView.canGoForward) {
            forwardButton.isEnabled = currentWebView.canGoForward
            forwardButton.tintColor = currentWebView.canGoForward ? .systemBlue : .systemGray4
        }
    }
    
    func updateTabBar() {
        tabBar.subviews.forEach { $0.removeFromSuperview() }
        tabButtons.removeAll()
        var xOffset: CGFloat = 5
        for (index, tab) in tabs.enumerated() {
            let tabButton = UIButton(type: .system)
            let isPrivate = tab.configuration.websiteDataStore.isPersistent == false
            let title = tab.title?.isEmpty ?? true ? "Nouvel onglet - Xplorer 2" : tab.title!
            tabButton.setTitle(String(title.prefix(15)), for: .normal)
            tabButton.tintColor = isPrivate ? .white : (isDarkMode ? .lightGray : .lightGray)
            tabButton.tag = index
            if let url = tab.url, let host = url.host, !isPrivateMode || !isPrivate {
                let faviconKey = "https://www.google.com/s2/favicons?domain=\(host)" as NSString
                if let cachedImage = faviconCache.object(forKey: faviconKey) {
                    tabButton.setImage(cachedImage.withRenderingMode(.alwaysOriginal), for: .normal)
                } else {
                    URLSession.shared.dataTask(with: URL(string: faviconKey as String)!) { data, _, _ in
                        if let data = data, let image = UIImage(data: data) {
                            self.faviconCache.setObject(image, forKey: faviconKey)
                            DispatchQueue.main.async {
                                tabButton.setImage(image.withRenderingMode(.alwaysOriginal), for: .normal)
                            }
                        }
                    }.resume()
                }
                tabButton.imageEdgeInsets = UIEdgeInsets(top: 0, left: -10, bottom: 0, right: 10)
                tabButton.titleEdgeInsets = UIEdgeInsets(top: 0, left: 10, bottom: 0, right: 20)
            }
            tabButton.frame = CGRect(x: xOffset, y: 0, width: 140, height: 40)
            tabButton.contentHorizontalAlignment = .left
            tabButton.addTarget(self, action: #selector(switchToTab(sender:)), for: .touchUpInside)
            tabButton.layer.cornerRadius = 8
            tabButton.backgroundColor = index == currentTabIndex ? (isPrivate ? .darkGray : (isDarkMode ? .darkGray : .white)) : (isPrivate ? .gray : (isDarkMode ? .gray : .lightGray.withAlphaComponent(0.3)))
            let closeButton = UIButton(type: .system)
            closeButton.setImage(UIImage(systemName: "xmark"), for: .normal)
            closeButton.tintColor = isPrivate ? .white : (isDarkMode ? .lightGray : .gray)
            closeButton.tag = index
            closeButton.frame = CGRect(x: 110, y: 5, width: 30, height: 30)
            closeButton.addTarget(self, action: #selector(closeTab(sender:)), for: .touchUpInside)
            tabButton.addSubview(closeButton)
            tabBar.addSubview(tabButton)
            tabButtons.append(tabButton)
            xOffset += 145
        }
        let addButton = UIButton(type: .system)
        addButton.setTitle("+", for: .normal)
        addButton.frame = CGRect(x: xOffset, y: 0, width: 40, height: 40)
        addButton.addTarget(self, action: #selector(addNewTab), for: .touchUpInside)
        addButton.backgroundColor = isDarkMode ? .gray : .lightGray.withAlphaComponent(0.3)
        addButton.layer.cornerRadius = 8
        tabBar.addSubview(addButton)
        tabBar.contentSize = CGSize(width: xOffset + 45, height: 40)
    }
    
    @objc func addNewTab() {
        guard tabs.count < maxTabs else { return }

        // 1. Choisir la bonne configuration
        let config = isPrivateMode ? privateWebConfiguration : webConfiguration
        
        // 2. Appliquer les scripts (UserAgent, DevTools, etc.)
        setupConfigurationForNewTab(config, isPrivate: isPrivateMode)

        // 3. Créer la WebView
        let newWebView = WKWebView(frame: view.bounds, configuration: config)

        // 4. LES DELEGATES (Crucial pour que la recherche fonctionne)
        newWebView.navigationDelegate = self
        newWebView.uiDelegate = self
        let proxy = LeakFreeProxy(delegate: self)
            
            let handlers = ["retryHandler", "fetchBridge", "engineHandler", "customizeHandler", "homeHandler", "devTools"]
            for name in handlers {
                // IMPORTANT : On retire d'abord pour être propre
                config.userContentController.removeScriptMessageHandler(forName: name)
                // ON AJOUTE LE PROXY AU LIEU DE "SELF"
                config.userContentController.add(proxy, name: name)
            }

        // 5. LES OBSERVATEURS (Pour la barre de progression et le titre)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.isLoading), options: .new, context: nil)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.canGoBack), options: .new, context: nil)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.canGoForward), options: .new, context: nil)

        // 6. Ajouter au tableau
        tabs.append(newWebView)
        history.append([])

        // 7. Afficher l'onglet (Appelle ta fonction switchTab robuste)
        switchTab(to: tabs.count - 1)

        // 8. Charger la page d'accueil
        loadNewTabPage()
    } 
    
    @objc func addPrivateTab() {
        guard tabs.count < maxTabs else {
            showAlert(title: "Limite atteinte", message: "Vous avez atteint la limite de \(maxTabs) onglets.")
            return
        }
        let newWebView = WKWebView(frame: webView.frame, configuration: privateWebConfiguration)
        newWebView.navigationDelegate = self
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.isLoading), options: .new, context: nil)
        view.addSubview(newWebView)
        tabs.append(newWebView)
        history.append([])
        switchToTab(at: tabs.count - 1)
        isPrivateMode = true
        view.backgroundColor = .systemGray6
        faviconCache.removeAllObjects()
        loadNewTabPage()
    }
    
    func closeCurrentTab() {
        if tabs.count > 1 {
            cleanupWebView(tabs[currentTabIndex])
            tabs[currentTabIndex].removeFromSuperview()
            tabs.remove(at: currentTabIndex)
            history.remove(at: currentTabIndex)
            currentTabIndex = min(currentTabIndex, tabs.count - 1)
            switchToTab(at: currentTabIndex)
            isPrivateMode = tabs[currentTabIndex].configuration.websiteDataStore.isPersistent == false
            view.backgroundColor = isPrivateMode ? .gray : customBackgroundColor
        } else {
            loadNewTabPage()
        }
        updateTabBar()
    }
    
    @objc func closeTab(sender: UIButton) {
        let index = sender.tag
        
        // Si c'est le dernier onglet, on ne le ferme pas, on charge juste la page d'accueil
        if tabs.count <= 1 {
            loadNewTabPage()
            return
        }

        let webViewToClose = tabs[index]
        
        // 1. On coupe les ponts proprement
        cleanupWebView(webViewToClose)
        webViewToClose.removeFromSuperview()
        
        // 2. On retire du tableau
        tabs.remove(at: index)
        history.remove(at: index)
        
        // 3. On ajuste l'index actuel
        if currentTabIndex >= tabs.count {
            currentTabIndex = tabs.count - 1
        } else if currentTabIndex > index {
            currentTabIndex -= 1
        }

        // 4. ON FORCE LE SWITCH propre vers le nouvel onglet actif
        switchTab(to: currentTabIndex)
    }
    
    func closeAllTabs() {
        let confirmation = UIAlertController(title: "Confirmer", message: "Voulez-vous fermer tous les onglets ?", preferredStyle: .alert)
        confirmation.addAction(UIAlertAction(title: "Oui", style: .destructive) { _ in
            self.tabs.forEach { self.cleanupWebView($0); $0.removeFromSuperview() }
            self.tabs.removeAll()
            self.history.removeAll()
            let newWebView = WKWebView(frame: self.webView.frame, configuration: self.webConfiguration)
            newWebView.navigationDelegate = self
            newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
            newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.isLoading), options: .new, context: nil)
            self.view.addSubview(newWebView)
            self.tabs.append(newWebView)
            self.history.append([])
            self.currentTabIndex = 0
            self.isPrivateMode = false
            self.view.backgroundColor = self.customBackgroundColor
            self.loadNewTabPage()
            self.updateTabBar()
        })
        confirmation.addAction(UIAlertAction(title: "Non", style: .cancel))
        present(confirmation, animated: true)
    }
    
    @objc func switchToTab(sender: UIButton) {
        switchToTab(at: sender.tag)
    }
    
    func switchToTab(at index: Int) {
        // On récupère l'onglet actuel
        let currentTab = tabs[currentTabIndex]

        if let url = currentTab.url {
            // On utilise ta fonction getDisplayDomain qui filtre about:blank
            addressBar.text = getDisplayDomain(from: url)
        } else {
            addressBar.text = ""
        }
        tabs[currentTabIndex].isHidden = true
        currentTabIndex = index
        tabs[currentTabIndex].isHidden = false
        addressBar.text = tabs[currentTabIndex].url?.absoluteString ?? ""
        NSLayoutConstraint.activate([
            tabs[currentTabIndex].topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 10),
            tabs[currentTabIndex].leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tabs[currentTabIndex].trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tabs[currentTabIndex].bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        isPrivateMode = tabs[currentTabIndex].configuration.websiteDataStore.isPersistent == false
        view.backgroundColor = isPrivateMode ? .systemGray6 : customBackgroundColor
        updateTabBar()
        updateSecurityIcon(url: tabs[currentTabIndex].url)
    }
    
    func addToHistory(url: URL) {
        if !isPrivateMode {
            history[currentTabIndex].append(HistoryEntry(url: url, timestamp: Date()))
        }
    }
    
    func showHistory() {
        if isPrivateMode {
            showAlert(title: "Historique", message: "L'historique n'est pas enregistré en mode privé.")
            return
        }
        
        let alert = UIAlertController(title: "Historique", message: "Recherchez ou sélectionnez une entrée", preferredStyle: .alert)
        alert.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
        alert.addTextField { textField in
            textField.placeholder = "Rechercher dans l'historique"
            textField.addTarget(self, action: #selector(self.updateHistoryAlert(_:)), for: .editingChanged)
        }
        
        updateHistoryAlertWithEntries(alert: alert, searchText: nil)
        present(alert, animated: true)
    }
    
    @objc func updateHistoryAlert(_ sender: UITextField) {
        guard let alert = presentedViewController as? UIAlertController else { return }
        let searchText = sender.text?.lowercased()
        updateHistoryAlertWithEntries(alert: alert, searchText: searchText)
    }
    
    private func updateHistoryAlertWithEntries(alert: UIAlertController, searchText: String?) {
        let existingActions = alert.actions
        let cancelAction = existingActions.first { $0.title == "Annuler" }
        alert.actions.forEach { action in
            if action != cancelAction { /* On ne peut pas supprimer directement */ }
        }
        
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        
        var filteredHistory = history[currentTabIndex]
        if let searchText = searchText, !searchText.isEmpty {
            filteredHistory = filteredHistory.filter { $0.url.absoluteString.lowercased().contains(searchText) }
        }
        
        for entry in filteredHistory.reversed().prefix(10) {
            let title = "\(entry.url.absoluteString) - \(formatter.string(from: entry.timestamp))"
            alert.addAction(UIAlertAction(title: title, style: .default, handler: { _ in
                self.loadURL(entry.url.absoluteString)
            }))
        }
        
        if cancelAction == nil {
            alert.addAction(UIAlertAction(title: "Annuler", style: .cancel, handler: nil))
        }
    }
    
    func addToBookmarks() {
        if let url = tabs[currentTabIndex].url, let title = tabs[currentTabIndex].title, !title.isEmpty {
            bookmarks.append((title: title, url: url))
            showAlert(title: "Favori ajouté", message: "\(title) ajouté.")
        }
    }
    
    func showBookmarks() {
        let alert = UIAlertController(title: "Favoris", message: nil, preferredStyle: .alert)
        alert.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
        for bookmark in bookmarks {
            alert.addAction(UIAlertAction(title: bookmark.title, style: .default, handler: { _ in self.loadURL(bookmark.url.absoluteString) }))
        }
        alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
        present(alert, animated: true)
    }
    
    func translatePage() {
        let translateScript = """
        if (!window.google || !window.google.translate) {
            var script = document.createElement('script');
            script.src = 'https://translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
            script.onerror = function() { window.webkit.messageHandlers.errorHandler.postMessage('Erreur de chargement du script de traduction'); };
            document.head.appendChild(script);
        } else {
            googleTranslateElementInit();
        }

        window.googleTranslateElementInit = function() {
            new google.translate.TranslateElement({
                pageLanguage: '',
                autoDisplay: false,
                layout: google.translate.TranslateElement.InlineLayout.SIMPLE
            }, 'google_translate_element');
        };

        if (!document.getElementById('google_translate_element')) {
            var div = document.createElement('div');
            div.id = 'google_translate_element';
            div.style.position = 'fixed';
            div.style.top = '10px';
            div.style.right = '10px';
            div.style.zIndex = '1000';
            document.body.appendChild(div);
        }
        """
        
        tabs[currentTabIndex].evaluateJavaScript(translateScript) { _, error in
        }
    }
    
    func showFindInPage() {
        let alert = UIAlertController(title: "Rechercher dans la page", message: nil, preferredStyle: .alert)
        alert.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
        alert.addTextField { textField in
            textField.placeholder = "Entrez le texte à chercher"
        }
        alert.addAction(UIAlertAction(title: "Rechercher", style: .default) { _ in
            if let text = alert.textFields?.first?.text, !text.isEmpty {
                self.findInPage(text)
            }
        })
        alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
        present(alert, animated: true)
    }
    
    func findInPage(_ text: String) {
        // Configuration de la recherche native
        let config = WKFindConfiguration()
        config.backwards = false
        config.caseSensitive = false
        config.wraps = true // Recommence au début si on arrive à la fin
        
        // Appel natif à WebKit (beaucoup plus fluide et surligne en jaune automatiquement)
        tabs[currentTabIndex].find(text, configuration: config) { result in
            if result.matchFound {
                // On ne met pas d'alerte à chaque fois, c'est agaçant.
                // On pourrait juste faire un petit print ou une vibration.
                print("Texte trouvé !")
            } else {
                self.showAlert(title: "Recherche", message: "Aucune occurrence trouvée.")
            }
        }
    }
    
    func showSettings() {
        let alert = UIAlertController(title: "Réglages", message: "Personnalisez votre expérience", preferredStyle: .actionSheet)

                alert.addAction(UIAlertAction(title: "À propos", style: .default, handler: { _ in
                    let aboutAlert = UIAlertController(title: "Xplorer 2", 
                        message: "Version : 20260409 (Bubble Fish)\nStatut : Github Edition", 
                        preferredStyle: .alert)
                    aboutAlert.overrideUserInterfaceStyle = self.isDarkMode ? .dark : .light
                    aboutAlert.addAction(UIAlertAction(title: "OK", style: .cancel))
                    self.present(aboutAlert, animated: true)
                }))
        alert.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
        alert.addAction(UIAlertAction(title: "Moteur de recherche : Google", style: .default, handler: { _ in
            self.currentSearchEngine = "google"
            self.addressBar.placeholder = "Rechercher avec Google ou entrer une URL"
            UserDefaults.standard.set("google", forKey: "searchEngine")
        }))
        alert.addAction(UIAlertAction(title: "Moteur de recherche : Bing", style: .default, handler: { _ in
            self.currentSearchEngine = "bing"
            self.addressBar.placeholder = "Rechercher avec Bing ou entrer une URL"
            UserDefaults.standard.set("bing", forKey: "searchEngine")
        }))
        alert.addAction(UIAlertAction(title: "Moteur de recherche : DuckDuckGo", style: .default, handler: { _ in
            self.currentSearchEngine = "duckduckgo"
            self.addressBar.placeholder = "Rechercher avec DuckDuckGo ou entrer une URL"
            UserDefaults.standard.set("duckduckgo", forKey: "searchEngine")
        }))
        alert.addAction(UIAlertAction(title: "Supprimer les données de navigation", style: .destructive, handler: { _ in
            self.clearBrowsingData()
        }))
        alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
        present(alert, animated: true)
    }
    
    func clearBrowsingData() {
        let confirmation = UIAlertController(title: "Confirmer",
                                           message: "Voulez-vous vraiment supprimer toutes les données de navigation (cookies, cache, historique) ?",
                                           preferredStyle: .alert)
        confirmation.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
        
        confirmation.addAction(UIAlertAction(title: "Oui", style: .destructive) { _ in
            let dataStore = WKWebsiteDataStore.default()
            let dataTypes = WKWebsiteDataStore.allWebsiteDataTypes()
            
            dataStore.removeData(ofTypes: dataTypes,
                               modifiedSince: Date.distantPast) {
                DispatchQueue.main.async {
                    self.history = self.history.map { _ in [] }
                    self.bookmarks.removeAll()
                    self.faviconCache.removeAllObjects()
                    self.showAlert(title: "Succès", message: "Les données de navigation ont été supprimées.")
                }
            }
        })
        
        confirmation.addAction(UIAlertAction(title: "Non", style: .cancel))
        present(confirmation, animated: true)
    }
    
    func toggleFullScreen() {
        isFullScreen.toggle()
        UIView.animate(withDuration: 0.3) {
            self.tabBar.isHidden = self.isFullScreen
            self.addressBar.isHidden = self.isFullScreen
            self.backButton.isHidden = self.isFullScreen
            self.forwardButton.isHidden = self.isFullScreen
            self.refreshButton.isHidden = self.isFullScreen
            self.menuButton.isHidden = self.isFullScreen
            self.goButton.isHidden = self.isFullScreen
            self.progressBar.alpha = self.isFullScreen || self.tabs[self.currentTabIndex].estimatedProgress == 1.0 ? 0 : 1
            self.securityIcon.isHidden = self.isFullScreen
            self.suggestionView.isHidden = true
            NSLayoutConstraint.deactivate(self.tabs[self.currentTabIndex].constraints)
            NSLayoutConstraint.activate(self.isFullScreen ? [
                self.tabs[self.currentTabIndex].topAnchor.constraint(equalTo: self.view.topAnchor),
                self.tabs[self.currentTabIndex].leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
                self.tabs[self.currentTabIndex].trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
                self.tabs[self.currentTabIndex].bottomAnchor.constraint(equalTo: self.view.bottomAnchor)
            ] : [
                self.tabs[self.currentTabIndex].topAnchor.constraint(equalTo: self.progressBar.bottomAnchor, constant: 10),
                self.tabs[self.currentTabIndex].leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
                self.tabs[self.currentTabIndex].trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
                self.tabs[self.currentTabIndex].bottomAnchor.constraint(equalTo: self.view.bottomAnchor)
            ])
            self.view.layoutIfNeeded()
        }
        menuButton.menu = createMenu()
    }
    
    @objc func exitFullScreen() {
        if isFullScreen { toggleFullScreen() }
    }
    
    func updateSecurityIcon(url: URL?) {
            DispatchQueue.main.async {[weak self] in
                guard let self = self else { return }
                
                // 1. Cas page vide ou accueil
                guard let url = url, url.absoluteString != "about:blank", let scheme = url.scheme else {
                    self.securityIcon.image = UIImage(systemName: "house.fill")
                    self.securityIcon.tintColor = .systemBlue
                    return
                }
                
                let host = url.host ?? ""
                
                // 2. Cas HTTPS
                if scheme == "https" {
                    // On vérifie si ce host est dans notre liste "Attention"
                    if self.bypassedSSLHosts.contains(host) {
                        // CADENA NOIR + ATTENTION (Firefox Style)
                        self.securityIcon.image = UIImage(systemName: "lock.trianglebadge.exclamationmark.fill")
                        self.securityIcon.tintColor = .label // S'adapte au mode sombre/clair automatiquement
                    } else {
                        // CADENA VERT (Sécurité standard)
                        self.securityIcon.image = UIImage(systemName: "lock.fill")
                        self.securityIcon.tintColor = .systemGreen
                    }
                } 
                // 3. Cas HTTP
                else if scheme == "http" {
                    self.securityIcon.image = UIImage(systemName: "exclamationmark.triangle.fill")
                    self.securityIcon.tintColor = .systemOrange
                }
            }
        }
    
    func setupSecurityIcon() {
        securityIcon.isUserInteractionEnabled = true
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(showSecurityInfo))
        securityIcon.addGestureRecognizer(tapGesture)
    }
    
       @objc func showSecurityInfo() {
           guard let currentURL = tabs[currentTabIndex].url else { return }
           
           // 1. Préparation du message principal
           let alertTitle = (currentURL.scheme == "https") ? "Connexion Sécurisée" : "Non Sécurisé"
           var message = ""
           
           if currentURL.scheme == "https" {
               message = "🔒 Ce site utilise une connexion chiffrée (HTTPS).\nVos données sont protégées."
           } else {
               message = "⚠️ ATTENTION : Site Non Sécurisé (HTTP).\nNe saisissez jamais de mot de passe ou de carte bancaire ici."
           }
           
           let alert = UIAlertController(title: alertTitle, message: message, preferredStyle: .alert)
           
           // 2. Bouton "Détails techniques" (Uniquement si HTTPS)
           if currentURL.scheme == "https" {
               alert.addAction(UIAlertAction(title: "Détails techniques", style: .default) { _ in
                   // C'est ici que ça se passait ! On crée une NOUVELLE alerte.
                   
                   var detailsText = ""
                   
                   if let info = self.sslCertificateInfo {
                       // On met en forme le texte proprement
                       if let sujet = info["Sujet"] {
                           detailsText += "📍 SITE WEB :\n\(sujet)\n\n"
                       }
                       if let emetteur = info["Émetteur"] {
                           detailsText += "✍️ SIGNÉ PAR :\n\(emetteur)\n\n"
                       }
                       if let expiration = info["Expiration"] {
                           detailsText += "📅 EXPIRATION :\n\(expiration)"
                       }
                   } else {
                       detailsText = "Aucune information technique disponible."
                   }
                   
                   // On affiche la deuxième fenêtre
                   let detailAlert = UIAlertController(title: "Certificat SSL", message: detailsText, preferredStyle: .alert)
                   detailAlert.addAction(UIAlertAction(title: "Fermer", style: .cancel))
                   self.present(detailAlert, animated: true)
               })
           }
           
           // Bouton OK pour fermer la première fenêtre
           alert.addAction(UIAlertAction(title: "OK", style: .cancel))
           
           present(alert, animated: true)
       }

    
    // MARK: - Feedback Visuel
    func animateLoadingFeedback() {
        refreshButton.layer.add(CABasicAnimation(keyPath: "transform.rotation") {
            $0.duration = 1
            $0.repeatCount = .infinity
            $0.toValue = 2 * Double.pi
        }, forKey: "rotate")
        UIView.animate(withDuration: 0.3) {
            self.goButton.transform = .init(scaleX: 1.2, y: 1.2)
        } completion: { _ in
            UIView.animate(withDuration: 0.3) {
                self.goButton.transform = .identity
            }
        }
    }
    
    // MARK: - Gestion des suggestions
    func showSuggestions(_ suggestions: [String]) {
        self.suggestions = suggestions
        suggestionTableView.reloadData()
        suggestionView.isHidden = suggestions.isEmpty || isFullScreen
        view.bringSubviewToFront(suggestionView)
    }
    
    func hideSuggestions() {
        suggestionView.isHidden = true
        suggestions.removeAll()
    }
    
    // MARK: - Utilitaires
    func cleanupWebView(_ webView: WKWebView) {
        // 1. Stop immédiat
        webView.stopLoading()
        
        // 2. On coupe les liens JS <-> Swift (C'est souvent là que ça fuit)
        webView.configuration.userContentController.removeAllUserScripts()
        webView.configuration.userContentController.removeAllScriptMessageHandlers()
        
        // 3. On libère les délégués
        webView.navigationDelegate = nil
        webView.uiDelegate = nil
        
        // 4. L'ASTUCE PRO : Charger une page vide force WebKit à vider le cache de la page précédente
        webView.load(URLRequest(url: URL(string: "about:blank")!))
        
        // 5. On retire les observateurs (KVO) pour éviter les crashs
        webView.removeObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress))
        webView.removeObserver(self, forKeyPath: #keyPath(WKWebView.isLoading))
        webView.removeObserver(self, forKeyPath: #keyPath(WKWebView.canGoBack))
        webView.removeObserver(self, forKeyPath: #keyPath(WKWebView.canGoForward))
        
        print("Onglet nettoyé et mémoire libérée.")
    }
    
    func showAlert(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.overrideUserInterfaceStyle = isDarkMode ? .dark : .light
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
    
    func UIColorToHex(color: UIColor) -> String {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        color.getRed(&r, green: &g, blue: &b, alpha: &a)
        return String(format: "#%02X%02X%02X", Int(r * 255), Int(g * 255), Int(b * 255))
    }
    // MARK: - Fonctionnalité d'Authentification Biométrique
    func authenticateWithBiometrics(url: URL, callbackURLScheme: String) {
        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackURLScheme) { [weak self] callbackURL, error in
            guard let self = self else { return }
            
            if let successURL = callbackURL {
                print("Authentification réussie, chargement de l'URL de rappel: \(successURL)")
                
                // 1. Mettre à jour l'adresse URL dans le champ de texte
                self.addressBar.text = successURL.absoluteString
                
                // 2. Appeler votre fonction de chargement existante (qui ne prend pas d'argument)
                self.loadWebsite() // J'assume ici que votre fonction s'appelle loadWebsite()
            }
        }
    }
    
    // MARK: - Utilitaires d'URL pour l'affichage
    func getDisplayDomain(from url: URL) -> String {
        let absString = url.absoluteString
        
        // Si c'est une page vide, on ne renvoie rien
        if absString == "about:blank" || absString.isEmpty {
            return ""
        }
        
        guard var host = url.host else { 
            return absString
        }
        
        if host.hasPrefix("www.") {
            host.removeFirst(4)
        }
        return host
    }
    // MARK: - Utilitaires de WKWebView
    // Cette fonction doit encapsuler toute la logique d'initialisation de votre WKWebView
    func createAndConfigureWebView(with configuration: WKWebViewConfiguration? = nil) -> WKWebView {
        
        // Utilise la configuration fournie ou crée la vôtre (mode privé/sombre)
        let config = configuration ?? createWebViewConfiguration(forPrivateMode: self.isPrivateMode) 
        let newWebView = WKWebView(frame: .zero, configuration: config)
        
        // La nouvelle WebView DOIT AVOIR les deux delegates pour fonctionner correctement
        newWebView.navigationDelegate = self 
            newWebView.uiDelegate = self        // <--- Le UI Delegate est nécessaire pour gérer les popups
        
        // Assurez-vous d'avoir toutes vos configurations de base ici
        newWebView.allowsBackForwardNavigationGestures = true
        // newWebView.scrollView.delegate = self // Si vous utilisez un delegate pour le scroll
        
        return newWebView
    }

    // Fonction utilitaire pour la configuration (assumée de votre code)
    func createWebViewConfiguration(forPrivateMode isPrivate: Bool) -> WKWebViewConfiguration {
        let config = WKWebViewConfiguration()
        
        // Gère le mode privé
        if isPrivate {
            config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        } else {
            config.websiteDataStore = WKWebsiteDataStore.default()
        }
        
        
        return config
    }
    // MARK: - Action de l'Utilisateur : Ouvrir Nouvel Onglet
    @objc func openNewTab() {
        // 1. Crée un nouvel onglet
        let newWebView = createAndConfigureWebView()
        
        // 2. L'ajoute à votre tableau d'onglets et le rend actif
        tabs.append(newWebView)
        currentTabIndex = tabs.count - 1
        
        // 3. Met à jour l'UI
        updateTabBar() 
        switchTab(to: currentTabIndex) 
        
        // 4. Charge la page de nouvel onglet
        if let newTabURL = URL(string: "about:blank") {
            addressBar.text = newTabURL.absoluteString // Met à jour l'adresse
            loadWebsite() 
        }
    }
    // MARK: - Gestion des Onglets : Affichage
    func switchTab(to index: Int) {
        // 1. Sécurité : on vérifie que l'index existe
        guard index >= 0 && index < tabs.count else { return }
        guard index < tabs.count else { return }

        // 2. Nettoyer l'affichage actuel : on cache tout
        for tab in tabs {
            tab.isHidden = true
            // On ne le retire pas forcément du superview ici pour éviter les bugs de clignotement
        }

        currentTabIndex = index
        let activeWebView = tabs[currentTabIndex]
        
        // 3. ÉTAPE CRUCIALE : On ajoute la WebView à la hiérarchie AVANT les contraintes
        if activeWebView.superview == nil {
            view.addSubview(activeWebView)
        }
        
        activeWebView.isHidden = false
        view.sendSubviewToBack(activeWebView) // Pour rester derrière les barres d'outils

        // 4. On active les contraintes (Maintenant qu'ils ont un ancêtre commun : 'view')
        activeWebView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            activeWebView.topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 10),
            activeWebView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            activeWebView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            activeWebView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])

        // 5. Mise à jour de l'UI
        isPrivateMode = (activeWebView.configuration.websiteDataStore.isPersistent == false)
        view.backgroundColor = isPrivateMode ? UIColor.darkGray : customBackgroundColor
        addressBar.text = activeWebView.url?.absoluteString ?? ""
        updateSecurityIcon(url: activeWebView.url)
        updateTabBar()
    }
    func webViewDidClose(_ webView: WKWebView) {
        if let indexToRemove = tabs.firstIndex(of: webView) {
            // Nettoyage de la WebView qui ferme
            cleanupWebView(webView)
            webView.removeFromSuperview()
            tabs.remove(at: indexToRemove)
            history.remove(at: indexToRemove)

            // Déterminer quel onglet montrer ensuite
            if tabs.isEmpty {
                addNewTab() // Si on a tout fermé, on en ouvre un nouveau
            } else {
                // Si on a fermé l'onglet actuel, on va sur le précédent
                if currentTabIndex >= tabs.count {
                    currentTabIndex = tabs.count - 1
                }
                // On force le rafraîchissement de l'affichage
                switchTab(to: currentTabIndex)
            }
        }
        
    }
    
    
}
import WebKit

class AdBlockManager {
    static let shared = AdBlockManager()
    var compiledRuleList: WKContentRuleList?
    
    // Liste de domaines à bloquer (Avant le téléchargement)
    private let blockedDomains = [
        "doubleclick.net", "googlesyndication.com", "google-analytics.com", "adservice.google.com",
        "facebook.com/tr", "connect.facebook.net", "ads.twitter.com", "static.ads-twitter.com",
        "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adnxs.com", "adsrvr.org",
        "rubiconproject.com", "pubmatic.com", "openx.net", "smartadserver.com",
        "amazon-adsystem.com", "moatads.com", "adroll.com", "appsflyer.com",
        "hotjar.com", "mouseflow.com", "freshmarketer.com", "luckyorange.com",
        "cdn.siftscience.com", "pixel.facebook.com", "an.facebook.com",
        "ads.linkedin.com", "analytics.tiktok.com", "ads.pinterest.com",
        "adcolony.com", "applovin.com", "chartboost.com", "inmobi.com",
        "unityads.unity3d.com", "vungle.com", "iron-source.com"
    ]
    
    // Génère le JSON requis par WebKit
    private func buildRuleListJSON() -> String {
        var rules: [[String: Any]] = []
        
        // Règle 1 : Bloquer les chargements provenant de ces domaines
        let domainTrigger = blockedDomains.joined(separator: "|")
        // On échappe les points pour le Regex
        let escapedDomains = domainTrigger.replacingOccurrences(of: ".", with: "\\.")
        
        let blockRule: [String: Any] = [
            "trigger": [
                "url-filter": ".*(\(escapedDomains)).*",
                "resource-type": ["script", "image", "style-sheet", "popup", "ping", "media", "xmlhttprequest"]
            ],
            "action": [
                "type": "block"
            ]
        ]
        rules.append(blockRule)
        
        // Règle 2 : Masquer les éléments visuels CSS courants (class="ads", id="banner", etc.)
        let cssHideRule: [String: Any] = [
            "trigger": [
                "url-filter": ".*" // S'applique partout
            ],
            "action": [
                "type": "css-display-none",
                "selector": ".ads, .ad-banner, .advertisement, #google_ads_frame, .outbrain-widget, .taboola-widget, [id^='div-gpt-ad'], .fb-pixel"
            ]
        ]
        rules.append(cssHideRule)
        
        // Règle 3 : Forcer le HTTPS (Upgrade insecure requests)
        let httpsRule: [String: Any] = [
            "trigger": [
                "url-filter": ".*"
            ],
            "action": [
                "type": "make-https"
            ]
        ]
        rules.append(httpsRule)
        
        // Conversion en String JSON
        if let jsonData = try? JSONSerialization.data(withJSONObject: rules, options: []),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        }
        return "[]"
    }
    
    // Compile la liste pour WebKit (Opération lourde, faite une seule fois)
    func compileRules(completion: @escaping (WKContentRuleList?) -> Void) {
        if let existingList = compiledRuleList {
            completion(existingList)
            return
        }
        
        let jsonString = buildRuleListJSON()
        
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: "AdBlockList",
            encodedContentRuleList: jsonString
        ) { [weak self] ruleList, error in
            if let error = error {
                print("Erreur compilation AdBlock: \(error)")
                completion(nil)
            } else {
                print("AdBlock activé avec succès !")
                self?.compiledRuleList = ruleList
                completion(ruleList)
            }
        }
    }
}

// MARK: - Extension WKUIDelegate pour les Nouveaux Onglets
extension BrowserViewController: WKUIDelegate {

    func webView(_ webView: WKWebView, 
                 createWebViewWith configuration: WKWebViewConfiguration, 
                 for navigationAction: WKNavigationAction, 
                 windowFeatures: WKWindowFeatures) -> WKWebView? {
        
        // 1. Déterminer si on doit être en mode privé
        // On regarde si l'onglet qui a ouvert le lien (webView) est privé
        let isPrivate = webView.configuration.websiteDataStore.isPersistent == false
        
        // 2. Appliquer notre configuration propre sur l'objet fourni par le système
        
        // C'est ici qu'on remplace la boucle qui crashait par notre fonction sûre
        setupConfigurationForNewTab(configuration, isPrivate: isPrivate)
        
        // 3. Créer la WebView avec cette configuration préparée
        let newWebView = WKWebView(frame: view.bounds, configuration: configuration)
        
        // 4. Configuration visuelle et délégués
        newWebView.uiDelegate = self
        newWebView.navigationDelegate = self
        newWebView.translatesAutoresizingMaskIntoConstraints = false
        
        // 5. Observateurs
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.isLoading), options: .new, context: nil)
        
        // 6. Ajout à la vue (Pour éviter le crash d'affichage)
        view.addSubview(newWebView)
        
        // 7. Gestion des données
        tabs.append(newWebView)
        let newIndex = tabs.count - 1
        switchTab(to: newIndex)
        history.append([]) 
        
        // 8. Afficher l'onglet
        switchToTab(at: tabs.count - 1)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.canGoBack), options: .new, context: nil)
        newWebView.addObserver(self, forKeyPath: #keyPath(WKWebView.canGoForward), options: .new, context: nil)
        let handlers = ["retryHandler", "engineHandler", "customizeHandler", "homeHandler", "devTools"]
        return newWebView
    }

    // C'est souvent une bonne idée d'implémenter aussi ceci pour les alertes/prompts JavaScript
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let alertController = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: { _ in
            completionHandler()
        }))
        present(alertController, animated: true, completion: nil)
    }
    // Cette fonction autorise le site à demander l'accès au Micro/Caméra
    @available(iOS 15.0, *)
    func webView(_ webView: WKWebView, 
                 decideMediaCapturePermissionFor origin: WKSecurityOrigin, 
                 initiatedByFrame frame: WKFrameInfo, 
                 type: WKMediaCaptureType, 
                 decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        
        // Pour ton usage perso, on dit "OUI" automatiquement (ou tu peux mettre une alerte)
        decisionHandler(.grant) 
    }
}

// MARK: - Extension ASWebAuthenticationPresentationContextProviding
extension BrowserViewController: ASWebAuthenticationPresentationContextProviding {
    
    // Cette fonction indique l'ancre (la fenêtre) où la session d'authentification doit s'afficher.
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        // Retourne la fenêtre principale pour afficher la boîte de dialogue
        return self.view.window ?? ASPresentationAnchor()
    }
}

// MARK: - WKNavigationDelegate
extension BrowserViewController: WKNavigationDelegate {
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if let url = webView.url, webView == tabs[currentTabIndex] {
            addToHistory(url: url)
            addressBar.text = url.absoluteString
            updateSecurityIcon(url: url)
            updateTabBar()
                    self.addressBar.text = getDisplayDomain(from: url)
        }
        
    }
    func presentDownloadAlert(for url: URL) {
            let fileName = url.lastPathComponent
            let alert = UIAlertController(title: "Fichier détecté", 
                                          message: "Que souhaitez-vous faire avec '\(fileName)' ?", 
                                          preferredStyle: .actionSheet)
            
            alert.addAction(UIAlertAction(title: "Afficher dans le navigateur", style: .default) { _ in
                self.allowedInlineFiles.insert(url.absoluteString)
                self.tabs[self.currentTabIndex].load(URLRequest(url: url))
            })
            
            alert.addAction(UIAlertAction(title: "Télécharger", style: .default) { _ in
                self.startDownload(from: url)
            })
            
            alert.addAction(UIAlertAction(title: "Annuler", style: .cancel))
            
            if let popover = alert.popoverPresentationController {
                popover.sourceView = self.addressBar
            }
            
            present(alert, animated: true)
        }
        
        func startDownload(from url: URL) {
            // UI: Barre de progression et Croix rouge !
            self.progressBar.alpha = 1
            self.progressBar.setProgress(0.1, animated: true)
            
            DispatchQueue.main.async {
                self.refreshButton.setImage(UIImage(systemName: "xmark"), for: .normal)
                self.refreshButton.tintColor = .red
                // On stoppe la rotation de la flèche si elle tournait
                self.refreshButton.layer.removeAnimation(forKey: "rotate") 
            }
            
            let task = URLSession.shared.downloadTask(with: url) { [weak self] (tempLocalUrl, response, error) in
                guard let self = self else { return }
                
                // On réinitialise l'UI à la fin (succès ou erreur)
                DispatchQueue.main.async {
                    self.currentDownloadTask = nil
                    let isLoading = self.tabs[self.currentTabIndex].isLoading
                    self.refreshButton.setImage(UIImage(systemName: isLoading ? "xmark" : "arrow.clockwise"), for: .normal)
                    self.refreshButton.tintColor = isLoading ? .red : .systemBlue
                    self.progressBar.alpha = 0
                }
                
                if let error = error {
                    // Si l'erreur est "Annulé" (parce qu'on a cliqué sur la croix), on ne dit rien
                    if (error as NSError).code != NSURLErrorCancelled {
                        DispatchQueue.main.async { self.showAlert(title: "Erreur", message: error.localizedDescription) }
                    }
                    return
                }
                
                guard let tempLocalUrl = tempLocalUrl else { return }
                
                let fileName = url.lastPathComponent
                let destinationUrl = FileManager.default.temporaryDirectory.appendingPathComponent(fileName)
                try? FileManager.default.removeItem(at: destinationUrl)
                
                do {
                    try FileManager.default.moveItem(at: tempLocalUrl, to: destinationUrl)
                    DispatchQueue.main.async {
                        self.progressBar.setProgress(1.0, animated: true)
                        self.showShareSheet(for: destinationUrl)
                    }
                } catch {
                    DispatchQueue.main.async { self.showAlert(title: "Erreur", message: "Impossible de sauvegarder le fichier.") }
                }
            }
            
            self.currentDownloadTask = task // On sauvegarde la tâche pour pouvoir l'annuler
            task.resume()
        }
        
        func showShareSheet(for fileUrl: URL) {
            let activityVC = UIActivityViewController(activityItems: [fileUrl], applicationActivities: nil)
            
            if let popover = activityVC.popoverPresentationController {
                popover.sourceView = self.menuButton // Ou un autre bouton
            }
            
            self.present(activityVC, animated: true)
        }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        if let nsError = error as NSError? {
            if nsError.code == NSURLErrorCancelled {
                // L'utilisateur a probablement annulé la navigation.
                if let failingURL = nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
                    webView.load(URLRequest(url: URL(string: "about:blank")!))
                    return
                }
                print("Navigation annulée (-999) sans URL de requête.")
            } else {
                // Autre erreur de navigation, afficher un message à l'utilisateur
                print("Erreur de navigation: \(error.localizedDescription)")
                displayErrorMessage(message: "La page n'a pas pu être chargée.") // Utilise une fonction pour afficher l'alerte
                loadOfflinePage()
            }
        } else {
            // Erreur non NSError, afficher un message générique
            print("Erreur de navigation non NSError: \(error.localizedDescription)")
            displayErrorMessage(message: "Une erreur est survenue lors du chargement de la page.")
        }
        // Fonction pour afficher une alerte d'erreur à l'utilisateur
            func displayErrorMessage(message: String) {
                let alertController = UIAlertController(title: "Erreur", message: message, preferredStyle: .alert)
                let okAction = UIAlertAction(title: "OK", style: .default)
                alertController.addAction(okAction)
                present(alertController, animated: true)
            }
    }
    

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if webView != tabs[currentTabIndex] { return }

        let nsError = error as NSError
        if nsError.code == NSURLErrorCancelled { return }
        // 2. Ignorer l'erreur 102 SEULEMENT si c'est un de nos fichiers (PDF, ZIP...)
        if nsError.domain == "WebKitErrorDomain" && nsError.code == 102 {
            if let url = nsError.userInfo["NSErrorFailingURLStringKey"] as? String {
                let fileExtensions = ["pdf", "zip", "dmg", "mp4", "mp3", "docx", "xlsx", "pptx"]
                if fileExtensions.contains(where: { url.lowercased().hasSuffix($0) }) {
                    return // C'est une interruption normale due à notre popup de téléchargement
                }
            }
        }
        // --- 1. INTERCEPTION DES ERREURS SSL (Auto-signé, expiré, etc.) ---
        let sslErrorCodes = [
            NSURLErrorServerCertificateUntrusted,      // -1202 (Auto-signé ou inconnu)
            NSURLErrorServerCertificateHasBadDate,     // -1201 (Expiré)
            NSURLErrorServerCertificateHasUnknownRoot, // -1203
            NSURLErrorServerCertificateNotYetValid,    // -1204
            NSURLErrorSecureConnectionFailed           // -1200
        ]
        
        if sslErrorCodes.contains(nsError.code) {
            if let failingURL = nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
                print("🛡️ Erreur SSL interceptée pour : \(failingURL.host ?? "inconnu") (Code: \(nsError.code))")
                self.loadSSLWarning(for: failingURL, errorCode: nsError.code)
                return
            }
        }
        //INTERCEPTION DU BLOCAGE PAR LE FILTRE (Code 105)
                if nsError.domain == "WebKitErrorDomain" && nsError.code == 105 {
                    if let failingURL = nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
                        print("Bloqué par le filtre (AdBlock) : \(failingURL.host ?? "")")
                        self.loadContentFilterWarning(for: failingURL)
                        return
                    }
                }
        // --- 2. FALLBACK HTTP (Ton code pour le Smart Upgrade) ---
        if let failingURL = nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
            let host = failingURL.host ?? ""
            
            if failingURL.scheme == "https" && !bypassedHTTPHosts.contains(host) {
                print("Le HTTPS a échoué pour \(host). Proposition du fallback HTTP.")
                let httpFallbackURLString = failingURL.absoluteString.replacingOccurrences(of: "https://", with: "http://")
                if let httpFallbackURL = URL(string: httpFallbackURLString) {
                    self.loadHTTPWarning(for: httpFallbackURL)
                    return
                }
            }
        }
        
        // --- 3. ERREUR RÉSEAU CLASSIQUE (Plus d'internet, site introuvable) ---
        print("Erreur réseau: \(error.localizedDescription)")
        lastFailedURL = (nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL)?.absoluteString
        lastNetworkError = error
        loadOfflinePage()
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }

        if url.absoluteString == "about:blank" || url.scheme == "file" {
            decisionHandler(.allow)
            return
        }

        // Protection Iframe : On ne vérifie que la page principale
        guard navigationAction.targetFrame?.isMainFrame == true else {
            decisionHandler(.allow)
            return
        }
        //GESTION DES TÉLÉCHARGEMENTS
                let fileExtensions = ["pdf", "zip", "dmg", "mp4", "mp3", "docx", "xlsx", "pptx", "iso", "rar", "gz", "exe", "apk"]
                let extensionPath = url.pathExtension.lowercased()
        if extensionPath == "pdf" {
                    decisionHandler(.cancel) // On stoppe la navigation standard
                    let pdfVC = PDFViewController()
                    pdfVC.pdfURL = url
                    pdfVC.isDarkMode = self.isDarkMode
                    let nav = UINavigationController(rootViewController: pdfVC)
                    nav.modalPresentationStyle = .fullScreen
                    self.present(nav, animated: true)
                    return
                }
                if fileExtensions.contains(extensionPath) {
                    // Si l'utilisateur a DÉJÀ cliqué sur "Afficher dans le navigateur" pour ce fichier
                    if self.allowedInlineFiles.contains(url.absoluteString) {
                        decisionHandler(.allow) // On le laisse passer !
                        return
                    }
                    
                    // Sinon, on bloque et on demande quoi faire
                    decisionHandler(.cancel)
                    self.presentDownloadAlert(for: url)
                    return
                }
        let host = url.host ?? ""

        // 1. VÉRIFICATION ANTI-PHISHING
        if PhishingManager.shared.isDangerous(url: url) {
            // On vérifie si on l'a autorisé manuellement avant de bloquer
            if !self.bypassedPhishingHosts.contains(host) {
                print("ALERTE PHISHING : \(url.absoluteString)")
                decisionHandler(.cancel)
                self.loadPhishingWarning(for: url)
                return
            }
        }
        
        // 2. SMART HTTPS UPGRADE
        if url.scheme == "http" && !host.isEmpty {
            if self.bypassedHTTPHosts.contains(host) {
                decisionHandler(.allow)
                return
            } else {
                print("🔄 Upgrade automatique vers HTTPS pour : \(host)")
                decisionHandler(.cancel)
                
                var components = URLComponents(url: url, resolvingAgainstBaseURL: true)
                components?.scheme = "https"
                if let secureURL = components?.url {
                    webView.load(URLRequest(url: secureURL))
                }
                return
            }
        }
        
        decisionHandler(.allow)
    }

    // Fonction pour vérifier si un hôte est un traqueur (à implémenter)
    func isTracker(host: String) -> Bool {
        // Exemple simple : vérifier si l'hôte est dans une liste de domaines de traqueurs
        let trackerDomains = [
            "google-analytics.com",
            "doubleclick.net",
            "facebook.com",
            "twitter.com",
            "adservice.google.com",
            "ads.google.com",
            "googletagmanager.com",
            "googleadservices.com",
            "googlesyndication.com",
            "adwords.google.com",
            "assoc-amazon.com",
            "ads.microsoft.com",
            "atdmt.com",
            "adnexus.net",
            "amazon-adsystem.com",
            "criteo.com",
            "criteo.net",
            "adnxs.com",
            "appnexus.com",
            "advertising.com",
            "taboola.com",
            "taboola.net",
            "outbrain.com",
            "adroll.com",
            "adroll.net",
            "demdex.net",
            "mixpanel.com",
            "heap.io",
            "hotjar.com",
            "smartlook.com",
            "t.co",
            "analytics.twitter.com",
            "pinit.js",
            "sc-static.net",
            "byteoversea.com",
            "track.hubspot.com",
            "sfdcstatic.com",
            "mktto.com",
            "rlcdn.com",
            "adsrvr.org",
            "media.net",
            "ytimg.com",
            "f.vimeocdn.com",
            "distillery.wistia.com",
            "secure.brightcove.com",
            "content.jwplatform.com",
            "scdn.co",
            "sndcdn.com",
            "list-manage.com",
            "optimizelycdn.com",
            "dev.visualwebsiteoptimizer.com",
            "cdn.segment.com",
            "tags.tiqcdn.com",
            "mc.yandex.ru",
            "hm.baidu.com",
            "adobe-analytics2.js",
            "facebook.com/tr",
            "google-analytics.com/collect",
            "googletagmanager.com/gtm.js",
            "linkedin.com/px",
            "twitter.com/widgets",
            "facebook.com/plugins",
            "matomo.php",
            "piwik.php",
            "sdelivr.net",
        ]
        return trackerDomains.contains(host)
    }
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            
            // On vérifie que le challenge concerne bien la sécurité du serveur (SSL/TLS)
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
               let serverTrust = challenge.protectionSpace.serverTrust {
                
                let host = challenge.protectionSpace.host
                
                // 1. Sauvegarde des infos pour notre bouton "Détails techniques"
                // On ne le fait que si c'est l'onglet actuellement affiché
                if webView == tabs[currentTabIndex] {
                    self.sslCertificateInfo = extractCertificateData(trust: serverTrust)
                    
                    // Mise à jour de l'icône du cadenas sur le thread principal
                    DispatchQueue.main.async { 
                        self.updateSecurityIcon(url: webView.url) 
                    }
                }
                
                // 2. VÉRIFICATION DU BYPASS SSL (Le secret pour le bouton "Continuer quand même")
                // Si l'utilisateur a accepté le risque pour ce site invalide, on force WebKit à l'accepter !
                if self.bypassedSSLHosts.contains(host) {
                    print("SSL Bypassé manuellement pour : \(host)")
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    return
                }
            }
            completionHandler(.performDefaultHandling, nil)
        }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        print("Le processus web a crashé (Mémoire saturée). Rechargement automatique...");
        webView.reload()
    }
}


extension BrowserViewController: UITextFieldDelegate {
    
    
    func textFieldDidBeginEditing(_ textField: UITextField) {
        if let url = tabs[currentTabIndex].url {
            let absString = url.absoluteString
            textField.text = (absString == "about:blank") ? "" : absString
        }
        textField.selectAll(nil)
    }

    func textFieldDidEndEditing(_ textField: UITextField) {
        
        
        if tabs[currentTabIndex].url != nil && !textField.isFirstResponder {
            if let url = tabs[currentTabIndex].url {
                textField.text = getDisplayDomain(from: url)
            }
        }
    }
    
}

extension BrowserViewController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return suggestions.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "SuggestionCell", for: indexPath)
        cell.textLabel?.text = suggestions[indexPath.row]
        cell.textLabel?.textColor = isDarkMode ? .white : .black
        cell.backgroundColor = isDarkMode ? .darkGray : .white
        cell.selectionStyle = .gray
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        addressBar.text = suggestions[indexPath.row]
        loadWebsite()
        addressBar.resignFirstResponder()
        tableView.deselectRow(at: indexPath, animated: true)
    }
    
    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return 44
    }
}

extension UIColor {
    convenience init?(hex: String) {
        var hexSanitized = hex.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "#", with: "")
        if hexSanitized.count == 6 {
            hexSanitized = "FF" + hexSanitized
        }
        guard hexSanitized.count == 8 else { return nil }
        var rgb: UInt64 = 0
        Scanner(string: hexSanitized).scanHexInt64(&rgb)
        let a = CGFloat((rgb & 0xFF000000) >> 24) / 255.0
        let r = CGFloat((rgb & 0x00FF0000) >> 16) / 255.0
        let g = CGFloat((rgb & 0x0000FF00) >> 8) / 255.0
        let b = CGFloat(rgb & 0x000000FF) / 255.0
        self.init(red: r, green: g, blue: b, alpha: a)
    }
}

extension CABasicAnimation {
    convenience init(keyPath: String, configuration: (CABasicAnimation) -> Void) {
        self.init(keyPath: keyPath)
        configuration(self)
    }
}

class ReaderViewController: UIViewController {
    var articleTitle: String = ""
    var articleContent: String = ""
    var isDarkMode: Bool = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let webView = WKWebView(frame: view.bounds)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        
        webView.scrollView.showsHorizontalScrollIndicator = false
        view.addSubview(webView)
        
        let bgColor = isDarkMode ? "#1e1e1e" : "#fbfbfb"
        let textColor = isDarkMode ? "#d4d4d4" : "#222222"
        let linkColor = isDarkMode ? "#8ab4f8" : "#1a73e8"
        
                let html = """
                <!DOCTYPE html>
                <html>
                <head>
                <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
                <style>
                    :root { color-scheme: \(isDarkMode ? "dark" : "light"); }
                    body {
                        font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        background-color: \(bgColor);
                        color: \(textColor);
                        padding: 5% 8%;
                        line-height: 1.8;
                        font-size: 19px;
                        max-width: 800px;
                        margin: auto;
                        word-wrap: break-word;
                    }
                    h1 { 
                        font-family: "Georgia", serif; 
                        font-size: 32px; 
                        font-weight: bold; 
                        margin-bottom: 30px; 
                        line-height: 1.3;
                    }
                    p { margin-bottom: 20px; }
                    
                    /* Améliorations visuelles pour Readability */
                    img, video, iframe { 
                        max-width: 100%; 
                        height: auto; 
                        border-radius: 8px; 
                        margin: 20px 0;
                        display: block;
                    }
                    a { color: \(linkColor); text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    
                    /* Belles citations */
                    blockquote {
                        border-left: 4px solid \(linkColor);
                        margin: 20px 0;
                        padding-left: 15px;
                        font-style: italic;
                        color: \(isDarkMode ? "#aaaaaa" : "#555555");
                        background: \(isDarkMode ? "#2a2a2a" : "#f9f9f9");
                        padding: 15px;
                        border-radius: 0 8px 8px 0;
                    }
                    
                    /* Code et texte préformaté */
                    pre, code {
                        background: \(isDarkMode ? "#2a2a2a" : "#f4f4f4");
                        padding: 4px 8px;
                        border-radius: 5px;
                        font-family: Menlo, Monaco, Consolas, monospace;
                        font-size: 15px;
                    }
                    pre {
                        overflow-x: auto;
                        padding: 15px;
                    }
                    
                    figure { margin: 0; padding: 0; }
                    figcaption { font-size: 14px; color: gray; text-align: center; margin-top: 5px; }
                    
                    /* Masquer certains éléments inutiles laissés par le site */
                    .page-element-to-hide { display: none; }
                </style>
                </head>
                <body>
                    <h1>\(articleTitle)</h1>
                    \(articleContent)
                </body>
                </html>
                """ 
        
        webView.loadHTMLString(html, baseURL: nil)
        
        title = "Readability"
        let closeAction = UIAction { _ in self.dismiss(animated: true) }
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Fermer", primaryAction: closeAction)
        
        navigationController?.navigationBar.barTintColor = isDarkMode ? UIColor(red: 0.1, green: 0.1, blue: 0.1, alpha: 1) : .white
        navigationController?.navigationBar.titleTextAttributes = [.foregroundColor: isDarkMode ? UIColor.white : UIColor.black]
    }
}

let viewController = BrowserViewController()
viewController.preferredContentSize = CGSize(width: 800, height: 600)
PlaygroundPage.current.liveView = viewController
PlaygroundPage.current.needsIndefiniteExecution = true






