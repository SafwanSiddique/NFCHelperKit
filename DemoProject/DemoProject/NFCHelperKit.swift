//
//  nfcHelperKit.swift
//  NFC Tools
//
//  Created by Safwan on 07/02/2024.
//

import UIKit
import CoreNFC

enum DataType: Identifiable {
    case Url, Text, Contact, Email, Location, Call, Message, Socials, Wifi
    
    var id: Int {
        hashValue
    }
}

enum NFCAction: Identifiable {
    
    case SingleWriteTag, SetTagPassword, RemoveTagPassword, ReadTag, EraseTag, LockTag
    
    var id: Int {
        hashValue
    }
}

//MARK: NFC Ease of access Methods
extension NFCHelperKit {
    func lockTagWithoutData(password: String, completion: @escaping (_ error: String?) -> Void) {
        if password.count != 4 {
            completion("The password must be a 4 digits")
            return
        }
        
        if !password.allSatisfy({ $0.isNumber }) {
            completion("The password must contain only numbers")
        }
        
        self.password = password
        self.nfcAction = .SetTagPassword
        self.startNDEFSession()
        
        completion(nil)
        return
    }
    
    func unlockTag(password: String, completion: @escaping (_ error: String?) -> Void) {
        if password.count != 4 {
            completion("The password must be a 4 digits")
            return
        }
        
        if !password.allSatisfy({ $0.isNumber }) {
            completion("The password must contain only numbers")
        }
        
        self.password = password
        self.nfcAction = .RemoveTagPassword
        self.startNDEFSession()
        
        completion(nil)
        return
    }
}

//MARK: Underlying Implementation
class NFCHelperKit: UIViewController {
    
    public static var shared = NFCHelperKit()
    var session: NFCTagReaderSession?
    var detectedMessages = [NFCNDEFMessage]()
    
    var nfcAction: NFCAction!
    var tagData = [String]()
    var dataType: DataType!
    var password = ""
    
    var singleWriteCompleted:(()->Void)?
//    var readSuccess:((_ tagData: Tag_Details)->Void)?
    var succesfulWritePrompt = "Tag Configured Successfully"
    
    
    func startNDEFSession() {
        
        guard NFCNDEFReaderSession.readingAvailable else {
            
            let alert = UIAlertController(title: "Scanning Not Supported", message: "This device doesn't support tag scanning.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
            return
        }
        
        self.session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: DispatchQueue.main)
        self.session?.alertMessage = "Hold your iPhone near the item to learn more about it."
        self.session?.begin()
    }
    
    func parseCompleteURINFC(_ data: Data) -> String {
        guard let prefixByte = data.first else { return "error" }
        let rest = data.dropFirst()

        let uriPrefix: String? = {
            switch prefixByte {
            case 0x00: return nil // No prefix
            case 0x01: return "http://www."
            case 0x02: return "https://www."
            case 0x03: return "http://"
            case 0x04: return "https://"
            case 0x05: return "tel:"
            case 0x06: return "mailto:"
            case 0x07: return "ftp://anonymous:anonymous@"
            case 0x08: return "ftp://ftp."
            case 0x09: return "ftps://"
            case 0x0A: return "sftp://"
            case 0x0B: return "smb://"
            case 0x0C: return "nfs://"
            case 0x0D: return "ftp://"
            case 0x0E: return "dav://"
            case 0x0F: return "news:"
            case 0x10: return "telnet://"
            case 0x11: return "imap:"
            case 0x12: return "rtsp://"
            case 0x13: return "urn:"
            case 0x14: return "pop:"
            case 0x15: return "sip:"
            case 0x16: return "sips:"
            case 0x17: return "tftp:"
            case 0x18: return "btspp://"
            case 0x19: return "btl2cap://"
            case 0x1A: return "btgoep://"
            case 0x1B: return "tcpobex://"
            case 0x1C: return "irdaobex://"
            case 0x1D: return "file://"
            case 0x1E: return "urn:epc:id:"
            case 0x1F: return "urn:epc:tag:"
            case 0x20: return "urn:epc:pat:"
            case 0x21: return "urn:epc:raw:"
            case 0x22: return "urn:epc:"
            case 0x23: return "urn:nfc:"
            default: return ""
            }
        }()

        guard let prefix = uriPrefix, let restString = String(data: rest, encoding: .utf8) else { return "error" }
        return prefix + restString
    }

    
}

extension NFCHelperKit: NFCTagReaderSessionDelegate {
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("tagReaderSessionDidBecomeActive")
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        print( "tagReaderSession:didInvalidateWithError - \(error)" )
    }

    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        
        switch nfcAction {
            //MARK: Single Write Tag
        case .SingleWriteTag:
            print("CASE - single write tag")
                
            switch tags.first! {
            case .iso7816(_):
                print("iso7816")
                break
            case .feliCa(_):
                print("feliCa")
                break
            case .iso15693(_):
                print("iso15693")
                break
            case let .miFare(tag):
                let mifare: NFCMiFareTag = tag
                
                session.connect(to: tags.first!) { (error: Error?) in
                    if error != nil {
                        session.invalidate(errorMessage: "Connection error. Please try again.")
                        return
                    }
                    tag.queryNDEFStatus() { (status: NFCNDEFStatus, capacity: Int, error: Error?) in
                        if error != nil {
                            session.invalidate(errorMessage: "Fail to determine NDEF status.  Please try again.")
                            return
                        }
                        if status == .readOnly {
                            session.invalidate(errorMessage: "Tag is Read-Only")
                            return
                        }
                        
                        let readInfoCMD = Data(bytes: [0x60], count: 1)
                        
                        mifare.sendMiFareCommand(commandPacket: readInfoCMD) { response, error in
                            if error != nil {
                                session.invalidate(errorMessage: "Failed to Unlock Tag")
                                return
                            }
                            
                            //Checking if Tag is password protected
                            var passwordCheck = [UInt8]()
                            if response[response.count - 2] == 17 {
                                passwordCheck = [0x30, 0x83]
                            } else if response[response.count - 2] == 15 {
                                passwordCheck = [0x30, 0x29]
                            } else if response[response.count - 2] == 19 {
                                passwordCheck = [0x30, 0xE3]
                            }
                            let pwdCheckCmd = Data(bytes: passwordCheck, count: passwordCheck.count)
                            mifare.sendMiFareCommand(commandPacket: pwdCheckCmd) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Unlock Tag")
                                    return
                                }
                                print(response as NSData)
                                let str = response.map { String(format: "%.hx", $0) }.joined()
                                print(str)
                                if !(str.contains("ff")) {
//                                    self.isLocked?(false)
                                    session.invalidate(errorMessage: "This Tag is Password Protected")
                                }
                            }
                            
                            var records = [NFCNDEFPayload]()
                            
                            switch self.dataType {
                                
                            case .Url, .Text, .Email, .Location, .Call, .Message, .Socials:
                                for urlString in self.tagData {
                                    if let url = URL(string: urlString),
                                       let payload = NFCNDEFPayload.wellKnownTypeURIPayload(url: url) {
                                        records.append(payload)
                                    } else {
                                        let textData = urlString.data(using: .utf8)!
                                        let locale = Locale.current
                                        let languageCode = locale.identifier.prefix(2).lowercased()
                                        let languageCodeData = languageCode.data(using: .ascii)!
                                        let payloadData = Data([UInt8(languageCodeData.count)]) + languageCodeData + textData
                                        
                                        let payload = NFCNDEFPayload(format: .nfcWellKnown, type: "T".data(using: .ascii)!, identifier: Data(), payload: payloadData)
                                        records.append(payload)
                                    }
                                }
                                
                            case .Contact:
                                for contactString in self.tagData {
                                    guard let vCardData = contactString.data(using: .utf8) else { continue }
                                    
                                    let mimeType = "text/vcard".data(using: .ascii)!
                                    let payload = NFCNDEFPayload(format: .media, type: mimeType, identifier: Data(), payload: vCardData)
                                    records.append(payload)
                                }
                                
                            case .Wifi:
                                for wifiInfo in self.tagData {
                                    let type = "application/vnd.wfa.wsc".data(using: .utf8)!
                                    
                                    _ = ["Open", "WPA-Personal", "Shared", "WPA-Enterprise", "WPA2-Enterprise", "WPA2-Personal"]
                                    _ = ["None", "WEP", "TKIP", "AES", "AES/TKIP (mixed)"]
                                    
                                    let authenticationTypes: [[UInt8]] = [[0x00, 0x01], [0x00, 0x02], [0x00, 0x04], [0x00, 0x08], [0x00, 0x10], [0x00, 0x20]]
                                    let encryptionTypes: [[UInt8]] = [[0x00, 0x01], [0x00, 0x02], [0x00, 0x04], [0x00, 0x08], [0x00, 0x0c]]
                                    
                                    
                                    
                                    let ssidString = "Horizam_5G"
                                    let networkKeyString = "hroizam66"
                                    
                                    let ssidBytes: [UInt8] = Array(ssidString.utf8)
                                    let networkKeyBytes: [UInt8] = Array(networkKeyString.utf8)
                                    
                                    let ssidLength = UInt8(ssidBytes.count)
                                    let networkKeyLength = UInt8(networkKeyBytes.count)
                                    
                                    let authenticationTypeBytes = authenticationTypes[5]
                                    let encryptionTypeBytes = encryptionTypes[0]
                                    
                                    let networkIndex: [UInt8]       = [0x10, 0x26, 0x00, 0x01, 0x01]
                                    let ssid: [UInt8]               = [0x10, 0x45, 0x00, ssidLength] + ssidBytes
                                    let authenticationType: [UInt8] = [0x10, 0x03, 0x00, 0x02] + authenticationTypeBytes
                                    let encryptionType: [UInt8]     = [0x10, 0x0F, 0x00, 0x02] + encryptionTypeBytes
                                    let networkKey: [UInt8]         = [0x10, 0x27, 0x00, networkKeyLength] + networkKeyBytes
                                    let macAddress: [UInt8]         = [0x10, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                                    
                                    let credential = networkIndex + ssid + authenticationType + encryptionType + networkKey + macAddress
                                    let credentialLength = UInt8(credential.count)
                                    
                                    let bytes = [0x10, 0x0E, 0x00, credentialLength] + credential
                                    let payload = Data(bytes: bytes, count: bytes.count)
                                    
                                    let ndefPayload = NFCNDEFPayload(format: .media, type: type, identifier: Data(), payload: payload)
                                    
                                    let ndefMessage = NFCNDEFMessage.init(records: [ndefPayload])
                                    
                                    //        guard let uriPayloadFromURL = NFCNDEFPayload.wellKnownTypeURIPayload( string: writeToTag ) else {
                                    //            return
                                    //        }
                                    
                                    //        print("Profile Url: ",writeToTag)
                                    //       print("url of payload: ",uriPayloadFromURL)
                                    
                                    
                                    // Code to Turn OFF Tap Count and Mirror
                                    let offCounter: [UInt8] = [0xA2, 0x84, 0x00, 0x05, 0x00, 0x00]
                                    let offMirror: [UInt8] = [0xA2, 0x83, 0x04, 0x00, 0x00, 0xFF]
                                    let offCounter213: [UInt8] = [0xA2, 0x2A, 0x00, 0x05, 0x00, 0x00]
                                    let offMirror213: [UInt8] = [0xA2, 0x29, 0x04, 0x00, 0x00, 0xFF]
                                    
                                    let offCounterCMD = Data(bytes: offCounter, count: offCounter.count)
                                    let offMirrorCMD = Data(bytes: offMirror, count: offMirror.count)
                                    let offCounterCMD213 = Data(bytes: offCounter213, count: offCounter213.count)
                                    let offMirrorCMD213 = Data(bytes: offMirror213, count: offMirror213.count)
                                    
                                    //Disable Counter 213
                                    mifare.sendMiFareCommand(commandPacket: offCounterCMD213) { response, error in
                                        if nil != error{
                                            return
                                        }
                                        print(response as NSData)
                                        //session.alertMessage = "Tag Configured Successfully"
                                        //session.invalidate()
                                        
                                    }
                                    //Disable Mirror 213
                                    mifare.sendMiFareCommand(commandPacket: offMirrorCMD213) { response, error in
                                        if nil != error {
                                            return
                                        }
                                        
                                        print(response as NSData)
                                        //session.alertMessage = "Tag Configured Successfully"
                                        //session.invalidate()
                                    }
                                    
                                    
                                    
                                    //-------------
                                    
                                    //Disable Counter 215
                                    mifare.sendMiFareCommand(commandPacket: offCounterCMD) { response, error in
                                        if nil != error{
                                            return
                                        }
                                        print(response as NSData)
                                        //session.alertMessage = "Tag Configured Successfully"
                                        //session.invalidate()
                                        
                                    }
                                    //Disable Mirror 215
                                    mifare.sendMiFareCommand(commandPacket: offMirrorCMD) { response, error in
                                        if nil != error{
                                            return
                                        }
                                        
                                        print(response as NSData)
                                        //session.alertMessage = "Tag Configured Successfully"
                                        //session.invalidate()
                                    }
                                    
                                    records.append(ndefPayload)
                                }
                                
                            case .none:
                                break
                            }
                            
                            

                            if records.isEmpty {
                                session.invalidate(errorMessage: "No valid data to write")
                                return
                            }
                            
                            let messge = NFCNDEFMessage.init(records: records)
                            
                            mifare.writeNDEF(messge) { error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to write message")
                                } else  {
                                    session.alertMessage = self.succesfulWritePrompt
                                    self.singleWriteCompleted?()
                                }
                                session.invalidate()
                            }
                        }
                    }
                }
                break
            @unknown default :
                session.invalidate(errorMessage: "Tag not valid.")
                return
            }
            
        //MARK: Set Tag Password
        case .SetTagPassword:
            print("CASE - Set Tag Password")
            switch tags.first! {
            case .iso7816(_):
                print("iso7816")
                break
            case .feliCa(_):
                print("feliCa")
                break
            case .iso15693(_):
                print("iso15693")
                break
            case let .miFare(tag):
                let mifare: NFCMiFareTag = tag
                
                session.connect(to: tags.first!) { (error: Error?) in
                    if error != nil {
                        session.invalidate(errorMessage: "Connection error. Please try again.")
                        return
                    }
                    
                    tag.queryNDEFStatus() { (status: NFCNDEFStatus, capacity: Int, error: Error?) in
                        if error != nil {
                            session.invalidate(errorMessage: "Fail to determine NDEF status.  Please try again.")
                            return
                        }
                        if status == .readOnly {
                            session.invalidate(errorMessage: "Tag is Read-Only")
                            return
                        }
                        let uid = mifare.identifier.map { String(format: "%.2hhx", $0) }.joined()
                        print("UID: \(uid)")
                        
                        var enablePassword: [UInt8] = []
                        var setPassword: [UInt8] = []
                        var setPack: [UInt8] = []
                        
                        let readInfoCMD = Data(bytes: [0x60], count: 1)
                        mifare.sendMiFareCommand(commandPacket: readInfoCMD) { response, error in
                            if error != nil {
                                session.invalidate(errorMessage: "Failed to Unlock Tag")
                                return
                            }
                            
                            //Checking if Tag is password protected
                            var passwordCheck = [UInt8]()
                            if response[response.count - 2] == 17 {
                                passwordCheck = [0x30, 0x83]
                            } else if response[response.count - 2] == 15 {
                                passwordCheck = [0x30, 0x29]
                            } else if response[response.count - 2] == 19 {
                                passwordCheck = [0x30, 0xE3]
                            }
                            let pwdCheckCmd = Data(bytes: passwordCheck, count: passwordCheck.count)
                            mifare.sendMiFareCommand(commandPacket: pwdCheckCmd) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Unlock Tag")
                                    return
                                }
                                print(response as NSData)
                                let str = response.map { String(format: "%.hx", $0) }.joined()
                                print(str)
                                if !(str.contains("ff")) {
//                                    self.isLocked?(false)
                                    session.invalidate(errorMessage: "This Tag is Password Protected")
                                }
                            }
                            
                            print(response as NSData)
                            print("Tag Unlocked Successfully")
                            print("Results: /n", response.map { String(format: "%.hx", $0) }.joined())
                            
                            
                            if response[response.count - 2] == 17 {
                                enablePassword = [0xA2, 0x83, 0x04, 0x00, 0x00, 0x00]
                                setPassword = [0xA2, 0x85]
                                setPack = [0xA2, 0x86]
                            } else if response[response.count - 2] == 15 {
                                enablePassword = [0xA2, 0x29, 0x04, 0x00, 0x00, 0x00]
                                setPassword = [0xA2, 0x2B]
                                setPack = [0xA2, 0x2C]
                            } else if response[response.count - 2] == 19 {
                                enablePassword = [0xA2, 0xE3, 0x04, 0x00, 0x00, 0x00]
                                setPassword = [0xA2, 0xE5]
                                setPassword = [0xA2, 0xE6]
                            }
                            
                            //Data to write Enable Password
                            let enablePasswordCMD = Data(bytes: enablePassword, count: enablePassword.count)
                            //Data to Write on PWD
                            let setPasswordCMD = Data(bytes: setPassword, count: setPassword.count) + Data(self.password.data(using: .utf8)!)
                            //Data to Write on PACK
                            let passBitsForPack = [setPasswordCMD[2], setPasswordCMD[3]]
                            let bitsForRFUI = Data(bytes: [0x00, 0x00], count: 2)
                            var setPackCMD = Data(bytes: setPack, count: setPack.count)
                            setPackCMD.append(contentsOf: passBitsForPack)
                            setPackCMD.append(bitsForRFUI)
                            
                            
                            //-----Write URL to Tag
//                                guard let uriPayloadFromURL = NFCNDEFPayload.wellKnownTypeURIPayload(url: URL(string: self.tagData)!) else {
//                                    return
//                                }
//                                let messge = NFCNDEFMessage.init(records: [uriPayloadFromURL])
//                                mifare.writeNDEF(messge) { error in
//                                    if error != nil {
//                                        session.invalidate(errorMessage: "Failed to write message")
//                                    }
//                                }
                            mifare.sendMiFareCommand(commandPacket: setPasswordCMD) { response, error in
                                if error != nil {
                                    print(error?.localizedDescription ?? "")
                                    session.invalidate(errorMessage: "Failed to Write Password")
                                    return
                                }
                                print("Password Set Successfully")
                            }
                            mifare.sendMiFareCommand(commandPacket: setPackCMD) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Write PACK")
                                    return
                                }
                                print("PACK Set Successfully")
                                print(response as NSData)
                            }
                            mifare.sendMiFareCommand(commandPacket: enablePasswordCMD) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Enable Auth0")
                                    return
                                }
                                print(response as NSData)
                                print("Password Enabled Successfully")
                                session.alertMessage = "Password Enabled Tag Configured Successfully"
                                session.invalidate()
//                                self.delegate?.nfcWriteSuccessful()
                            }
                            self.password = ""
//                            self.isLockTag = false
                        }
                    }
                }
                break
            @unknown default :
                session.invalidate(errorMessage: "Tag not valid.")
                return
            }
            
        //MARK: Remove Tag Password:
        case .RemoveTagPassword:
            print("CASE - Remove Tag Password")
            
            switch tags.first! {
            case .iso7816(_):
                print("iso7816")
                break
            case .feliCa(_):
                print("feliCa")
                break
            case .iso15693(_):
                print("iso15693")
                break
            case let .miFare(tag):
                let mifare: NFCMiFareTag = tag
                
                session.connect(to: tags.first!) { (error: Error?) in
                    if error != nil {
                        session.invalidate(errorMessage: "Connection error. Please try again.")
                        return
                    }
                    tag.queryNDEFStatus() { (status: NFCNDEFStatus, capacity: Int, error: Error?) in
                        if error != nil {
                            session.invalidate(errorMessage: "Fail to determine NDEF status.  Please try again.")
                            return
                        }
                        if status == .readOnly {
                            session.invalidate(errorMessage: "Tag is Read-Only")
                            return
                        }
                        let uid = mifare.identifier.map { String(format: "%.2hhx", $0) }.joined()
                        print("UID: \(uid)")
                        
                        var disablePassword: [UInt8] = [0xA2, 0x29, 0x04, 0x00, 0x00, 0xFF]
                        let unlockTag: [UInt8] = [0x1B]
                        
                        let readInfoCMD = Data(bytes: [0x60], count: 1)
                        mifare.sendMiFareCommand(commandPacket: readInfoCMD) { response, error in
                            if error != nil {
                                session.invalidate(errorMessage: "Failed to Get determine Tag info")
                                return
                            }
                            print(response as NSData)
                            print("Results: /n", response.map { String(format: "%.hx", $0) }.joined())
                            if response[response.count - 2] == 17 {
                                disablePassword = [0xA2, 0x83, 0x04, 0x00, 0x00, 0xFF]
                            } else if response[response.count - 2] == 15 {
                                disablePassword = [0xA2, 0x29, 0x04, 0x00, 0x00, 0xFF]
                            } else if response[response.count - 2] == 19 {
                                disablePassword = [0xA2, 0xE3, 0x04, 0x00, 0x00, 0xFF]
                            }
                            
                            let unlockTagCMD = Data(bytes: unlockTag, count: unlockTag.count) + Data(self.password.data(using: .utf8)!)
                            let disablePasswordCMD = Data(bytes: disablePassword, count: disablePassword.count)
                            
                            mifare.sendMiFareCommand(commandPacket: unlockTagCMD) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Unlock Tag")
                                    return
                                }
                                self.password = ""
                                print(response as NSData)
                                print("Tag Unlocked Successfully")
                            }
                            
                            mifare.sendMiFareCommand(commandPacket: disablePasswordCMD) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Disable Password")
                                    return
                                }
                                print(response as NSData)
                                print("Password Disabled Successfully")
                                session.alertMessage = "Tag Unlocked Successfully"
                                session.invalidate()
                            }
                        }
                    }
                }
                break
            @unknown default :
                session.invalidate(errorMessage: "Tag not valid.")
                return
            }
            
        //MARK: Read Tag
        case .ReadTag:
            print("CASE - Read Tag")
            
            var mifare_type = "n/a"
            var iso_type = "n/a"
            var tag_type = "n/a"
            var memory_info = "n/a"
            var serial_NFC = "n/a"
            var used_size = 0
            var total_size = 0
            var read_only = false
            var password_protected = false
            
            if tags.count > 1 {
                
                session.alertMessage = "More Than one tag Detected, Please try again"
                session.invalidate()
            }
            switch tags.first! {
                
            case .iso7816(_):
                print("Tag iso7816")
            case .feliCa(_):
                print("Tag feliCa")
                
//                if case let NFCTag.feliCa(tag) = tags.first! {
//                    session.connect(to: tags.first!) { (error) in
//                        if error != nil {
//                            session.invalidate(errorMessage: "Connection failed.")
//                            return
//                        }
//
//                        // Specify the service code and block list you want to read
//                        let serviceCode = Data([0x09, 0x0f]) // Example service code
//                        let blockList = [Data([0x80, 0x00])] // Example block list
//
//                        tag.requestService(nodeCodeList: [serviceCode]) { nodes, error in
//                            if let error = error {
//                                session.invalidate(errorMessage: "Failed to request service: \(error.localizedDescription)")
//                                return
//                            }
//
//                            tag.readWithoutEncryption(serviceCodeList: [serviceCode], blockList: blockList) { status1, status2, blockData, error in
//                                if let error = error {
//                                    session.invalidate(errorMessage: "Read failed: \(error.localizedDescription)")
//                                    return
//                                }
//
//                                // Process the block data
//                                print("Block Data: \(blockData)")
//
//                                session.invalidate()
//                            }
//                        }
//                    }
//                }
            case .iso15693(_):
                print("Tag iso15693")
            case let .miFare(tag):
                let mifare: NFCMiFareTag = tag
                print(mifare.identifier)
                
                switch mifare.mifareFamily {
                case .unknown:
                    mifare_type = "ISO14443 Type A"
                case .desfire:
                    mifare_type = "MIFARE DESfire®"
                case .plus:
                    mifare_type = "MIFARE Plus®"
                case .ultralight:
                    mifare_type = "MIFARE Ultralight®"
                @unknown default:
                    print("")
                }

                let tag = tags.first!
//                let identifierData = self.extractIdentifier(from: tag)
//                                let identifierString = identifierData.map { String(format: "%02x", $0) }.joined()
//                                print("Tag Identifier: \(identifierString)")
                
            
                session.connect(to: tag) { (error) in
                    if error != nil {
                        
                        session.invalidate(errorMessage: error!.localizedDescription)
                    }
                    if case let .miFare(stag) = tag {
                        
                        print(tag)
                        stag.queryNDEFStatus { status, capacity, error in

                            guard error == nil else {
                                session.invalidate(errorMessage: "Unable to query the NDEF status of tag.")
                                return
                            }
                            
                            let uid = stag.identifier.map{ String(format: "%.2hhx", $0) }.joined()
                            print(uid)
                            serial_NFC = uid
                            serial_NFC = uid.capitalized
                            serial_NFC.insert(":", at: serial_NFC.index(serial_NFC.startIndex, offsetBy: 2))
                            serial_NFC.insert(":", at: serial_NFC.index(serial_NFC.startIndex, offsetBy: 2+3))
                            serial_NFC.insert(":", at: serial_NFC.index(serial_NFC.startIndex, offsetBy: 5+3))
                            serial_NFC.insert(":", at: serial_NFC.index(serial_NFC.startIndex, offsetBy: 8+3))
                            serial_NFC.insert(":", at: serial_NFC.index(serial_NFC.startIndex, offsetBy: 11+3))
                            serial_NFC.insert(":", at: serial_NFC.index(serial_NFC.startIndex, offsetBy: 14+3))
                            serial_NFC = serial_NFC.capitalized
                            
                            print(serial_NFC)
                            
                            if capacity != nil {
                                
                                print(capacity)
                            }
                            if status == .readOnly {
                                read_only = true
                            } else {
                                read_only = false
                            }
                            
                            let readInfoCMD = Data(bytes: [0x60], count: 1)
                            
                            mifare.sendMiFareCommand(commandPacket: readInfoCMD) { response, error in

                                if error != nil {
                                    return
                                }
                                
                                //Checking if Tag is password protected
                                var passwordCheck = [UInt8]()
                                if response[response.count - 2] == 17 {
                                    passwordCheck = [0x30, 0x83]
                                } else if response[response.count - 2] == 15 {
                                    passwordCheck = [0x30, 0x29]
                                } else if response[response.count - 2] == 19 {
                                    passwordCheck = [0x30, 0xE3]
                                }
                                let pwdCheckCmd = Data(bytes: passwordCheck, count: passwordCheck.count)

                                mifare.sendMiFareCommand(commandPacket: pwdCheckCmd) { response, error in

                                    if error != nil {
                                        print("----- command 2 error")
                                        return
                                    }
                                    print(response as NSData)
                                    let str = response.map { String(format: "%.hx", $0) }.joined()
                                    print(str)
                                    if !(str.contains("ff")) {
                                        password_protected = true
                                    } else {
                                        password_protected = false
                                    }
                                    
                                    stag.readNDEF { (message: NFCNDEFMessage?, error: Error?) in

                                        total_size = capacity
                                        used_size = message?.length ?? 0
                                        
                                        //checking card type based on memory sized
//                                        if capacity == 137 {
//                                            tag_type = "NTAG213"
//                                            memory_info = "180 Bytes, 45 Pages of 4 bytes each"
//                                            iso_type = "ISO 14443-3A"
//                                        } else if capacity == 492 {
//                                            tag_type = "NTAG215"
//                                            memory_info = "540 Bytes, 135 Pages of 4 bytes each"
//                                            iso_type = "ISO 14443-3A"
//                                        } else if capacity >= 872 && capacity <= 880 { //need to fix this when i get a 216
//                                            tag_type = "NTAG216"
//                                            memory_info = "924 Bytes, 231 Pages of 4 bytes each"
//                                            iso_type = "ISO 14443-3A"
//                                        }
                                        
                                        if nil != error || nil == message {
                                            
                                        } else {
                                            //                                            let payload = message!.records.first
                                            var dataArray = [String]()
                                            
                                            
                                            for payload in message!.records {
                                
                                                if  message!.length > 3 {
                                                    
                                                    if let dataRead = payload.wellKnownTypeURIPayload() {
                                                        dataArray.append(dataRead.description)
                                                    } else {
                                                        if let dataRead = payload.wellKnownTypeTextPayload().0 {
                                                            dataArray.append(dataRead)
                                                        } else {
                                                            let dataRead = String(data: payload.payload, encoding: .ascii)!
                                                            dataArray.append(dataRead)
                                                        }
                                                    }
                                                    
                                                    session.alertMessage = "Tag Read Successfully"
                                                    
                                                    
                                                    
                                                    
                                                }
                                            }
                                            DispatchQueue.main.async {
//                                                let tagData = Tag_Details(records: dataArray, serialNumber: serial_NFC, isLocked: read_only, isPasswordProteced: password_protected, usedSize: used_size, totalSize: total_size, tagType: tag_type, memoryInfo: memory_info, mifareType: mifare_type, isoType: iso_type)
//                                                self.readSuccess?(tagData)
                                            }
                                            session.invalidate()
                                            
                                            
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
        //MARK: Erase Tag
        case .EraseTag:
            print("CASE - Erase Tag")
                
            switch tags.first! {
            case .iso7816(_):
                print("iso7816")
                break
            case .feliCa(_):
                print("feliCa")
                break
            case .iso15693(_):
                print("iso15693")
                break
            case let .miFare(tag):
                let mifare: NFCMiFareTag = tag
                
                session.connect(to: tags.first!) { (error: Error?) in
                    if error != nil {
                        session.invalidate(errorMessage: "Connection error. Please try again.")
                        return
                    }
                    tag.queryNDEFStatus() { (status: NFCNDEFStatus, capacity: Int, error: Error?) in
                        if error != nil {
                            session.invalidate(errorMessage: "Fail to determine NDEF status.  Please try again.")
                            return
                        }
                        if status == .readOnly {
                            session.invalidate(errorMessage: "Tag is Read-Only")
                            return
                        }
                        
                        let readInfoCMD = Data(bytes: [0x60], count: 1)
                        
                        mifare.sendMiFareCommand(commandPacket: readInfoCMD) { response, error in
                            if error != nil {
                                session.invalidate(errorMessage: "Failed to Unlock Tag")
                                return
                            }
                            
                            //Checking if Tag is password protected
                            var passwordCheck = [UInt8]()
                            if response[response.count - 2] == 17 {
                                passwordCheck = [0x30, 0x83]
                            } else if response[response.count - 2] == 15 {
                                passwordCheck = [0x30, 0x29]
                            } else if response[response.count - 2] == 19 {
                                passwordCheck = [0x30, 0xE3]
                            }
                            let pwdCheckCmd = Data(bytes: passwordCheck, count: passwordCheck.count)
                            mifare.sendMiFareCommand(commandPacket: pwdCheckCmd) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Unlock Tag")
                                    return
                                }
                                print(response as NSData)
                                let str = response.map { String(format: "%.hx", $0) }.joined()
                                print(str)
                                if !(str.contains("ff")) {
//                                    self.isLocked?(false)
                                    session.invalidate(errorMessage: "This Tag is Password Protected")
                                }
                            }
                            
                            
                            var records = [NFCNDEFPayload]()
                            let messge = NFCNDEFMessage.init(records: records)
                            
                            mifare.writeNDEF(messge) { error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to write message")
                                } else  {
                                    session.alertMessage = "Tag Erased Successfully"
                                }
                                session.invalidate()
                            }
                        }
                    }
                }
                break
            @unknown default :
                session.invalidate(errorMessage: "Tag not valid.")
                return
            }
        
        //MARK: Lock Tag
        case .LockTag:
            print("CASE - Lock Tag")
                
            switch tags.first! {
            case .iso7816(_):
                print("iso7816")
                break
            case .feliCa(_):
                print("feliCa")
                break
            case .iso15693(_):
                print("iso15693")
                break
            case let .miFare(tag):
                let mifare: NFCMiFareTag = tag
                
                session.connect(to: tags.first!) { (error: Error?) in
                    if error != nil {
                        session.invalidate(errorMessage: "Connection error. Please try again.")
                        return
                    }
                    tag.queryNDEFStatus() { (status: NFCNDEFStatus, capacity: Int, error: Error?) in
                        if error != nil {
                            session.invalidate(errorMessage: "Fail to determine NDEF status.  Please try again.")
                            return
                        }
                        if status == .readOnly {
                            session.invalidate(errorMessage: "Tag is Read-Only")
                            return
                        }
                        
                        let readInfoCMD = Data(bytes: [0x60], count: 1)
                        
                        mifare.sendMiFareCommand(commandPacket: readInfoCMD) { response, error in
                            if error != nil {
                                session.invalidate(errorMessage: "Failed to Unlock Tag")
                                return
                            }
                            
                            //Checking if Tag is password protected
                            var passwordCheck = [UInt8]()
                            if response[response.count - 2] == 17 {
                                passwordCheck = [0x30, 0x83]
                            } else if response[response.count - 2] == 15 {
                                passwordCheck = [0x30, 0x29]
                            } else if response[response.count - 2] == 19 {
                                passwordCheck = [0x30, 0xE3]
                            }
                            let pwdCheckCmd = Data(bytes: passwordCheck, count: passwordCheck.count)
                            mifare.sendMiFareCommand(commandPacket: pwdCheckCmd) { response, error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to Unlock Tag")
                                    return
                                }
                                print(response as NSData)
                                let str = response.map { String(format: "%.hx", $0) }.joined()
                                print(str)
                                if !(str.contains("ff")) {
                                    session.invalidate(errorMessage: "This Tag is Password Protected")
                                }
                            }
                            
                            
                            mifare.writeLock { error in
                                if error != nil {
                                    session.invalidate(errorMessage: "Failed to lock tag")
                                } else  {
                                    session.alertMessage = "Tag Locked Successfully"
                                }
                                session.invalidate()
                            }
                        }
                    }
                }
                break
            @unknown default :
                session.invalidate(errorMessage: "Tag not valid.")
                return
            }
        
            
        case .none:
            print("CASE - none")
            break
            
        }
    }
    
    
}
