import Foundation
import AVFoundation
import CoreAudio
import os.log

/// Monitors microphone and camera activation (OverSight-inspired).
/// Uses CoreAudio property listeners for mic, AVCaptureDevice for camera.
@MainActor
public final class AVMonitor: ObservableObject {
    public static let shared = AVMonitor()

    @Published public private(set) var events: [AVDeviceEvent] = []
    @Published public private(set) var activeMicrophones: Set<String> = []
    @Published public private(set) var activeCameras: Set<String> = []

    private let logger = Logger(subsystem: "com.wudan.iris", category: "AVMonitor")
    private var audioListeners: [AudioObjectID: AudioObjectPropertyListenerBlock] = [:]
    private var isMonitoring = false
    private let eventQueue = DispatchQueue(label: "com.wudan.iris.avmonitor", qos: .userInitiated)
    private let maxEvents = 200

    private var deviceNotificationObservers: [NSObjectProtocol] = []

    public func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        logger.info("Starting AV monitoring")

        registerMicrophoneListeners()
        registerDeviceNotifications()
        pollCameraState()
    }

    public func stopMonitoring() {
        guard isMonitoring else { return }
        isMonitoring = false
        removeAllListeners()
        for observer in deviceNotificationObservers {
            NotificationCenter.default.removeObserver(observer)
        }
        deviceNotificationObservers.removeAll()
        logger.info("Stopped AV monitoring")
    }

    // MARK: - Microphone Monitoring via CoreAudio

    private func registerMicrophoneListeners() {
        let devices = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInMicrophone, .externalUnknown],
            mediaType: .audio,
            position: .unspecified
        ).devices

        for device in devices {
            let deviceID = getAudioObjectID(for: device)
            guard deviceID != kAudioObjectUnknown else { continue }

            var address = AudioObjectPropertyAddress(
                mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
                mScope: kAudioObjectPropertyScopeGlobal,
                mElement: kAudioObjectPropertyElementMain
            )

            let deviceName = device.localizedName
            let deviceUID = device.uniqueID

            let block: AudioObjectPropertyListenerBlock = { [weak self] _, _ in
                Task { @MainActor [weak self] in
                    self?.handleMicStateChange(
                        deviceID: deviceID,
                        deviceName: deviceName,
                        deviceUID: deviceUID
                    )
                }
            }

            let status = AudioObjectAddPropertyListenerBlock(
                deviceID, &address, eventQueue, block
            )

            if status == noErr {
                audioListeners[deviceID] = block
                logger.debug("Registered mic listener for \(deviceName)")
            }
        }
    }

    private func handleMicStateChange(deviceID: AudioObjectID, deviceName: String, deviceUID: String) {
        let isRunning = getMicState(deviceID: deviceID)

        if isRunning {
            activeMicrophones.insert(deviceUID)
        } else {
            activeMicrophones.remove(deviceUID)
        }

        let event = AVDeviceEvent(
            deviceType: .microphone,
            deviceName: deviceName,
            deviceUID: deviceUID,
            isActive: isRunning
        )
        appendEvent(event)
    }

    private func getMicState(deviceID: AudioObjectID) -> Bool {
        var address = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )
        var isRunning: UInt32 = 0
        var size = UInt32(MemoryLayout<UInt32>.size)

        let status = AudioObjectGetPropertyData(
            deviceID, &address, 0, nil, &size, &isRunning
        )
        return status == noErr && isRunning != 0
    }

    private func getAudioObjectID(for device: AVCaptureDevice) -> AudioObjectID {
        // Use the device's uniqueID to find the matching AudioObject
        var address = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyDevices,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )
        var size: UInt32 = 0
        AudioObjectGetPropertyDataSize(
            AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &size
        )

        let deviceCount = Int(size) / MemoryLayout<AudioDeviceID>.size
        var deviceIDs = [AudioDeviceID](repeating: 0, count: deviceCount)
        AudioObjectGetPropertyData(
            AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &size, &deviceIDs
        )

        for audioID in deviceIDs {
            var uidAddress = AudioObjectPropertyAddress(
                mSelector: kAudioDevicePropertyDeviceUID,
                mScope: kAudioObjectPropertyScopeGlobal,
                mElement: kAudioObjectPropertyElementMain
            )
            var uid: CFString = "" as CFString
            var uidSize = UInt32(MemoryLayout<CFString>.size)

            if AudioObjectGetPropertyData(audioID, &uidAddress, 0, nil, &uidSize, &uid) == noErr {
                if (uid as String) == device.uniqueID {
                    return audioID
                }
            }
        }
        return kAudioObjectUnknown
    }

    // MARK: - Camera Monitoring via Polling

    private func pollCameraState() {
        guard isMonitoring else { return }

        let cameras = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInWideAngleCamera, .externalUnknown],
            mediaType: .video,
            position: .unspecified
        ).devices

        for camera in cameras {
            // AVCaptureDevice doesn't have a direct "in use" property observable
            // from outside the capturing process. We check system log or use
            // notification center for connect/disconnect events.
            // For now, track via connection notifications.
            _ = camera
        }

        // Re-poll every 2 seconds
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(2))
            self?.pollCameraState()
        }
    }

    // MARK: - Device Connection/Disconnection

    private func registerDeviceNotifications() {
        let connectObserver = NotificationCenter.default.addObserver(
            forName: .AVCaptureDeviceWasConnected,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let device = notification.object as? AVCaptureDevice else { return }
            let deviceType: AVDeviceType = device.hasMediaType(.audio) ? .microphone : .camera
            let event = AVDeviceEvent(
                deviceType: deviceType,
                deviceName: device.localizedName,
                deviceUID: device.uniqueID,
                isActive: true
            )
            self?.appendEvent(event)
            self?.logger.info("Device connected: \(device.localizedName)")
        }

        let disconnectObserver = NotificationCenter.default.addObserver(
            forName: .AVCaptureDeviceWasDisconnected,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let device = notification.object as? AVCaptureDevice else { return }
            let deviceType: AVDeviceType = device.hasMediaType(.audio) ? .microphone : .camera
            let event = AVDeviceEvent(
                deviceType: deviceType,
                deviceName: device.localizedName,
                deviceUID: device.uniqueID,
                isActive: false
            )
            self?.appendEvent(event)
            self?.logger.info("Device disconnected: \(device.localizedName)")
        }

        deviceNotificationObservers.append(connectObserver)
        deviceNotificationObservers.append(disconnectObserver)
    }

    // MARK: - Helpers

    private func appendEvent(_ event: AVDeviceEvent) {
        events.insert(event, at: 0)
        if events.count > maxEvents {
            events.removeLast(events.count - maxEvents)
        }
    }

    private func removeAllListeners() {
        for (deviceID, block) in audioListeners {
            var address = AudioObjectPropertyAddress(
                mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
                mScope: kAudioObjectPropertyScopeGlobal,
                mElement: kAudioObjectPropertyElementMain
            )
            AudioObjectRemovePropertyListenerBlock(deviceID, &address, eventQueue, block)
        }
        audioListeners.removeAll()
    }
}
