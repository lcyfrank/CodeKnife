permission_pairs = {
    'NSBluetoothPeripheralUsageDescription': 'Access Bluetooth',
    'NFCReaderUsageDescription': 'Access NFC Reader',
    'NSAppleMusicUsageDescription': 'Access Media Library',
    'NSCalendarsUsageDescription': 'Access User\'s Calendars',
    'NSCameraUsageDescription': 'Access Device\'s Camera',
    'NSContactsUsageDescription': 'Access User\'s Contact',
    'NSFaceIDUsageDescription': 'Access Face ID',
    'NSHealthClinicalHealthRecordsShareUsageDescription': 'Access User\'s Clinical Health Records',
    'NSHealthShareUsageDescription': 'Access User\'s Health Data',
    'NSHealthUpdateUsageDescription': 'Modify User\'s Health Data',
    'NSHomeKitUsageDescription': 'Access User\'s HomeKit Configuration Data',
    'NSLocationAlwaysUsageDescription': 'Access User\'s Location Information at All Times',
    'NSLocationUsageDescription': 'Access User\'s Location Information',
    'NSLocationWhenInUseUsageDescription': 'Access User\'s Location While App is in Use',
    'NSMicrophoneUsageDescription': 'Access Device\'s Microphones',
    'NSMotionUsageDescription': 'Access Device\'s Accelerometer',
    'NSPhotoLibraryAddUsageDescription': 'Access User\'s Photo Library (Write-Only)',
    'NSPhotoLibraryUsageDescription': 'Access User\'s Photo Library',
    'NSRemindersUsageDescription': 'Access User\'s Reminders',
    'NSSiriUsageDescription': 'Access Siri',
    'NSSpeechRecognitionUsageDescription': 'Send User Data to Apple’s Speech Recognition Servers',
    'NSVideoSubscriberAccountUsageDescription': 'Access User\'s TV Provider Account'
}


class ApplicationBasicInfo:

    def __init__(self, app_path):
        self.app_path = app_path

        self.icon_path = None  # 图标
        self.display_name = None  # 名字
        self.bundle_identifier = None  # Bundle identifier

        self.execute_path = None
        self.execute_hash = None  # Hash Code
        self.platform = None  # iPhone, iPad, Universal
        self.operating_system = None  # Operating System Version

        self.app_version = None  # APP Version

        self.url_schemas = []
        self.supported_document_type = []
        self.SDK_version = None  # SDK Version
        self.SDK_build = None  # SDK Build
        self.Xcode_version = None  # Xcode Version
        self.Xcode_build = None  # Xcode Build
        self.machine_build = None  # Machine Build
        self.compiler = None  # Compiler

        self.requested_permissions = []
        self.developed_files = []
