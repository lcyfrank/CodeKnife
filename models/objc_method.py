# Contains return type of Objective-C methods
objc_methods = {
    'UIApplication': {
        'sharedApplication': 'UIApplication'
    },
    'UIScreen': {
        'mainScreen': 'UIScreen'
    },
    'UIPasteboard': {
        'generalPasteboard': 'UIPasteboard'
    },
    'NSNotificationCenter': {
        'defaultCenter': 'NSNotificationCenter'
    },
    '*': {
        'view': 'UIView',
        'keyWindow': 'UIWindow'
    }
}