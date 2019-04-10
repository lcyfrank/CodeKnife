# Contains return type of Objective-C methods
objc_methods_return_type = {
    'UIApplication': {
        'sharedApplication': 'UIApplication'
    },
    'UIScreen': {
        'mainScreen': 'UIScreen'
    },
    'UIView': {
    },
    'UIPasteboard': {
        'generalPasteboard': 'UIPasteboard'
    },
    'NSNotificationCenter': {
        'defaultCenter': 'NSNotificationCenter'
    },
    'NSUserDefaults': {
        'standardUserDefaults': 'NSUserDefaults'
    },
    'NSBundle': {
        'mainBundle': 'NSBundle'
    },
    '*': {
        'view': 'UIView',
        'keyWindow': 'UIWindow',
        'bounds': 'None',
        'addSubview:': 'None',
        'setBackgroundColor:': 'None',
        'setAlpha:': 'None'
    }
}

objc_methods_arguments = {
    'UIView': {
    },
    '*': {
        'addSubview:': [('id', 8)]
    }
}
