background_methods = {
	'*': ['applicationWillResignActive:', 'applicationDidEnterBackground:']
}

background_behaviours = callee.find_api(background_methods)
for callee_method in background_behaviours:
    ck_log(callee_method)
    for _class, method in background_behaviours[callee_method]:
        ck_log('&nbsp;' + _class + ' ' + method)
