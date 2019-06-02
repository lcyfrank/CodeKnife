background_methods = {
	'*': ['applicationWillResignActive:', 'applicationDidEnterBackground:']
}

background_behaviours = callee.find_api(background_methods)
for _class in background_behaviours:
	ck_log(_class)