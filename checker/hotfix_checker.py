init_apis = {
	'JSContext': ['alloc', 'init', 'initWithVirtualMachine:']
}
ck_log('Init hotfix Environment')
ck_log(caller.find(init_apis))
ck_log('===')


set_apis = {
	'JSContext': ['setObject:forKeyedSubscript:']
}
ck_log('Setting hotfix Environment')
ck_log(caller.find(set_apis))
ck_log('===')

evaluate_apis = {
	'JSContext': ['evaluateScript:', 'evaluateScript:withSourceURL:']
}
ck_log('Evaluate hotfix')
ck_log(caller.find(evaluate_apis))
ck_log('===')