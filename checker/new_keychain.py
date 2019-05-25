add_function = ['_SecItemAdd']
search_function = ['_SecItemCopyMatching']
update_function = ['_SecItemUpdate']
delete_function = ['_SecItemDelete']

ck_log('Add to KeyChain')
add_results = caller.find_function(add_function)
ck_log(add_results)
ck_log('===')

ck_log('Query from KeyChain')
query_results = caller.find_function(search_function)
ck_log(query_results)
ck_log('===')