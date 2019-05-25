create_methods = {
	'UIPasteboard': ['generalPasteboard']
}
read_methods = {
	'UIPasteboard': ['dataForPasteboardType:', 'valueForPasteboardType:', 'itemSetWithPasteboardTypes:', 'valuesForPasteboardType:inItemSet:', 
                    'dataForPasteboardType:inItemSet:', 'string', 'strings', 'URL', 'URLs', 'image', 'images', 'color', 'colors']
}
write_methods = {
	'UIPasteboard': ['setValue:forPasteboardType:', 'setData:forPasteboardType:', 'addItems:', 'setString:', 'setStrings:', 'setURL:',
                    'setURLs:', 'setImage:', 'setImages:', 'setColor:', 'setColors:']
}

ck_log('Create pasteboard:')
create_pasteboards = caller.find(create_methods)
ck_log(create_pasteboards)
ck_log('===')

ck_log('Read from pasteboard:')
read_pasteboards = caller.find(read_methods)
ck_log(read_pasteboards)
ck_log('===')

ck_log('Write to pasteboard:')
write_pasteboards = caller.find(write_methods)
ck_log(write_pasteboards)
ck_log('===')

