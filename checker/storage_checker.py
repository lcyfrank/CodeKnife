user_defaults_methods = {
	'NSUserDefaults': [
    	'standardUserDefaults', 'init', 'initWithSuiteName', 'setObject:forKey:', 
      	'setFloat:forKey:', 'setDouble:forKey:', 'setInteger:forKey:', 'setBool:forKey:',
      	'setURL:forKey:', 'removeObjectForKey:', 'objectForKey:', 'stringForKey:', 'URLForKey:', 
      	'arrayForKey:', 'dictionaryForKey:', 'stringArrayForKey:', 'dataForKey:', 'boolForKey:', 
      	'integerForKey:', 'floatForKey:', 'doubleForKey:', 'dictionaryRepresentation'
    ]
}
keyedarchive_methods = {
	'NSKeyedArchiver': [
    	'archivedDataWithRootObject:', 'archiveRootObject:toFile:', 'archivedDataWithRootObject:requiringSecureCoding:error:',
      	'encodeBool:forKey:', 'encodeBytes:length:forKey:', 'encodeConditionalObject:forKey:', 'encodeDouble:forKey:', 'encodeFloat:forKey:', 
      	'encodeInt:forKey:', 'encodeInt32:forKey:', 'encodeInt64:forKey:', 'encodeObject:forKey:'
    ],
  	'NSKeyedUnarchiver': [
    	'unarchiveObjectWithData:', 'unarchiveObjectWithFile:', 'containsValueForKey:', 'decodeBollForKey:', 'decodeBytesForKey:returnedLength:',
      	'decodeDoubleForKey:', 'decodeFloatForKey:', 'decodeIntForKey:', 'decodeInt32ForKey:', 'decodeInt64ForKey:', 'decodeObjectForKey:', 
      	'unarchivedObjectOfClass:fromData:error:', 'unarchivedObjectOfClasses:fromData:error:'
    ]

}

ck_log('User Defaults to store data')
result = caller.find(user_defaults_methods)
ck_log(result)
ck_log('===')
ck_log('Keyed Archive to store data')
result = caller.find(keyedarchive_methods)
ck_log(result)
ck_log('===')


