ck_log('handle notification')
notification_handlers = notification.handler(['*'])
ck_log(notification_handlers)
ck_log('===')
ck_log('post notification')
notification_posters = notification.poster(['*'])
ck_log(notification_posters)
ck_log('===')