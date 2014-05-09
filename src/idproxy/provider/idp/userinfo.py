__author__ = 'haho0032'


class DictionaryInformation(object):
    def __init__(self, user_info, extra_info=None, userid_map=None):
        self.user_info = user_info
        self.extra_info = extra_info
        self.userid_map = userid_map

    def information(self, environ, start_response, uid):
        if self.userid_map is not None and uid in self.userid_map:
            uid = self.userid_map[uid]
        return self.user_info[uid].copy()

    def extra(self, environ, start_response, uid):
        if self.userid_map is not None and uid in self.userid_map:
            uid = self.userid_map[uid]
        if self.extra_info is not None:
            return self.extra_info[uid].copy()
        return None
