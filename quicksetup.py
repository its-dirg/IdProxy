#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import shutil

folders = ['httpsCert', 'idp_cert', 'opKeys', 'sp_cert', 'static']

for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)


shutil.copy2('idp_conf.example', 'idp_conf.py')
shutil.copy2('sp_conf.example', 'sp_conf.py')
shutil.copy2('op_conf.example', 'op_conf.py')
shutil.copy2('server_conf.example', 'server_conf.py')