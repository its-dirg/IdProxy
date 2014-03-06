#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

folders = ['httpsCert', 'idp_cert', 'opKeys', 'sp_cert', 'static']

for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)