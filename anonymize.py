#!/usr/bin/env python
# This assumes an id on each field.
from __future__ import print_function
import logging
import hashlib
import random
from itertools import izip


log = logging.getLogger('anonymize')
common_hash_secret = "%016x" % (random.getrandbits(128))


def get_truncates(config):
    database = config.get('database', {})
    truncates = database.get('truncate', [])
    sql = []
    for truncate in truncates:
        sql.append('TRUNCATE `%s`' % truncate)
    return sql


def get_deletes(config):
    database = config.get('database', {})
    tables = database.get('tables', [])
    sql = []
    for table, data in tables.iteritems():
        if 'delete' in data:
            fields = []
            for f, v in data['delete'].iteritems():
                fields.append('`%s` = "%s"' % (f, v))
            statement = 'DELETE FROM `%s` WHERE ' % table + ' AND '.join(fields)
            sql.append(statement)
    return sql


listify = lambda x: x if isinstance(x, list) else [x]


def dictify(x):
    d = list()
    for item in x:
        item_list = item.split("=")
        i = iter(item_list)
        d.append(dict(izip(i, i)))
    return d

def get_updates(config):
    global common_hash_secret

    database = config.get('database', {})
    tables = database.get('tables', [])
    sql = []
    for table, data in tables.iteritems():
        updates = []
        conditional = []
        for operation, details in data.iteritems():
            if operation == 'nullify':
                for field in listify(details):
                    updates.append("`%s` = NULL" % field)
            elif operation == 'random_int':
                for field in listify(details):
                    updates.append("`%s` = ROUND(RAND()*1000000)" % field)
            elif operation == 'random_ip':
                for field in listify(details):
                    updates.append("`%s` = INET_NTOA(RAND()*1000000000)" % field)
            elif operation == 'random_email':
                for field in listify(details):
                    updates.append("`%s` = CONCAT(id, '@randemail.qwq')"
                                   % field)
            elif operation == 'random_username':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_user_', id)" % field)
            elif operation == 'random_name':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_name_', id)" % field)
            elif operation == 'random_slug':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_slug_', id)" % field)
            elif operation == 'hash_value':
                for field in listify(details):
                    updates.append("`%(field)s` = MD5(CONCAT(@common_hash_secret, `%(field)s`))"
                                   % dict(field=field))
            elif operation == 'hash_email':
                for field in listify(details):
                    updates.append("`%(field)s` = CONCAT(MD5(CONCAT(@common_hash_secret, `%(field)s`)), '@randemail.qwq')"
                                   % dict(field=field))
            elif operation == 'delete':
                continue
            elif operation == 'except_exact_field_value':
                for field in dictify(details):
                    for k, v in field.iteritems():
                        conditional.append("'{0}' not in {1}".format(k, v))
            elif operation == 'except_pattern_field_value':
                for field in dictify(details):
                    for k, v in field.iteritems():
                        conditional.append("'{0}' not like {1}".format(k, v))
            else:
                log.warning('Unknown operation.')
        if updates:
            where = []
            if conditional:
                q = ''
                for cond in conditional:
                    q += ' AND {0}'.format(cond) if q else cond
                where.append('WHERE {0}'.format(q))

            sql.append('UPDATE `{0}` SET {1} {2}'.format(table, ', '.join(updates), ' '.join(where)))

    return sql


def anonymize(config):
    database = config.get('database', {})

    if 'name' in database:
         print("USE {0};".format(database['name']))

    print("SET FOREIGN_KEY_CHECKS=0;")
    print("SET SQL_SAFE_UPDATES = 0;")

    sql = []
    sql.extend(get_truncates(config))
    sql.extend(get_deletes(config))
    sql.extend(get_updates(config))
    for stmt in sql:
        print('{0};'.format(stmt))

    print("SET SQL_SAFE_UPDATES = 1;")
    print("SET FOREIGN_KEY_CHECKS=1;")


if __name__ == '__main__':

    import yaml
    import sys

    if len(sys.argv) > 1:
        files = ['config/{0}/{1}-anonymize.yml'.format(sys.argv[1], sys.argv[1])]
    else:
        files = ['anonymize.yml']

    for f in files:
        print("--")
        print("-- {0}".format(f))
        print("--")
        print("SET @common_hash_secret=rand();")
        print("")
        cfg = yaml.load(open(f))
        if 'databases' not in cfg:
            anonymize(cfg)
        else:
            databases = cfg.get('databases')
            for name, sub_cfg in databases.items():
                print("USE {0};".format(name))
                anonymize({'database': sub_cfg})
