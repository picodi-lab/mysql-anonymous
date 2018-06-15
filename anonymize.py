#!/usr/bin/env python
# This assumes an id on each field.
from __future__ import print_function
import logging
import hashlib
import random
from itertools import izip


log = logging.getLogger('anonymize')
common_hash_secret = "%016x" % (random.getrandbits(128))
picodi_hash_secret = '_picodi'

mailinator_domain = 'mailinator.com'

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


def split_values(value):
    values = value.split("=")
    it = iter(values)
    return dict(izip(it, it))


def dictify(x):
    return [split_values(item) for item in x]


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
                    updates.append("`%s` = CONCAT(id, '@aaaaa.bbbbb')"
                                   % field)
            elif operation == 'random_username':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_user_', id)" % field)
            elif operation == 'random_f_name':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_f_name_', id)" % field)
            elif operation == 'random_l_name':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_l_name_', id)" % field)
            elif operation == 'random_string':
                for field in listify(details):
                    updates.append("`%s` = CONCAT('_string_', id)" % field)
            elif operation == 'hash_value':
                for field in listify(details):
                    updates.append("`%(field)s` = MD5(CONCAT(@common_hash_secret, `%(field)s`))"
                                   % dict(field=field))
            elif operation == 'hash_email':
                for field in listify(details):
                    updates.append("`%(field)s` = CONCAT(MD5(CONCAT(@common_hash_secret, `%(field)s`)), '@aaaaa.bbbbb')"
                                   % dict(field=field))
            # set hash from field with constant salt
            elif operation == 'pico_hash':
                for field in listify(details):
                    updates.append("`{0}` = MD5(CONCAT(`{0}`, '{1}'))".format(field, picodi_hash_secret))
            # set hash from field with constant salt and mailinator sufix
            elif operation == 'pico_email_mailinator':
                for field in listify(details):
                    updates.append("`{0}` = CONCAT(MD5(CONCAT(`{0}`, '{1}')), '@', '{2}')".format(field, picodi_hash_secret, mailinator_domain))
            # set empty string to field
            elif operation == 'empty_string':
                for field in listify(details):
                    updates.append("`%s` = ''" % field)
            # set random mac address
            elif operation == 'mac_constant':
                for field in listify(details):
                    updates.append("`{0}` = '{1}'".format(field, "01:23:45:67:89:AB"))
            # set random float number
            elif operation == 'random_float':
                for field in listify(details):
                    updates.append("`%s` = RAND()*100" % field)
            # set ip 127.0.0.1
            elif operation == 'ip_localhost':
                for field in listify(details):
                    updates.append("`%s` = '127.0.0.1'" % field)
            # set phone number 627042178
            elif operation == 'phone_constant':
                for field in listify(details):
                    updates.append("`%s` = '627042178'" % field)
            # set random date
            elif operation == 'date_random':
                for field in listify(details):
                    updates.append("`%s` = NOW() - INTERVAL ROUND(RAND()*10000) DAY" % field)
            # set random gender
            elif operation == 'gender_random':
                for field in listify(details):
                    updates.append("`%s` = CASE WHEN RAND() > 0.5 THEN NULL ELSE IF(RAND() > 0.5, 'f', 'm') END" % field)
            # where condition
            elif operation == 'where':
                for field in listify(details):
                    if isinstance(field['value'], basestring):
                        conditional.append("`{0}` {1} '{2}'".format(field['field'], field['condition'], field['value']))
                    else:
                        conditional.append("`{0}` {1} {2}".format(field['field'], field['condition'], field['value']))
            elif operation == 'delete':
                continue
            elif operation == 'except_field_values':
                for field in dictify(details):
                    for k, v in field.iteritems():
                        conditional.append("`{0}` NOT REGEXP {1}".format(k, v))
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
        files = ['config/{0}/{1}_anonymize.yml'.format(sys.argv[1], sys.argv[1])]
    else:
        files = ['config/example/example_anonymize.yml']

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
