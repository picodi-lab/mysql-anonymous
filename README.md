## Mysql Anonymous

Contributors can benefit from having real data when they are
developing.  This script can do a few things (see `anonymize.yml`):

* Truncate any tables (logs, and other cruft which may have sensitive data)
* Nullify fields (emails, passwords, etc)
* Fill in random/arbitrary data:
    * Random integers
    * Random IP addresses
    * Email addresses
    * Usernames
    * First Name
    * Last Name
    * String
* Delete rows based on simple rules:  e.g.
  ``DELETE FROM mytable WHERE private = "Yes"``:

   ``database:``
        ``tables:``
            ``mytable:``
                ``delete:``
                    ``private: Yes ``

* update records except field = 'value'

   for instance:

   `` database:
        tables:
            mytable:
                random_username: [ username, username_canonical]
                except_exact_field_value: [email='aaa@bbbb', email='bbb@aaaa']
                except_pattern_field_value: [email='%@pentalog.com', email='%@pentalog.fr'] ``

### Install

1. Python 2.7
2. Create virtualenv
3. Install requirements: ``pip install requirements ``


### Usage

    python anonymize.py [project_name] > anon.sql
    cat anon.sql | mysql


