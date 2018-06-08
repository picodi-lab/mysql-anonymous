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
  ```yml
  DELETE FROM mytable WHERE private = "Yes"``:

   database:
      tables:
         mytable:
            delete:
               private: Yes
    ```

* update records except field = 'value'

   for instance:

   ```yml
   database:
        tables:
            mytable:
                random_username: [ username, username_canonical]
                except_field_values: [username='john_doe|phillip|alex', email='@gmail.com|@yahoo.com|admin@gmail.com']
   ```

   ###### see example/example_anonymize.yml for reference 

### Install

1. Python 2.7
2. Create virtualenv
3. Install requirements: ``pip install requirements ``



### Usage

1. Create as many dirs you want under 'config' dir which represents the 'project_name'
2. Create yml file for each project and name it as follow: [project_name]_anonymize.yml
  (see example/example_anonymize.yml for reference)

    ```
    python anonymize.py [project_name] > anon.sql
    cat anon.sql | mysql
    ```


