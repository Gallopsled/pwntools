

mysql_tables = 'SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema <> "information_schema" AND table_schema <> "mysql"'

def mysql_columns(table):
    return 'SELECT GROUP_CONCAT(CONCAT(column_name,"(",column_type,")")) FROM information_schema.columns WHERE table_name = "%s"' % table

def mysql_dump(table, columns):
    return 'SELECT GROUP_CONCAT(CONCAT_WS("|",%s) SEPARATOR "\\n") from %s' % \
        (','.join(columns), table)

def mysql_file(filename):
    return 'SELECT load_file("%s")' % filename

mysql_fulldump = ''
