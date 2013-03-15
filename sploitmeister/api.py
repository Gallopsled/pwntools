
import sqlalchemy
from pwn import log
import datetime

class Api(object):
    def __init__(self, db_name, db_host, db_port, db_username=None, db_password=None):
        self.db_name = db_name
        self.db_host = db_host
        self.db_port = db_port
        self.db_username = db_username
        self.db_password = db_password
        # if self.db_username and self.db_password:
        #     dbConnectionString = 'mysql://%s:%s@%s:%s/%s' % (self.db_username, self.db_password, self.db_host, self.db_port, self.db_name)
        # else:
        #     dbConnectionString = 'mysql://%s:%s/%s' % (self.db_host, self.db_port, self.db_name)
        dbConnectionString = 'sqlite:///%s' % db_name
        self.engine = sqlalchemy.create_engine(dbConnectionString)
        self.metadata    = sqlalchemy.MetaData(self.engine)

        self._setupExploitTable()
        self._setupHostTable()
        self._setupServiceTable()
        self._setupFlagTable()
        self._setupAttackTable()
        self._setupConfigTable()
        self._setupLogTable()
        self.metadata.create_all()

    def _setupConfigTable(self):
        self.configTable = sqlalchemy.Table('config', self.metadata,
                                            sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                            sqlalchemy.Column('flag_regexp', sqlalchemy.types.String(100), nullable=False),
                                            sqlalchemy.Column('flag_submitter', sqlalchemy.types.BLOB, nullable=False),
                                            sqlalchemy.Column('cooldown', sqlalchemy.types.Integer, nullable=False, default=60),
                                            sqlalchemy.Column('batch_size', sqlalchemy.types.Integer, nullable=False, default=10)
                                            )

    def _setupExploitTable(self):
        self.exploitTable = sqlalchemy.Table('exploits', self.metadata,
                                             sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                             sqlalchemy.Column('data', sqlalchemy.types.BLOB, nullable=False),
                                             sqlalchemy.Column('author', sqlalchemy.types.String(60), nullable=False),
                                             sqlalchemy.Column('created', sqlalchemy.types.DateTime, default=datetime.datetime.now(), nullable=False),
                                             sqlalchemy.Column('name', sqlalchemy.types.String(100), nullable=False),
                                             sqlalchemy.Column('version', sqlalchemy.types.String(20), nullable=False)
                                             )

    def _setupHostTable(self):
        self.hostTable = sqlalchemy.Table('hosts', self.metadata,
                                          sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                          sqlalchemy.Column('ip', sqlalchemy.types.String(50), nullable=False),
                                          sqlalchemy.Column('desc', sqlalchemy.types.String(100), nullable=True)
                                          )

    def _setupServiceTable(self):
        self.serviceTable = sqlalchemy.Table('services', self.metadata,
                                             sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                             sqlalchemy.Column('name', sqlalchemy.types.String(60))
                                             )

    def _setupFlagTable(self):
        self.flagTable = sqlalchemy.Table('flags', self.metadata,
                                          sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                          sqlalchemy.Column('flag', sqlalchemy.types.String(100), nullable=False),
                                          sqlalchemy.Column('created', sqlalchemy.types.DateTime, default=datetime.datetime.now(), nullable=False),
                                          sqlalchemy.Column('status', sqlalchemy.types.Enum("delivered", "failed", "pending"), default="pending", nullable=False),
                                          sqlalchemy.Column('attack_id', sqlalchemy.ForeignKey('attacks.id'))
                                          )

    def _setupAttackTable(self):
        self.attackTable = sqlalchemy.Table('attacks', self.metadata,
                                            sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                            sqlalchemy.Column('exploit_id', sqlalchemy.ForeignKey('exploits.id')),
                                            sqlalchemy.Column('host_id', sqlalchemy.ForeignKey('hosts.id')),
                                            sqlalchemy.Column('service_id', sqlalchemy.ForeignKey('services.id')),
                                            sqlalchemy.Column('cooldown', sqlalchemy.types.Integer, nullable=False),
                                            sqlalchemy.Column('created', sqlalchemy.types.DateTime, default=datetime.datetime.now(), nullable=False),
                                            sqlalchemy.Column('last_run', sqlalchemy.types.DateTime, nullable=False),
                                            sqlalchemy.Column('status', sqlalchemy.types.Enum("started", "error", "pass", "ok", "disable", "enable"), default="started", nullable=False),
                                            sqlalchemy.Column('priority', sqlalchemy.types.Integer, unique=True, nullable=False)
                                            )

    def _setupLogTable(self):
        self.hostTable = sqlalchemy.Table('log', self.metadata,
                                          sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                          sqlalchemy.Column('created', sqlalchemy.types.DateTime, default=datetime.datetime.now(), nullable=False),
                                          sqlalchemy.Column('attack_id', sqlalchemy.ForeignKey('attacks.id')),
                                          sqlalchemy.Column('text', sqlalchemy.types.Text, nullable=True)
                                          )



    def addConfig(self, config):
        ''' type(config) == dict
valid fields:
'flag_regexp' : regular expression matching valid flag for current ctf
'flag_submitter' : executable script responsible for submitting the flags to flag server
'cooldown' : default cooldown for attacks
'batch_size' : amount of attacks given each worker
'''
        ins = self._configTable.insert()
        res = ins.execute(config)
        if res:
            rowid = res.lastrowid
            res.close()
            return rowid
        return False

    def getConfig(self):
        ''' Returns the configuration
'''
        column = self._configTable.c
        select = self._configTable.select()
        result = select.execute()
        row    = result.fetchone()
        return row


    def addExploit(self, config):
        ''' type(config) == dict
fields:
'data' : exploit payload in a format executable by the workers
'author' : author(s) of the exploit
'created' : time when exploit was submitted
'name' : name of the exploit
'version' : version of the exploit

'''
        ins = self._exploitTable.insert()
        res = ins.execute(config)
        if res:
            rowid = res.lastrowid
            res.close()
            return rowid
        return False

    def getExploits(self, amount=10):
        ''' Returns 'amount' (default: 10) exploits
'''
        column = self._exploitTable.c
        select = self._exploitTable.select()
        select = select.limit(amount)
        select = select.order_by(sqlalchemy.desc(column.ts))
        result = select.execute()
        rows   = result.fetchall()
        result.close()
        return rows


    def addService(self, config):
        '''type(config) == dict
fields:
'name' : name of service
'''
        ins = self._serviceTable.insert()
        res = ins.execute(config)
        if res:
            rowid = res.lastrowid
            res.close()
            return rowid
        return False

    def getServices(self, amount=10):
        ''' Returns 'amount' (default: 10) services
'''
        column = self._serviceTable.c
        select = self._serviceTable.select()
        select = select.limit(amount)
        result = select.execute()
        rows   = result.fetchall()
        result.close()
        return rows


    def addFlag(self, config):
        '''type(config) == dict
fields:
'flag' : the flag hash as a string
'created' : timestamp of when flag was stolen
'status' : status of flag (delivered/failed/pending)
'attack_id' : id of which attack stole the flag
'''
        ins = self._flagTable.insert()
        res = ins.execute(config)
        if res:
            rowid = res.lastrowid
            res.close()
            return rowid
        return False

    def getFlags(self, amount=10):
        ''' Returns 'amount' (default: 10) flags
'''
        column = self._flagTable.c
        select = self._flagTable.select()
        select = select.limit(amount)
        result = select.execute()
        rows   = result.fetchall()
        result.close()
        return rows


    def addHost(self, config):
        '''type(config) == dict
fields:
'ip' : ip address of host
'desc' : description of host
'''
        ins = self._hostTable.insert()
        res = ins.execute(config)
        if res:
            rowid = res.lastrowid
            res.close()
            return rowid
        return False

    def getHosts(self, amount=10):
        ''' Returns 'amount' (default: 10) hosts
'''
        column = self._hostTable.c
        select = self._hostTable.select()
        select = select.limit(amount)
        result = select.execute()
        rows   = result.fetchall()
        result.close()
        return rows


    def addAttack(self, config):
        '''type(config) == dict
fields:
'exploit_id' : exploit id
'host_id' : host id
'service_id' : service id
'cooldown' : minimum frequency of executions (s) (optional)
'created' : time of when attack was created
'last_run' : time of when attack was last executed
'active' : the status of current attack (started (default), error, pass, ok, disable, enable)
'priority' : priority (higher is lower prio)
'''
        if not config.has_key('cooldown'):
            config = self.getConfig()
            if not config:
                cooldown = 60
            else:
                cooldown = config[3]
            config.update({'cooldown' : cooldown})

        ins = self._attackTable.insert()
        res = ins.execute(config)
        if res:
            rowid = res.lastrowid
            res.close()
            return rowid
        return False

    def getAttacks(self, amount=None, get_all=False):
        ''' yields 'amount' (default: 10) attacks to be executed.
Each attack will get last_run field updated with current gmtime.
Only active attacks are returned unless get_all is True.
'''
        if not amount:
            config = self.getConfig()
            if not config:
                amount = 10
            else:
                amount = config[4]

        column = self._attackTable.c
        select = self._attackTable.select()
        if not get_all:
            select = select.where(column.active == True)

        select = select.limit(amount)
        select = select.order_by(sqlalchemy.desc(column.last_run))
        result = select.execute()
        rows   = result.fetchall()

        new_last_run = strftime("%Y-%m-%d %X", gmtime())
        ids = [row[0] for row in rows]

        for a_id in ids:
            up = self._attackTable.update()
            up = up.where(column.id == a_id)
            up = up.values(last_run = new_last_run)
            up.execute()

        result.close()
        return rows

    def promoteAttack(self, a_id, promote_level=None):
        ''' Promotes the priority (or sets priority level if promote_level is set) of attack with id `a_id`
'''
        try:
            if not isinstance(promote_level, int):
                up = self._attackTable.update()
                up = up.where(self._attackTable.c.id == a_id)
                up = up.values(priority = self._attackTable.c.priority - 1)
            else:
                up = self._attackTable.update()
                up = up.where(self._attackTable.c.id == a_id)
                up = up.values(priority = promote_level)
            up.execute()
        except:
            log.error("Failed demoting attack with id: %d" % a_id)


    def demoteAttack(self, a_id, promote_level=None):
        ''' Demotes priority (or sets priority level if promote_level is set) of attack with id `a_id`
'''
        try:
            if not isinstance(promote_level, int):
                up = self._attackTable.update()
                up = up.where(self._attackTable.c.id == a_id)
                up = up.values(priority = self._attackTable.c.priority + 1)
            else:
                up = self._attackTable.update()
                up = up.where(self._attackTable.c.id == a_id)
                up = up.values(priority = promote_level)
            up.execute()
        except:
            log.error("Failed demoting attack with id: %d" % a_id)

    def disableAttack(self, a_id):
        ''' Sets `active` column to `False` for attack with id `a_id`
'''
        up = self._attackTable.update()
        up = up.where(self._attackTable.c.id == a_id)
        up = up.values(active = "disable")
        up.execute()

    def enableAttack(self, a_id):
        ''' Sets `active` column to `True` for attack with id `a_id`
'''
        up = self._attackTable.update()
        up = up.where(self._attackTable.c.id == a_id)
        up = up.values(active = "started")
        up.execute()

    def getBatch(self, amount=None):
        return self.getAttacks(amount)
