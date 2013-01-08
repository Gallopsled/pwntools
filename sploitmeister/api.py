
import sqlalchemy
from pwn import log

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
        self.metadata.create_all()

    def _setupExploitTable(self):
        self.exploitTable = sqlalchemy.Table('exploits', self.metadata,
                                             sqlalchemy.Column('id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                             sqlalchemy.Column('data', sqlalchemy.types.BLOB, nullable=False),
                                             sqlalchemy.Column('author', sqlalchemy.types.String(60), nullable=False),
                                             sqlalchemy.Column('ts', sqlalchemy.types.DateTime, nullable=False),
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
                                          sqlalchemy.Column('ts', sqlalchemy.types.DateTime, nullable=False),
                                          sqlalchemy.Column('status', sqlalchemy.types.String(20), nullable=False),
                                          sqlalchemy.Column('attack_id', sqlalchemy.ForeignKey('attacks.a_id'))
                                          )

    def _setupAttackTable(self):
        self.attackTable = sqlalchemy.Table('attacks', self.metadata,
                                            sqlalchemy.Column('a_id', sqlalchemy.types.Integer, primary_key=True, autoincrement=True),
                                            sqlalchemy.Column('e_id', sqlalchemy.ForeignKey('exploits.id')),
                                            sqlalchemy.Column('h_id', sqlalchemy.ForeignKey('hosts.id')),
                                            sqlalchemy.Column('s_id', sqlalchemy.ForeignKey('services.id')),
                                            sqlalchemy.Column('cooldown', sqlalchemy.types.Integer, nullable=False),
                                            sqlalchemy.Column('last_run', sqlalchemy.types.DateTime, nullable=False),
                                            sqlalchemy.Column('active', sqlalchemy.types.Boolean, nullable=False),
                                            sqlalchemy.Column('priority', sqlalchemy.types.Integer, unique=True, nullable=False)
                                            )

    def addExploit(self, config):
        ins = self.exploitTable.insert()
        ins.execute(config)

    def addService(self, config):
        ins = self.serviceTable.insert()
        ins.execute(config)

    def addFlag(self, config):
        ins = self.flagTable.insert()
        ins.execute(config)

    def addHost(self, config):
        ins = self.hostTable.insert()
        ins.execute(config)

    def addAttack(self, config):
        ins = self.attackTable.insert()
        ins.execute(config)




    def promoteAttack(self, config):
        pass

    def demoteAttack(self, config):
        pass

    def getBatch(self, config):
        pass


