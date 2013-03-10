from pwn import *
import MySQLdb

con = MySQLdb.Connection(host='localhost', user='sploitmeister', passwd='hamster1', db = 'sploitmeister')

def get_job():
    con.query('''
    INSERT INTO job_status (service_id, host_id)
        SELECT services.id, hosts.id
        FROM services, hosts
        ORDER BY IFNULL(
            (
                SELECT created
                FROM job_status
                WHERE job_status.service_id = services.id AND
                      job_status.host_id = hosts.id
                ORDER BY created DESC
                LIMIT 1
            ),
            0
        ) ASC
        LIMIT 1;
    ''')
    con.query('''
    SELECT services.id as service_id,
           services.name as service_name,
           hosts.id as host_id,
           hosts.name as host_name,
           job_status.id as job_id
    FROM job_status, services, hosts
    WHERE job_status.id = LAST_INSERT_ID() AND
          job_status.service_id = services.id AND
          job_status.host_id = hosts.id;
    ''')
    r = con.store_result()
    con.commit()

    service_id, service_name, host_id, host_name, job_id = r.fetch_row()[0]
    return {'service_id': service_id,
            'service_name': service_name,
            'host_id': host_id,
            'host_name': host_name,
            'job_id': job_id
            }


def get_next_jobs():
    con.query('''
    SELECT services.id as service_id, hosts.id as host_id,  IFNULL(
        (
            SELECT created
            FROM job_status
            WHERE job_status.service_id = services.id AND
                  job_status.host_id = hosts.id
            ORDER BY created DESC
            LIMIT 1
        ),
        0
    ) AS last_time
    FROM services, hosts
    ORDER BY last_time ASC;
    ''')
    r = con.store_result()
    con.commit()

    out = []
    # TODO: REST
