import os
import sqlite3
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
DB_PATH = os.environ.get('EDR_DB', '../bpf/edr.db')

EVENT_TYPES = {1: 'fork', 2: 'exec', 3: 'exit', 4: 'file', 5: 'net'}


def query(sql, params=()):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        return []


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/stats')
def stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        active  = c.execute('SELECT COUNT(*) FROM processes WHERE end_ts IS NULL').fetchone()[0]
        events  = c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        alerts  = c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        conn.close()
        return jsonify({'active_procs': active, 'total_events': events, 'total_alerts': alerts})
    except:
        return jsonify({'active_procs': 0, 'total_events': 0, 'total_alerts': 0})


@app.route('/api/alerts')
def alerts():
    return jsonify(query(
        'SELECT a.id, a.ts, a.rule_id, a.severity, a.pid, a.start_ts, '
        '       p.comm, p.exe, e.fn, e.cmd '
        'FROM alerts a '
        'LEFT JOIN processes p ON a.pid=p.pid AND a.start_ts=p.start_ts '
        'LEFT JOIN events e ON a.event_id=e.id '
        'ORDER BY a.ts DESC LIMIT 100'
    ))


@app.route('/api/events')
def events():
    limit = request.args.get('limit', 200, type=int)
    return jsonify(query('SELECT * FROM events ORDER BY ts DESC LIMIT ?', (limit,)))


@app.route('/api/processes')
def processes():
    return jsonify(query(
        'SELECT * FROM processes ORDER BY start_ts DESC LIMIT 300'
    ))


@app.route('/api/graph')
def graph():
    procs = query(
        'SELECT pid, start_ts, comm, exe, ppid, uid, end_ts FROM processes '
        'ORDER BY start_ts DESC LIMIT 500'
    )
    alerted = {(r['pid'], r['start_ts']) for r in query(
        'SELECT DISTINCT pid, start_ts FROM alerts'
    )}

    node_ids = set()
    nodes = []
    for p in procs:
        nid = f"p_{p['pid']}_{p['start_ts']}"
        node_ids.add(nid)
        nodes.append({'data': {
            'id':       nid,
            'label':    p['comm'] or str(p['pid']),
            'pid':      p['pid'],
            'start_ts': p['start_ts'],
            'comm':     p['comm'],
            'exe':      p['exe'],
            'active':   p['end_ts'] is None,
            'alerted':  (p['pid'], p['start_ts']) in alerted,
            'type':     'process',
        }})

    edges = []
    # fork 엣지 (프로세스→프로세스)
    for e in query("SELECT * FROM graph_edges WHERE edge_type='fork' ORDER BY ts DESC LIMIT 500"):
        src = f"p_{e['src_pid']}_{e['src_start']}"
        dst = f"p_{e['dst_pid']}_{e['dst_start']}"
        if src in node_ids and dst in node_ids:
            edges.append({'data': {
                'id': f"e_{e['id']}", 'source': src, 'target': dst, 'type': 'fork'
            }})

    # connect 엣지 (프로세스→IP:port artifact 노드)
    artifact_ids = set()
    for e in query("SELECT * FROM graph_edges WHERE edge_type='connect' AND artifact IS NOT NULL ORDER BY ts DESC LIMIT 200"):
        src = f"p_{e['src_pid']}_{e['src_start']}"
        if src not in node_ids:
            continue
        art_id = f"a_{e['artifact']}"
        if art_id not in artifact_ids:
            artifact_ids.add(art_id)
            nodes.append({'data': {
                'id': art_id, 'label': e['artifact'],
                'type': 'artifact', 'active': False, 'alerted': False,
            }})
        edges.append({'data': {
            'id': f"e_{e['id']}", 'source': src, 'target': art_id, 'type': 'connect'
        }})

    return jsonify({'elements': nodes + edges})


@app.route('/api/graph/ancestry/<int:pid>/<int:start_ts>')
def ancestry(pid, start_ts):
    return jsonify(query('''
        WITH RECURSIVE anc(pid, start_ts, ppid, comm, exe, depth) AS (
            SELECT pid, start_ts, ppid, comm, exe, 0 FROM processes
            WHERE pid=? AND start_ts=?
            UNION ALL
            SELECT p.pid, p.start_ts, p.ppid, p.comm, p.exe, a.depth+1
            FROM processes p JOIN anc a ON p.pid=a.ppid
            WHERE a.depth < 50
        )
        SELECT * FROM anc ORDER BY depth DESC
    ''', (pid, start_ts)))


@app.route('/api/process/<int:pid>/<int:start_ts>/events')
def process_events(pid, start_ts):
    return jsonify(query(
        'SELECT * FROM events WHERE pid=? AND start_ts=? ORDER BY ts DESC LIMIT 50',
        (pid, start_ts)
    ))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
