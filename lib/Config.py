class Config:

    def __init__(self, config_file = "config.ini", trigger_file = "trigger.run"):
        self.config_file = config_file
        self.trigger_file = trigger_file
        self.config = {
            'name': 'network',
            'target': None,
            'hops': 10,
            'device': None,
            'fullscan': True,
            'syslog_host': None,
            'syslog_port': 514,
            'repeated': 0,
        }
        self._paused = 'paused'
        self._running = 'running'
        self._triggered = 'triggered'

    def load(self):
        with open(self.config_file, 'r') as file:
            fp = file.read()
            for line in fp.split("\n"):
                if len(line) < 1: continue
                if line[0] == '#': continue
                if line[0] == '[': continue
                (key, val) = line.split("=")
                key = key.strip()
                val = val.strip()
                self.set(key, val)
        return self

    def reload(self):
        self.load()

    def save(self):
        with open(self.config_file, mode='w') as file:
            file.write("[scanner]\n")
            for k,v in self.config.items():
                if k == 'fullscan':
                    k = 'simple'
                    v = False if v else True
                file.write("%s=%s\n" % (k, v))

    def get(self, key, default_value=None):
        return self.config.get(key, default_value)
    
    def set(self, key, value):
        if key in ('-t', '--target', 'target'):
            self.config['target'] = value if len(value) > 0 else ''
        elif key in ('-m', '--max', 'hops'):
            self.config['hops'] = int(value) if len(value) > 0 else 15
        elif key in ('-d', '--device', 'device'):
            self.config['device'] = value if len(value) > 0 else ''
        elif key in ('-n', '--name', 'name') and len(value) > 0:
            self.config['name'] = value
        elif key in ('-s', '--simple', 'simple') and len(value) > 0:
            self.config['fullscan'] = False if value == 'True' else True
        elif key in ('fullscan') and len(value) > 0:
            self.config['fullscan'] = False if value == 'false' else True
        elif key in ('-l', '--syslog', 'syslog_host', 'syslog'):
            self.config['syslog_host'] = value
        elif key in ('-p', '--port', 'syslog_port', 'port'):
            self.config['syslog_port'] = int(value) if len(value) > 0 else 514
        elif key in ('-r', '--repeated', 'repeated'):
            self.config['repeated'] = int(value) if len(value) > 0 else 0

    def get_plain_config(self):
        return self.config


    def is_paused(self):
        return self._read_state() == self._paused

    def is_triggered(self):
        return self._read_state() == self._triggered

    def is_running(self):
        return self._read_state() == self._running

    def start_run(self):
        if self.is_running():
            return False
        return self._write_state(self._running)

    def pause_run(self):
        if self.is_triggered():
            return False
        return self._write_state(self._paused)

    def trigger_run(self):
        if self.is_running():
            return False
        return self._write_state(self._triggered)

    def _read_state(self):
        with open(self.trigger_file, mode='a') as file:
            file.write('')
        with open(self.trigger_file, mode='r') as file:
            fp = file.read()
            line = fp.split("\n")[0]
            return line
        return ''

    def _write_state(self, state):
        with open(self.trigger_file, mode='w') as file:
            file.write(state)
        return True
