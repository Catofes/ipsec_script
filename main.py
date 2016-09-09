import argparse
import json
import hashlib


class IPsec:
    def __init__(self, args):
        self.file = open(args.json, "r")
        self.id = args.id
        self.connections = []
        self.servers = None
        self.outer_ip = ""
        self.inner_ip = ""
        self.script = ""
        self.seed = args.seed
        self.output = args.output

    def load_file(self):
        d = json.loads(self.file.read())
        self.servers = d['servers']
        self.outer_ip = self.servers[self.id]['ip']
        if 'inner' in self.servers[self.id].keys():
            self.inner_ip = self.servers[self.id]['inner']
        else:
            self.inner_ip = self.outer_ip
        for ele in d['connections']:
            if self.id == str(ele[0]):
                self.connections.append(str(ele[1]))
            if self.id == str(ele[1]):
                self.connections.append(str(ele[0]))

    def _generate_sec_spi(self, ip):
        temp = str(ip) + str(self.seed)
        temp = hashlib.sha256(temp.encode('utf-8')).hexdigest()
        temp = str(temp)
        enc = temp[0:8]
        spi = int(temp[8:10], 16)
        return enc, spi

    def generate_script(self):
        self.script += "#!/bin/bash\n"
        for con in self.connections:
            remote_server = self.servers[con]
            enc, spi = self._generate_sec_spi(remote_server['ip'])
            self.script += "ip xfrm state add src %s dst %s proto esp spi %s enc blowfish %s\n" \
                           % (self.inner_ip, remote_server['ip'], spi, enc)
            self.script += "ip xfrm policy add src %s dst %s dir out tmpl proto esp spi %s\n" \
                           % (self.inner_ip, remote_server['ip'], spi)
            enc, spi = self._generate_sec_spi(self.outer_ip)
            self.script += "ip xfrm state add src %s dst %s proto esp spi %s enc blowfish %s\n" \
                           % (remote_server['ip'], self.inner_ip, spi, enc)
            self.script += "ip xfrm policy add src %s dst %s dir in tmpl proto esp spi %s\n" \
                           % (remote_server['ip'], self.inner_ip, spi)
            self.script += "\n"
        open(self.output, "w").write(self.script)


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Generate Ipsec Setup Script")
    parser.add_argument("-j", "--json", help="Describe Json File.")
    parser.add_argument("-i", "--id", help="Server Id.")
    parser.add_argument("-s", "--seed", default="0", help="Encrypt Secret Seed.")
    parser.add_argument("-o", "--output", default="output.sh", help="Output Bash Script.")
    args = parser.parse_args()

    ip_sec = IPsec(args)
    ip_sec.load_file()
    ip_sec.generate_script()
