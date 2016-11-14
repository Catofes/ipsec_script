import argparse
import json
import hashlib


class Node:
    def __init__(self, rvalue):
        self.name = rvalue['name']
        self.address = rvalue['address']
        self.network = rvalue['network']
        self.route = rvalue['route']


class IPsec:
    def __init__(self, args):
        self.file = open(args.json, "r")
        self.d = json.loads(self.file.read())
        self.id = None  # args.id
        self.script = ""
        self.seed = args.seed
        self.output = None  # args.output
        self.nodes = {}  # type: dict(str,Node)
        self.self = None  # type: Node
        self.tunnels = None
        self.ipsec = None
        self.network = ""
        self.route_tmp = []

    def load_file(self):
        d = self.d
        self.self = Node(d['nodes'][self.id])
        for key, node in d['nodes'].items():
            self.nodes[key] = Node(node)
        self.tunnels = d['tunnel']
        self.ipsec = d['ipsec']
        self.network = d['network']

    def _generate_sec_spi(self, ip):
        temp = str(ip) + str(self.seed)
        temp = hashlib.sha256(temp.encode('utf-8')).hexdigest()
        temp = str(temp)
        enc = temp[0:8]
        spi = temp[8:16]
        return enc, spi

    def _generate_ipsec(self):
        self.script += "\n#####IPSEC#####\n"
        self.script += "#Self\n"
        for k, v in self.self.address.items():
            ip = v['public_ip']
            if 'local_ip' in v:
                ip = v['local_ip']
            enc, spi = self._generate_sec_spi(v['public_ip'])
            self.script += "ip xfrm state add dst %s proto esp spi 0x%s enc blowfish 0x%s\n" \
                           % (ip, spi, enc)
        self.script += "\n"
        for con in self.ipsec:
            info = con.split(".")
            if info[0] == self.id:
                local = self.self.address[info[1]]
                remote = self.nodes[info[2]].address[info[3]]
            elif info[2] == self.id:
                local = self.self.address[info[3]]
                remote = self.nodes[info[0]].address[info[1]]
            else:
                continue

            self.script += "#%s\n" % con
            remote_address = remote['public_ip']
            local_address = local['public_ip']
            if 'local_ip' in local:
                local_address = local['local_ip']

            enc, spi = self._generate_sec_spi(remote_address)
            self.script += "ip xfrm state add src %s dst %s proto esp spi 0x%s enc blowfish 0x%s\n" \
                           % (local_address, remote_address, spi, enc)
            self.script += "ip xfrm policy add src %s dst %s dir out tmpl proto esp spi 0x%s\n" \
                           % (local_address, remote_address, spi)
            enc, spi = self._generate_sec_spi(local['public_ip'])
            self.script += "ip xfrm policy add src %s dst %s dir in tmpl proto esp spi 0x%s\n" \
                           % (remote_address, local_address, spi)
            self.script += "\n"

    def _generate_tunnel(self):
        self.script += "\n#####TUNNEL#####\n"
        for con in self.tunnels:
            info = con.split(".")
            if info[0] == self.id:
                local = self.self.address[info[1]]
                remote = self.nodes[info[2]].address[info[3]]
                mode = info[4]
                name = "%s.%s" % (self.nodes[info[2]].name, info[3])
            elif info[2] == self.id:
                local = self.self.address[info[3]]
                remote = self.nodes[info[0]].address[info[1]]
                mode = info[4]
                name = "%s.%s" % (self.nodes[info[0]].name, info[1])
            else:
                continue

            self.script += "#%s\n" % con
            remote_ip = remote['public_ip']
            remote_inner_ip = remote['inner_ip']
            local_ip = local['public_ip']
            local_inner_ip = local['inner_ip']
            if 'local_ip' in local:
                local_ip = local['local_ip']

            if mode in ["ip6ip6", "ipip6", "ip6gre", "vti6"]:
                self.script += "ip -6 tunnel add %s mode %s local %s remote %s\n" % (name, mode, local_ip, remote_ip)
            else:
                self.script += "ip tunnel add %s mode %s local %s remote %s\n" % (name, mode, local_ip, remote_ip)
            self.script += "ip addr add %s peer %s dev %s\n" % (local_inner_ip, remote_inner_ip, name)
            self.script += "ip link set %s up\n" % name
            self.script += "\n"

    def _generate_route(self):
        self.script += "\n#####ROUTE#####\n"
        # self.script += "ip rule add pref 40000 lookup 1000\n"
        # self.script += "ip route flush table 40000\n"
        if "default" in self.self.route:
            dev = self.self.route["default"]
            info = dev.split(".")
            gateway = self.nodes[info[0]].address[info[1]]['inner_ip']
            name = "%s.%s" % (self.nodes[info[0]].name, info[1])
            self.script += "ip route add %s dev %s via %s\n" % (self.network, name, gateway)
        for k, v in self.nodes.items():
            if k == self.id:
                continue
            if k in self.self.route:
                dev = self.self.route[k]
                info = dev.split(".")
                gateway = self.nodes[info[0]].address[info[1]]['inner_ip']
                name = "%s.%s" % (self.nodes[info[0]].name, info[1])
                for address in v.network:
                    self.script += "ip route add %s dev %s via %s\n" % (address, name, gateway)
            elif "default" in self.self.route:
                dev = self.self.route["default"]
                info = dev.split(".")
                gateway = self.nodes[info[0]].address[info[1]]['inner_ip']
                name = "%s.%s" % (self.nodes[info[0]].name, info[1])
                for address in v.network:
                    self.script += "ip route add %s dev %s via %s\n" % (address, name, gateway)

    def generate_script(self):
        self.script += "#!/bin/bash\n"
        self._generate_ipsec()
        self._generate_tunnel()
        self._generate_route()
        open(self.output, "w").write(self.script)

    def generate_all(self):
        d = self.d
        for k, v in d['nodes'].items():
            self.id = k
            self.script = ""
            self.route_tmp = []
            self.output = "%s.sh" % v["name"]
            self.load_file()
            self.generate_script()


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Generate Ipsec Setup Script")
    parser.add_argument("-j", "--json", help="Describe Json File.")
    # parser.add_argument("-i", "--id", help="Server Id.")
    parser.add_argument("-s", "--seed", default="0", help="Encrypt Secret Seed.")
    # parser.add_argument("-o", "--output", default="output.sh", help="Output Bash Script.")
    args = parser.parse_args()

    ip_sec = IPsec(args)
    ip_sec.generate_all()
    # ip_sec.load_file()
    # ip_sec.generate_script()
