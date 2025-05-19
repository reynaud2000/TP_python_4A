from src.tp1.utils.lib import choose_interface
from scapy.all import sniff # type: ignore
class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.protocols = {}
        self.keyword_sql_injection = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "--", "' OR 1=1", "UNION SELECT", "--", "'; DROP", '" OR "a"="a', "1' OR '1'='1", "1' OR '1'='1' --", "' OR 'a'='a", "' OR 1=1 --", "' OR 1=1#", "OR 1=1", "OR 'a'='a", "OR 1=1 --"]
    def capture_trafic(self) :
        """
        Capture network trafic from an interface
        """
        interface = self.interface
        print(f"Capturing network traffic on interface: {interface}")
        self.snif_analyse= sniff(iface=interface,count=10)

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        """
        try:
            self.protocols.clear()
            for pkt in self.snif_analyse:
                last = pkt.lastlayer()
                name = last.__class__.__name__
                self.protocols[name] = self.protocols.get(name, 0) + 1
            return self.protocols

        except Exception as e:
            print(f"Error while sorting protocols: {e}")
            return {}
            
    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        return self.protocols
    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un traffic est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        attack_detected = False
        attack_info = []
        for proto in self.protocols:
            name = proto.__class__.__name__
            src_ip = getattr(proto, 'src', 'Unknown')
            if name == "HTTP":
                payload = getattr(proto, 'payload', '')
                if self.keyword_sql_injection(payload): 
                    attack_info.append(("HTTP (SQLi)", src_ip))
                    attack_detected = True
            elif name == "ARP":
                if getattr(proto, 'op', '') == 2:

                    attack_info.append(("ARP Spoofing", src_ip))
                    attack_detected = True
            elif name == "ICMP":
                if getattr(proto, 'type', '') == 8:
                    attack_info.append(("ICMP Echo Request", src_ip))
                    attack_detected = True
            elif name == "TCP":
                if getattr(proto, 'flags', '') == 0x02:
                    attack_info.append(("TCP SYN Scan", src_ip))
                    attack_detected = True
            elif name == "UDP":
                if getattr(proto, 'dport', '') == 53:
                    attack_info.append(("DNS Spoofing", src_ip))
                    attack_detected = True
            else:
                attack_info.append((name, src_ip))
        if attack_detected:
            for attack in attack_info:
                print(f"Attack type: {attack[0]}, Source IP: {attack[1]}")
        else:
            print("No attack detected.")
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        self.summary = self.gen_summary()
        

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
