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
Voici le script Python :
[dhcp_starvation.py](https://github.com/Frowing33/network-security/blob/main/dhcp_starvation.py)


## Description
Ce script exécute une attaque de DHCP starvation en inondant le serveur DHCP avec des requêtes malveillantes afin d'épuiser ses adresses IP disponibles.

## Utilisation
```bash
python dhcp_starvation.py -i <interface> [-t <target_ip>] [-p]
python dhcp_starvation.py -i eth0 -t 10.2.1.11 -p
```

# Attaque ARP
## 1. `arp_poisoning.py`
[arp_poisoning.py](https://github.com/Frowing33/network-security/blob/main/arp_poisoning.py)

### Description
Ce script réalise une attaque d'ARP poisoning en injectant une fausse association IP ↔ MAC dans la table ARP de la victime.

### Utilisation
```bash
python arp_poisoning.py <victim_ip> <fake_mac> <interface>
python arp_poisoning.py 192.168.1.10 00:11:22:33:44:55 eth0
```
## 2. `arp_spoof.py`
[arp_poisoning.py](https://github.com/Frowing33/network-security/blob/main/arp_spoof.py)

## Description
Ce script effectue une attaque d'ARP spoofing en modifiant la table ARP de la victime pour associer une IP à une fausse adresse MAC.

## Utilisation
```bash
python arp_spoof.py <victim_ip> <spoof_ip> <interface>
python arp_spoof.py 192.168.1.10 192.168.1.1 eth0
```

## 3. `arp_mitm.py`
[arp_mitm.py](https://github.com/Frowing33/network-security/blob/main/arp_mitm.py)
## Description
Ce script réalise une attaque Man-in-the-Middle (MITM) en manipulant les tables ARP de deux victimes pour intercepter leurs communications.

## Utilisation
```bash
python arp_mitm.py <victim_ip1> <victim_ip2> <victim_mac1> <victim_mac2> <interface>
```
## Attaque DNS

## 1. `dns_spoof.py`
[dns_spoof.py](https://github.com/Frowing33/network-security/blob/main/dns_spoof.py)
## Description
Ce script intercepte les requêtes DNS pour un domaine spécifique et renvoie une réponse malveillante contenant une IP spoofée.

## Utilisation
```bash
python dns_spoof.py -d <spoofed_domain> -i <spoofed_ip> -n <interface>
python dns_spoof.py -d efrei.fr -i 13.37.13.37 -n eth0
```

# Remédiations :
## 1. Attaques DHCP
### Menaces :

- DHCP Spoofing : Un attaquant crée un faux serveur DHCP.
- DHCP Starvation : Saturation des adresses IP disponibles.

### Remédiations :

- DHCP Snooping : Configurez des switches pour bloquer les réponses DHCP non autorisées.
- Isolation réseau : Utilisez des VLAN pour segmenter le trafic DHCP.
- Limitation des adresses MAC : Limitez le nombre d’adresses MAC par port sur les switches.

## 2. Attaques ARP

### Menaces :

- ARP Spoofing/Poisoning : Redirection du trafic via des réponses ARP falsifiées.
### Remédiations :

- Dynamic ARP Inspection (DAI) : Validez les requêtes ARP avec une base DHCP sécurisée.
- Tables ARP statiques : Configurez manuellement des correspondances IP/MAC pour les appareils critiques.
- Segmentation réseau : Utilisez des VLAN pour réduire la portée des attaques.
## 3. Attaques DNS
### Menaces :

- DNS Spoofing/Cache Poisoning : Faux enregistrements dans le cache DNS.
- DNS Amplification : Utilisation du DNS pour amplifier des attaques DDoS.
- DNS Hijacking : Redirection malveillante via des configurations DNS compromises.

### Remédiations :

- DNSSEC : Sécurisez les réponses DNS avec des signatures cryptographiques.
- Cache DNS restreint : Réduisez la durée de vie (TTL) des enregistrements DNS.
- ACL et filtrage : Limitez l’accès au DNS aux serveurs autorisés.
- Protection anti-DDoS : Activez des mécanismes de limitation des requêtes DNS.

