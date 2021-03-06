<p align="center">
  <img alt="Logo" src="https://raw.githubusercontent.com/jebr/network-monitoring/main/docs/readme-docs/network-monitoring.png">
</p>

# Linux Network Monitoring
Linux Netwerk monitoring tool (netwerk scanner, port scanner, ping detector)

Deze applicatie is gemaakt om te werken op Linux Ubuntu

## Demo / Preview
[![Screenshot](https://github.com/jebr/network-monitoring/blob/main/docs/readme-docs/network-monitoring-v1.0.png "Network Monitoring Screenshot")](https://github.com/jebr/network-monitoring/releases/)

## Documenatie
[Documentatie](https://switchit.me/network-monitoring)


## Development

### Opstarten en starten project
Open de terminal en voer de volgende syntaxis uit

1. Download het project naar je computer 
   
```python
git clone https://github.com/jebr/network-monitoring.git
```
   
2. navigeer naar de **src** folder en voer de volgende 
   syntax uit voor het aanmaken van een virtuele omgeving

```python
python3 -m venv ./venv
```   

3. Activeerd de virtuele omgeving met de volgende syntax
   
```python
source venv/bin/activate
```
    
   
4. Installeer de modules voor het project
   
```python
pip install -r requirements.txt
```

### Sluiten virtuele omgeving
Voor het verlaten van de virtuele omgeving gebruik de onderstaande syntax

```python
deactivate
```