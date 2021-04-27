.. Network Monitoring documentation master file, created by
   Jeroen Brauns on Sun Apr 25 20:41:11 2021.

Network Monitoring Documentatie
==============================================
Het network monitoring programma kan gebruikt worden voor de volgende taken:

* Scannen van apparaten in een netwerk
* Scannen van poorten van een apparaat in het netwerk
* Detecteren of je wordt gepinged door een ander apparaat


Programma en Modules
--------------------
Het programma is geschreven met de programmeertaal Python v3.8. De belangrijkste Python modules die gebruikt zijn voor het
programma zijn de volgende:


+--------------------------------------------------------+-------------------------------------------+
| `Python NMAP <https://pypi.org/project/python-nmap/>`_ | Scannen netwerk en Scannen poorten        |
+--------------------------------------------------------+-------------------------------------------+
| `PyQt5 <https://pypi.org/project/PyQt5/>`_             | Grafische gebruikersinterface             |
+--------------------------------------------------------+-------------------------------------------+
| `ipaddrss <https://pypi.org/project/ipaddress/>`_      | Controle invoer IP adres                  |
+--------------------------------------------------------+-------------------------------------------+
| `netifaces <https://pypi.org/project/netifaces/>`_     | Opvragen en weergeven netwerkinstellingen |
+--------------------------------------------------------+-------------------------------------------+
| `Pyinstaller <https://pypi.org/project/pyinstaller/>`_ | Maken van een uitvoerbestand              |
+--------------------------------------------------------+-------------------------------------------+

Downloaden en starten
---------------------
Het programma is ontwikkeld om te kunnen gebruiken op **Linux Ubuntu**. Het programma kan gedownload worden via deze 
`koppeling <https://github.com/jebr/network-monitoring/releases/download/v1.0/network-monitoring>`_.

Volg de onderstaande stappen om het programma te starten:

1. Download het programma via deze `link <https://github.com/jebr/network-monitoring/releases/download/v1.0/network-monitoring>`_
2. Open de terminal
3. Navigeer naar de download locatie
4. Voer het volgende commando uit om het programma uit te kunnen voeren ``sudo chmod +x network-monitoring``
5. Start het programma met het volgende commando ``./network-monitoring``
6. Je kunt nu het programma gaan gebruiken



Beschrijving programma onderdelen
---------------------------------

* :doc:`networkscan`
* :doc:`portscan`
* :doc:`pingdetector`


.. toctree::
   :maxdepth: 2
   :caption: Inhoud:
   :hidden:

   networkscan.rst
   portscan.rst
   pingdetector.rst

