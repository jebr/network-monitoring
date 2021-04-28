Poortscanner
============

Voor het uitvoeren van de portscan moet het IP adres van de te scannen host worden ingevuld in het veld **IP-address**.
Selecteer vervolgens een optie om de poortscan te starten. Er zijn drie opties beschikbaar te weten:

* 20 meest gebruikte poorten
* 100 meest gebruikte poorten
* Vrij te kiezen poorten

Een overzicht van de meest gebruikte poorten is :ref:`hier <top-ports>` terug te vinden.

Waneer de **Scan** knop wordt ingedrukt zal de scan gestart worden met de gekozen optie. In de weergave zullen alleen de openstaande poorten worden weergegeven. Wanneer een poort op een host gesloten is zal deze niet worden weergegeven in de scanlijst.

Voor de vrij te kiezen poort zijn de volgende manieren voor invoeren toegestaan:

* poorten gescheiden door een komma (,)
* poorten gescheiden door een streepje (-)

Wanneer de invoer met een komma wordt gebruikt zullen alle ingevoerde poorten apart gescaned worden. Wanneer er tussen de poort een streepje wordt geplaatst zullen de tussenliggende poorten ook gescaned worden.

Voorbeelden van een geldige invoer:

1. 80,81,22,21
2. 8080-8085

Voor de vrije poortscan kunnen poorten van 1 t/m  65535 ingevoerd worden.


.. image:: images/portscan.png
   :scale: 100%
   :align: center

