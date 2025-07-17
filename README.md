# PY_ELF_CFG


## Fonctionnalités

- **Parsing ELF** : lecture des sections exécutables du binaire ELF.
- **Extraction des fonctions** : identification des fonctions à partir des symboles et du code désassemblé.
- **Construction du CFG** : création du graphe avec des blocs basiques en nœuds et des arêtes représentant les flux de contrôle (sauts, appels).
- **Support architectures** : x86 et x86-64 (modulable).
---
## ToDo / Roadmap

- Implémentation de l’algorithme de Sugiyama pour un dessin optimisé et lisible des graphes orientés.
- Correction de l’affichage des liens entre les différents blocs pour améliorer la clarté visuelle.
- Ajout de fonctionnalités interactives, notamment :
  - Changement dynamique de la couleur des blocs pour une meilleure distinction.
  - Renommage manuel des blocs pour faciliter l’analyse.
  - Recherche d’adresses spécifiques dans le CFG avec mise en surbrillance.
- Support étendu pour d’autres architectures ELF.
- Amélioration de l’interface utilisateur et ajout d’une visualisation intégrée.

---

## Finalité du projet

L’objectif ultime est de développer un **debugger graphique** intégré, permettant de visualiser en temps réel l’exécution d’un programme ELF via son **graphe de flot de contrôle (CFG)**.

Cette visualisation interactive facilitera :
- La compréhension du comportement du programme en suivant son flot d’exécution.
- L’analyse dynamique combinée à l’analyse statique via le CFG.
- Le debugging avancé avec mise en surbrillance des blocs exécutés, des sauts et des appels en temps réel.
- L’amélioration du reverse engineering et de la détection de vulnérabilités.

Ce projet servira donc de base à un outil complet alliant **analyse binaire**, **visualisation graphique** et **débogage** pour les programmes ELF.
