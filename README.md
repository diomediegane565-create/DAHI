# Dahira Khidmatul Khayril Hallamina Ahmada

Site du dahira : `index.html` (publié avec GitHub Pages) + base de données Supabase.

- Hébergement : GitHub Pages (Settings > Pages > Deploy from a branch > main / root).
- Données : Supabase. Le schéma et les fonctions serveur sont dans `supabase/schema.sql`
  (déjà appliqués sur le projet). Le mot de passe administrateur n'est pas dans ce dépôt :
  il est stocké chiffré dans la base et se change depuis l'espace administrateur.

## Suppression de membres

Dans l'espace administrateur, chaque membre a un bouton **Supprimer** (avec confirmation) qui
efface sa fiche et sa photo. Après une suppression, les nouveaux matricules continuent après le
plus grand numéro existant : **ré-exécuter la fonction `register_member` de `supabase/schema.sql`**
dans Supabase (SQL Editor) pour activer ce comportement.

## E-mail de bienvenue (EmailJS)

1. Créer un compte gratuit sur https://www.emailjs.com et ajouter un *Email Service* (Gmail convient).
2. Créer un *Email Template* : champ « To Email » = `{{to_email}}`, puis un texte du type :
   `Bienvenue {{prenom}} {{nom}} ! Votre inscription au Dahira Khidmatul Khayril Hallamina Ahmada est
   enregistrée. Votre numéro de membre : {{matricule}}. Site : {{site_url}}`
3. Dans `index.html`, renseigner `const EMAILJS = { serviceId, templateId, publicKey }`
   (la clé publique est dans Account > General).
4. Dans EmailJS > Security, limiter les domaines autorisés à celui du site.

Tant que `EMAILJS` est vide, aucun e-mail n'est envoyé. Un échec d'envoi ne bloque jamais l'inscription.

## Modifier une carte de membre

Espace administrateur > bouton **Carte / modifier** sur un membre : on peut corriger prénom, nom,
téléphone, adresse, commission, fonction, mission, et ajouter / remplacer / retirer la photo
(réduite automatiquement à 600 px). Aucun changement de base de données n'est nécessaire.
