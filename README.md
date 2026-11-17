# Dahira Khidmatul Khayril Hallamina Ahmada

Site du dahira : `index.html` (publié avec GitHub Pages) + base de données Supabase.

- Hébergement : GitHub Pages (Settings > Pages > Deploy from a branch > main / root).
- Données : Supabase. Le schéma et les fonctions serveur sont dans `supabase/schema.sql`
  (déjà appliqués sur le projet). Le mot de passe administrateur n'est pas dans ce dépôt :
  il est stocké chiffré dans la base et se change depuis l'espace administrateur.

## Comptes membres (accès réservé)

Pour entrer sur la plateforme, il faut un compte : **e-mail + mot de passe**, créé à l'inscription.
Le contrôle est fait côté serveur (sans connexion, la base ne renvoie aucun contenu ; seule la charte
reste lisible pour pouvoir s'inscrire). Les mots de passe sont stockés hachés (bcrypt).

- **Mise en ligne : d'abord `supabase/schema.sql` (SQL Editor de Supabase, ré-exécutable), ensuite `index.html`.**
  Dans l'autre ordre, la connexion et l'inscription échouent.
- Membres déjà inscrits avant les comptes : onglet **« Déjà inscrit ? »** (numéro de membre + téléphone
  d'origine, puis choix de l'e-mail et du mot de passe).
- Mot de passe oublié : l'administrateur clique **Réinit. mot de passe** sur la ligne du membre et lui
  transmet le mot de passe temporaire affiché.
- L'espace administrateur reste accessible par le lien « Accès administrateur » de la page de connexion
  (ou par le QR code des cartes administrateur).

## Suppression de membres (définitive)

Bouton **Supprimer** (avec confirmation) : efface la fiche, la photo, le compte et les sessions du membre,
puis **renumérote les matricules** restants sans trou (KKHA-0001, KKHA-0002…). Les cartes déjà imprimées
des membres qui suivaient le membre supprimé portent donc un ancien matricule et sont à réimprimer.

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
