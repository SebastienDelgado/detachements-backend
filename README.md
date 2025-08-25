# Détachements Art.21 — Starter (Netlify + Render)

Ce paquet contient :
- `frontend/` : un site statique prêt pour Netlify (ou tout hébergeur statique)
- `server.js` + `package.json` : une API Express minimale à déployer sur Render

## 1) Déployer l'API sur Render
1. Créez un **Web Service** Render (Node 18+).
2. Source: **Deploy from Git** (ou Zip upload si vous préférez).
3. `Build Command` : *(vide)* (pas de build nécessaire)
4. `Start Command` : `node server.js`
5. Déployez. Notez l'URL Render obtenue, ex. `https://votre-api.onrender.com`

## 2) Tester localement (optionnel)
```bash
npm install
npm start
# API sur http://localhost:3000
```

## 3) Déployer le front (Netlify)
- Uploadez le dossier **frontend/** sur Netlify (Drag&Drop).
- Dans `frontend/index.html`, l'API est lue via `window.API_BASE`. 
  Vous pouvez :
  - soit éditer la ligne et mettre votre URL Render permanente,
  - soit définir une **Environment Variable** Netlify nommée `API_BASE` puis ajouter
    un petit snippet Netlify (non nécessaire ici). Le plus simple : remplacez directement l'URL.

### Modifier l'URL API
Ouvrez `frontend/index.html` et remplacez :
```js
window.API_BASE = "https://YOUR-RENDER-APP.onrender.com";
```
par votre URL Render réelle.

## 4) Connexion Admin (démo)
- Email : `admin@csec-sg.com`
- Mot de passe : `Art21!`

## 5) CORS
Le backend autorise par défaut l'origine Netlify `https://cgtsg-detachements-art21-csecsg.netlify.app` + localhost. 
Si votre domaine change, modifiez le tableau `ALLOWED_ORIGINS` dans `server.js`.

## 6) Données
Ce backend **démo** stocke en **mémoire** (non persistant). C'est suffisant pour vos tests UI. 
Pour la prod, branchez une base (Postgres, etc.).
