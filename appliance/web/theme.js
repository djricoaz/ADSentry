// Thème appliqué avant l'affichage de la page (évite un éclair blanc en mode sombre).
(function () {
  var saved = localStorage.getItem("adsentry.theme");
  var dark = saved ? saved === "dark" : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "dark" : "light";
})();
