// Les liens analysés sont fournis par des inconnus : tout le texte est inséré avec
// textContent, jamais avec innerHTML, pour qu'aucun lien ne puisse injecter de code.

const $ = (id) => document.getElementById(id);
const form = $('form');
const input = $('url');
const button = $('go');
const statusEl = $('status');
const result = $('result');

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.classList.toggle('error', isError);
}

function render(r) {
  const level = { faible: 'low', modéré: 'mid', élevé: 'high' }[r.verdict];
  result.dataset.level = level;
  $('score').textContent = r.score;
  $('verdict').textContent = r.verdict;

  const facts = $('facts');
  facts.replaceChildren();
  const add = (k, v) => {
    if (!v) return;
    facts.append(el('dt', '', k), el('dd', '', v));
  };
  add('Lien', r.url);
  if (r.url_finale && r.url_finale !== r.url) add('Mène à', r.url_finale);
  add('Domaine réel', r.domaine);
  add('Domaine créé le', r.domaine_cree_le);
  add('Certificat émis par', r.emetteur_certificat);

  const list = $('signals');
  list.replaceChildren();
  const risky = r.signaux.filter((s) => s.points > 0).sort((a, b) => b.points - a.points);
  const info = r.signaux.filter((s) => s.points === 0);
  if (!risky.length) list.append(el('li', 'none', 'Aucun signal de risque détecté.'));
  for (const s of risky) {
    const li = el('li', 'signal');
    const top = el('div', 'signal__top');
    top.append(el('span', 'signal__label', s.label), el('span', 'signal__pts', `+${s.points}`));
    li.append(top);
    if (s.detail) li.append(el('p', 'signal__detail', s.detail));
    const bar = el('span', 'bar');
    const fill = el('span', 'bar__fill');
    fill.style.setProperty('--w', `${Math.min(100, (s.points / 35) * 100)}%`);
    bar.append(fill);
    li.append(bar);
    list.append(li);
  }
  for (const s of info) {
    const li = el('li', 'signal signal--info');
    li.append(el('span', 'signal__label', s.label));
    if (s.detail) li.append(el('p', 'signal__detail', s.detail));
    list.append(li);
  }
  result.hidden = false;
}

async function analyse(url) {
  button.disabled = true;
  result.hidden = true;
  setStatus('Analyse en cours… (quelques secondes)');
  try {
    const res = await fetch('/api/analyse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data.erreur || (res.status === 422 ? 'Ce lien est illisible.' : "L'analyse a échoué.");
      setStatus(msg, true);
      return;
    }
    setStatus('');
    render(data);
    result.focus?.();
  } catch {
    setStatus('Impossible de joindre le service. Vérifiez votre connexion.', true);
  } finally {
    button.disabled = false;
  }
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) {
    setStatus('Collez un lien à analyser.', true);
    input.focus();
    return;
  }
  analyse(url);
});

for (const chip of document.querySelectorAll('.chip')) {
  chip.addEventListener('click', () => {
    input.value = chip.dataset.url;
    analyse(chip.dataset.url);
  });
}

// Lien partageable : /?url=… lance directement l'analyse.
const shared = new URLSearchParams(location.search).get('url');
if (shared) {
  input.value = shared;
  analyse(shared);
}
