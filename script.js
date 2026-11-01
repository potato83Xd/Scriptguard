/* ScriptGuard · analizador estático de scripts Lua.
   El código pegado se trata SIEMPRE como texto: nunca se ejecuta ni se evalúa,
   y los resultados se pintan con textContent (nunca innerHTML). */
(() => {
'use strict';

/* ───────── 1 · Configuración ───────── */
const MAX = 200000;
const WEIGHT = { low: 3, medium: 8, high: 18, critical: 35 };
const SEV = { low: 'Bajo', medium: 'Medio', high: 'Alto', critical: 'Crítico' };
const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const LEVELS = [
  { max: 5,  id: 'bajo',    name: 'Bajo',    msg: 'No se encontraron patrones preocupantes. Eso no garantiza que el script sea seguro: el análisis estático tiene límites.' },
  { max: 20, id: 'medio',   name: 'Medio',   msg: 'Hay señales que conviene revisar. Muchas aparecen también en scripts legítimos: lee cada hallazgo antes de decidir.' },
  { max: 45, id: 'alto',    name: 'Alto',    msg: 'Hay comportamientos habituales en scripts maliciosos. No lo ejecutes si no entiendes y confías en cada línea marcada.' },
  { max: 1e9, id: 'critico', name: 'Crítico', msg: 'Combina señales muy peligrosas (carga remota, robo de datos u otras). Recomendamos no ejecutarlo.' }
];
const EMPTY = 'El informe aparecerá aquí: nivel de riesgo, fragmentos sospechosos, explicación de cada uno y qué hacer.';
const SAMPLE = [
  '-- Ejemplo de prueba: no hace nada real',
  'local url = "https://pastebin.com/raw/EJEMPLO"',
  'local lllllllll = string.char(104,101,108,108,111,32,119,111)',
  'loadstring(game:HttpGet(url))()',
  'game:GetService("MarketplaceService"):PromptPurchase(game.Players.LocalPlayer, 1234567)',
  'while true do',
  '  print("hola")',
  'end'
].join('\n');

/* ───────── 2 · Reglas ───────── */
// R(id, gravedad, título, expresión, por qué es sospechoso, qué hacer)
const R = (id, sev, title, re, why, tip) => ({ id, sev, title, re, why, tip });

const RULES = [
  // Ejecución y carga de código externo
  R('rce', 'critical', 'Descarga y ejecuta código remoto', /loadstring\s*\([^\n]{0,90}?(?:HttpGet|GetAsync|HttpService|request)/gi,
    'El script baja código de internet y lo ejecuta al instante. Quien controle ese enlace puede cambiar lo que hace en cualquier momento, aunque hoy parezca inofensivo.',
    'Abre la URL en el navegador y lee el contenido. Si no puedes entenderlo, no lo ejecutes.'),
  R('ls', 'medium', 'Uso de loadstring', /\b(?:loadstring|dostring)\b/gi,
    'Convierte texto en código y lo ejecuta. Es legítimo en algunos casos, pero permite esconder lo que el script hace de verdad.',
    'Comprueba de dónde sale el texto que recibe loadstring.'),
  R('req', 'high', 'Módulo cargado por ID (require numérico)', /\brequire\s*\(\s*\d{5,}\s*\)/g,
    'Carga un módulo del catálogo de Roblox por su número. Es una técnica clásica de puertas traseras: el módulo puede cambiar sin que toques el script.',
    'Busca ese ID en el catálogo y revisa quién lo publicó.'),
  R('asset', 'medium', 'Carga de recursos externos', /\b(?:LoadAsset|InsertService|GetObjects)\b/gi,
    'Inserta objetos de otros autores en el juego. Esos objetos pueden traer scripts ocultos.',
    'Revisa el asset indicado y su autor antes de usarlo.'),
  // Red y destinos
  R('net', 'medium', 'Peticiones de red', /\b(?:HttpGet(?:Async)?|HttpPost(?:Async)?|RequestAsync|PostAsync|GetAsync|http_request|syn\.request|http\.request)\b|\brequest\s*\(\s*\{/gi,
    'Envía o recibe datos de internet. No es malo por sí mismo, pero es la vía para descargar código nuevo o sacar información de tu equipo.',
    'Comprueba a qué dirección se conecta y qué datos envía.'),
  R('hook', 'high', 'Webhook de Discord', /discord(?:app)?\.com\/api\/webhooks\//gi,
    'Un webhook envía mensajes a un canal de Discord sin autenticación. Es muy usado para recibir en secreto datos robados.',
    'Desconfía si el script no tiene un motivo claro para enviar datos fuera.'),
  R('logger', 'high', 'Dominio de registro de IP', /iplogger\.|grabify\.|2no\.co|blasze\.|leancoding\.co|stopify\.co|ipgrabber/gi,
    'Estos dominios existen para averiguar la dirección IP de quien abre el enlace.',
    'No abras ni ejecutes nada que apunte a ellos.'),
  R('short', 'medium', 'Enlace acortado', /https?:\/\/(?:bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|t\.co)\//gi,
    'Un acortador oculta el destino real del enlace.',
    'Expándelo con un verificador de enlaces antes de abrirlo.'),
  R('host', 'medium', 'Código alojado en sitios editables', /pastebin\.com\/raw|raw\.githubusercontent\.com|gist\.githubusercontent\.com|hastebin\.com|paste\.ee\/r/gi,
    'Son sitios donde el autor puede cambiar el contenido cuando quiera. Lo que revisas hoy puede ser distinto mañana.',
    'Copia el contenido, revísalo y usa esa copia en lugar del enlace.'),
  R('ipurl', 'medium', 'URL con dirección IP', /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/g,
    'Los servicios legítimos suelen usar un dominio. Una IP directa dificulta saber quién está detrás.',
    'Pregunta al autor por qué necesita conectarse a esa IP.'),
  R('url', 'low', 'URLs externas', /https?:\/\/[^\s"'<>)\]]+/gi,
    'El script menciona direcciones de internet. Revisa que cada una tenga sentido para lo que dice hacer.',
    'Visita (con cuidado) o investiga cada dominio listado.'),
  // Datos, cuenta y sistema
  R('cookie', 'critical', 'Referencia a la cookie de Roblox', /ROBLOSECURITY|_\|WARNING:-DO-NOT-SHARE|\.RBXTOKEN/gi,
    'La cookie .ROBLOSECURITY da acceso total a tu cuenta, incluso sin contraseña. Ningún script legítimo necesita leerla.',
    'No lo ejecutes. Si ya lo hiciste, cierra sesión en todos los dispositivos y cambia tu contraseña.'),
  R('hwid', 'high', 'Lectura de identificadores del dispositivo', /RbxAnalyticsService|GetClientId|\bHWID\b/gi,
    'Obtiene un identificador único de tu equipo, útil para rastrearte o para vincular datos robados.',
    'Pregunta por qué lo necesita; rara vez hay una razón válida.'),
  R('osx', 'high', 'Comandos del sistema operativo', /\bos\.(?:execute|remove|rename|getenv|exit)\b|\bio\.popen\b/g,
    'Intenta ejecutar o borrar cosas fuera de Roblox. No funciona en Roblox normal, pero indica intenciones peligrosas o un script hecho para otro entorno.',
    'No lo uses fuera de un entorno aislado y que controles.'),
  R('fs', 'medium', 'Acceso a archivos', /\b(?:writefile|readfile|appendfile|delfile|listfiles|loadfile|dofile|makefolder|delfolder)\b|\bio\.open\b/gi,
    'Lee o escribe archivos en tu dispositivo. Puede guardar configuraciones, pero también robar o borrar datos.',
    'Comprueba qué rutas toca.'),
  R('env', 'medium', 'Manipulación del entorno o ganchos', /\b(?:getfenv|setfenv|getrawmetatable|setrawmetatable|setreadonly|hookfunction|hookmetamethod|newcclosure|getgc|getrenv)\b|\bdebug\.(?:getupvalue|setupvalue|sethook)\b/gi,
    'Modifica cómo funcionan otras funciones del juego o del ejecutor. Es común en scripts avanzados y también en los que ocultan acciones.',
    'Solo es razonable si entiendes qué función se modifica y por qué.'),
  R('buy', 'medium', 'Ventanas de compra', /\b(?:PromptPurchase|PromptProductPurchase|PromptGamePassPurchase|PromptBundlePurchase|PromptPremiumPurchase|PerformPurchase)\b/gi,
    'Puede abrir pantallas de compra con Robux sin que lo pidas.',
    'Verifica el artículo y el precio antes de aceptar cualquier compra.'),
  R('tp', 'medium', 'Teletransporte a otros lugares', /\b(?:TeleportService|TeleportAsync|TeleportToPlaceInstance)\b/g,
    'Puede llevarte a otro juego, a veces uno diseñado para engañarte.',
    'Comprueba el ID del lugar de destino.'),
  R('loop', 'medium', 'Bucle infinito sin pausa', /while\s+(?:true|1)\s+do(?:(?!wait|Heartbeat|RenderStepped|Stepped|break|return)[\s\S]){0,300}?\bend\b/gi,
    'Un bucle sin espera puede congelar el juego y consumir CPU.',
    'Debe incluir task.wait() u otra pausa.'),
  R('remote', 'low', 'Eventos remotos al servidor', /:\s*(?:FireServer|InvokeServer)\s*\(/g,
    'Envía mensajes al servidor del juego. Se usa para hacer trampas o abusar de remotos, lo que puede acabar en sanciones.',
    'Entiende qué evento llama y con qué datos.'),
  R('clip', 'low', 'Acceso al portapapeles', /\b(?:setclipboard|toclipboard)\b/gi,
    'Escribe en tu portapapeles: puede sustituir lo que copiaste por otra cosa.',
    'Revisa qué texto copia.'),
  R('kick', 'low', 'Expulsión o cierre del juego', /:\s*Kick\s*\(|game\s*:\s*Shutdown/gi,
    'Puede sacarte de la partida o cerrarla.',
    'Comprueba en qué condiciones se activa.'),
  R('scam', 'medium', 'Texto típico de estafa', /free\s*robux|robux\s*(?:gratis|generator|hack)|generador\s+de\s+robux|verify\s+your\s+account|verifica\s+tu\s+cuenta/gi,
    'Promete Robux gratis o pide «verificar» tu cuenta. Es la excusa más común de las estafas.',
    'Los Robux gratis mediante scripts no existen. No introduzcas datos de tu cuenta.'),
  // Ofuscación (las ids empiezan por «o» + dígito)
  R('o1', 'low', 'Escapes numéricos en cadenas', /(?:\\\d{2,3}){8,}|(?:\\x[0-9a-f]{2}){8,}/gi,
    'Texto escrito como códigos numéricos para que no se pueda leer a simple vista.', 'Decodifícalo con una herramienta antes de fiarte.'),
  R('o2', 'low', 'Texto armado carácter a carácter', /string\.char\s*\((?:\s*\d+\s*,){5,}/gi,
    'Construye palabras con números (string.char) para que no aparezcan escritas.', 'Averigua qué texto forma.'),
  R('o3', 'low', 'Nombres de variables ilegibles', /\b[Il][Il10O_]{7,}\b/g,
    'Nombres como «IIlIlIlI» no tienen otro propósito que dificultar la lectura.', 'Si el autor no ofrece una versión legible, desconfía.'),
  R('o4', 'low', 'Líneas extremadamente largas', /[^\n]{1200,}/g,
    'Código comprimido en pocas líneas: típico de scripts minimizados u ofuscados.', 'Pide la versión sin minimizar.'),
  R('o5', 'medium', 'Bloque grande de texto codificado', /["'][A-Za-z0-9+\/=]{200,}["']/g,
    'Una cadena enorme sin sentido a simple vista suele ser código o datos escondidos (por ejemplo, base64).', 'Averigua qué contiene y cómo se usa.'),
  R('o6', 'medium', 'Firma de ofuscador conocido', /\b(?:Luraph|Moonsec|IronBrew|Prometheus|WeAreDevs|PSU)\b|obfuscat/gi,
    'El texto menciona herramientas que ofuscan código. Algunos autores las usan para proteger su trabajo.', 'Pide al autor una versión legible.'),
  R('o7', 'low', 'Acceso dinámico a funciones', /\b_G\s*\[|\b_ENV\s*\[|getfenv\s*\(\s*\d*\s*\)\s*\[|select\s*\(\s*["']#["']/g,
    'Llama funciones por su nombre en texto, lo que esconde qué se está usando.', 'Revisa qué nombres se construyen.')
];

/* ───────── 3 · Análisis ───────── */
// Sustituye los comentarios por espacios (respetando cadenas) para conservar los números de línea.
function stripComments(s) {
  let out = '', i = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    if (c === '-' && s[i + 1] === '-') {
      const m = /^--\[(=*)\[/.exec(s.slice(i, i + 40));
      let e;
      if (m) { const close = ']' + m[1] + ']'; e = s.indexOf(close, i + m[0].length); e = e < 0 ? n : e + close.length; }
      else { e = s.indexOf('\n', i); if (e < 0) e = n; }
      out += s.slice(i, e).replace(/[^\n]/g, ' '); i = e;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && s[j] !== c && s[j] !== '\n') { if (s[j] === '\\') j++; j++; }
      out += s.slice(i, j + 1); i = j + 1;
    } else if (c === '[' && /^\[=*\[/.test(s.slice(i, i + 40))) {
      const m = /^\[(=*)\[/.exec(s.slice(i, i + 40)), close = ']' + m[1] + ']';
      let e = s.indexOf(close, i + m[0].length); e = e < 0 ? n : e + close.length;
      out += s.slice(i, e); i = e;
    } else { out += c; i++; }
  }
  return out;
}

function analyze(src) {
  const text = src.replace(/\r\n?/g, '\n');
  const clean = stripComments(text);
  const lines = text.split('\n');
  const starts = [0];
  for (let i = 0; i < clean.length; i++) if (clean.charCodeAt(i) === 10) starts.push(i + 1);
  const lineOf = pos => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m] <= pos) lo = m; else hi = m - 1; } return lo + 1; };

  const found = [];
  for (const r of RULES) {
    const hits = [...clean.matchAll(r.re)];
    if (!hits.length) continue;
    const f = { ...r, n: hits.length, lines: [...new Set(hits.map(h => lineOf(h.index)))] };
    if (r.id === 'url') f.note = 'Dominios: ' + [...new Set(hits.map(h => h[0].replace(/^https?:\/\//i, '').split(/[\/:?#]/)[0].toLowerCase()))].slice(0, 8).join(', ');
    found.push(f);
  }

  // Combinaciones: señales que juntas pesan más que por separado
  const ids = new Set(found.map(f => f.id));
  const has = (...a) => a.some(x => ids.has(x));
  const obf = found.filter(f => /^o\d/.test(f.id)).length;
  const combo = (id, sev, title, why, tip) => found.push({ id, sev, title, why, tip, n: 0, lines: [] });
  if (has('net', 'hook', 'rce') && has('cookie', 'hwid'))
    combo('c1', 'critical', 'Posible robo de datos', 'Combina lectura de datos sensibles (cuenta o dispositivo) con conexión a internet. Es el patrón típico de los scripts que roban cuentas.', 'No lo ejecutes.');
  if (obf >= 2 && has('ls', 'rce', 'net', 'req'))
    combo('c2', 'high', 'Ofuscado y con ejecución dinámica', 'El código está difícil de leer y además descarga o ejecuta código. Es una mala combinación: no puedes comprobar qué hará.', 'Exige una versión legible antes de usarlo.');
  else if (obf >= 3)
    combo('c3', 'medium', 'Varias señales de ofuscación', 'La ofuscación no prueba que haya malware (hay autores que protegen así su trabajo), pero impide verificar qué hace el script.', 'Trátalo con más desconfianza que uno legible.');

  found.sort((a, b) => ORDER[a.sev] - ORDER[b.sev]);
  const score = found.reduce((t, f) => t + WEIGHT[f.sev], 0);
  let idx = LEVELS.findIndex(l => score < l.max);
  if (found.some(f => f.sev === 'critical')) idx = Math.max(idx, 2);

  const flagged = new Map();
  for (const f of found) for (const l of f.lines) {
    const cur = flagged.get(l);
    if (!cur || ORDER[f.sev] < ORDER[cur]) flagged.set(l, f.sev);
  }
  return { found, score, level: LEVELS[idx], flagged, lines, chars: src.length };
}

/* ───────── 4 · Interfaz ───────── */
const $ = id => document.getElementById(id);
const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
const code = $('code'), gutter = $('gutter'), report = $('report');
let flagged = new Map(), shown = 1;

function updateEditor(force) {
  const n = code.value.split('\n').length, len = code.value.length;
  $('lines').textContent = n + (n === 1 ? ' línea' : ' líneas');
  $('chars').textContent = len.toLocaleString('es') + ' / ' + MAX.toLocaleString('es');
  $('chars').className = len >= MAX ? 'full' : '';
  if (n !== shown || force) {
    const frag = document.createDocumentFragment();
    for (let i = 1; i <= n; i++) frag.append(el('span', flagged.has(i) ? 'f-' + flagged.get(i) : '', i));
    gutter.replaceChildren(frag);
    shown = n;
  }
  gutter.scrollTop = code.scrollTop;
}

function render(a) {
  const L = a.level, root = document.createDocumentFragment();

  const sum = el('div', 'sum ' + L.id), left = el('div'), right = el('div'), meter = el('div', 'meter'), bar = el('i'), stats = el('p', 'stats');
  left.append(el('p', 'mu', 'Nivel de riesgo'), el('p', 'lvl', L.name));
  meter.append(bar);
  stats.append(el('span', null, a.lines.length + ' líneas'), el('span', null, a.found.length + ' hallazgos'), el('span', null, 'Puntuación ' + a.score));
  right.append(el('p', null, L.msg), meter, stats);
  sum.append(left, right);
  root.append(sum);
  requestAnimationFrame(() => { bar.style.width = Math.min(100, a.score) + '%'; });

  root.append(el('h3', 'rep-h', 'Hallazgos'));
  if (!a.found.length) root.append(el('p', 'empty', 'No se encontró ningún patrón conocido. Recuerda que esto no demuestra que el script sea seguro.'));
  for (const f of a.found) {
    const d = el('details', 'fd'), s = el('summary'), b = el('div', 'fb');
    d.open = f.sev === 'critical' || f.sev === 'high';
    s.append(el('span', 'tag ' + f.sev, SEV[f.sev]), el('span', null, f.title + (f.n > 1 ? ' (×' + f.n + ')' : '')));
    b.append(el('p', null, f.why));
    if (f.note) b.append(el('p', 'mu', f.note));
    if (f.lines.length) {
      b.append(el('p', 'mu', 'Líneas: ' + f.lines.slice(0, 12).join(', ') + (f.lines.length > 12 ? '…' : '')));
      const snip = el('div', 'snip');
      for (const n of f.lines.slice(0, 4)) {
        const t = a.lines[n - 1].trim(), row = el('div');
        row.append(el('b', null, n), document.createTextNode(t.length > 160 ? t.slice(0, 160) + '…' : t));
        snip.append(row);
      }
      b.append(snip);
    }
    const tip = el('p', 'tip'); tip.append(el('strong', null, 'Qué hacer: '), document.createTextNode(f.tip));
    b.append(tip);
    d.append(s, b);
    root.append(d);
  }

  const recs = [...new Set(a.found.slice(0, 4).map(f => f.tip))];
  if (a.score >= 20) recs.unshift('No ejecutes este script a menos que lo entiendas por completo y confíes en su autor.');
  recs.push('Nunca compartas tu contraseña ni la cookie .ROBLOSECURITY con nadie.');
  const ul = el('ul', 'recs');
  recs.forEach(r => ul.append(el('li', null, r)));
  root.append(el('h3', 'rep-h', 'Recomendaciones'), ul);

  root.append(el('p', 'note', 'Informe orientativo. ScriptGuard analiza el texto sin ejecutarlo: no puede confirmar qué hace realmente el script, no ve el código que descargaría de internet y puede dar falsos positivos o pasar por alto riesgos. Un nivel bajo no es una garantía.'));
  report.replaceChildren(root);
}

function run() {
  if (!code.value.trim()) { report.replaceChildren(el('p', 'empty', 'Pega un script Lua en el editor para analizarlo.')); return; }
  const a = analyze(code.value);
  flagged = a.flagged;
  updateEditor(true);
  render(a);
  report.scrollIntoView({ behavior: 'smooth', block: 'start' });
  report.focus({ preventScroll: true });
}

code.addEventListener('input', () => { if (flagged.size) flagged = new Map(); updateEditor(!!gutter.querySelector('[class]')); });
code.addEventListener('scroll', () => { gutter.scrollTop = code.scrollTop; });
$('analyze').addEventListener('click', run);
$('clear').addEventListener('click', () => {
  code.value = ''; flagged = new Map(); updateEditor(true);
  report.replaceChildren(el('p', 'empty', EMPTY));
  code.focus();
});
$('sample').addEventListener('click', () => { code.value = SAMPLE; flagged = new Map(); updateEditor(true); code.scrollTop = 0; });

// Menú móvil
const burger = $('burger'), menu = $('menu');
const setMenu = open => { menu.classList.toggle('open', open); burger.setAttribute('aria-expanded', open); burger.setAttribute('aria-label', open ? 'Cerrar menú' : 'Abrir menú'); };
burger.addEventListener('click', () => setMenu(!menu.classList.contains('open')));
menu.addEventListener('click', e => { if (e.target.tagName === 'A') setMenu(false); });

updateEditor(true);
})();
