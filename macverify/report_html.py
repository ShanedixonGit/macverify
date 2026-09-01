import html

from . import i18n, quickfix, scope as scope_mod
from .findings import SEVERITY_ORDER

MAX_ROWS = 250
MAX_DEPTH = 6

STYLE = """
:root {
  color-scheme: light;
  --bg: #ffffff;
  --surface: #f7f7f6;
  --surface-2: #f1f1ef;
  --ink: #17181a;
  --ink-2: #55575c;
  --ink-3: #86888e;
  --line: #e4e4e1;
  --line-2: #d2d2ce;
  --critical: #9d1f1f;
  --warning: #7c5312;
  --info: #2b4a86;
  --critical-bg: #fbeeee;
  --warning-bg: #fbf4e8;
  --info-bg: #eef2fa;
  --f1: #3d4046;
  --f2: #70737a;
  --f3: #a0a3aa;
  --f4: #c8cad0;
  --radius: 6px;
  --step-0: 0.8125rem;
  --step-1: 0.875rem;
  --step-2: 0.9375rem;
  --step-3: 1.0625rem;
  --step-4: 1.375rem;
  --step-5: 1.75rem;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #16171a;
    --surface: #1d1f22;
    --surface-2: #232529;
    --ink: #e9e9e7;
    --ink-2: #a8aaaf;
    --ink-3: #7c7e85;
    --line: #2a2c31;
    --line-2: #3a3d43;
    --critical: #f08a8a;
    --warning: #e0b166;
    --info: #93b2e8;
    --critical-bg: #2a1c1c;
    --warning-bg: #2a2417;
    --info-bg: #1b2333;
  --f1: #d9dbe0;
  --f2: #9a9da5;
  --f3: #6c6f77;
  --f4: #43464c;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; scrollbar-color: var(--line-2) transparent; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--sans);
  font-size: var(--step-2);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  font-variant-numeric: tabular-nums;
}
::selection { background: var(--surface-2); color: var(--ink); }
:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; border-radius: 3px; }
:where(a) { color: inherit; }
.wrap { max-width: 1060px; margin: 0 auto; padding: 0 32px; }

header.page { padding: 64px 0 28px; }
.eyebrow-free h1 { font-size: var(--step-5); font-weight: 620; margin: 0 0 6px; letter-spacing: -0.018em; }
h1 { font-size: var(--step-5); font-weight: 620; margin: 0 0 6px; letter-spacing: -0.018em; }
.ident { color: var(--ink-2); font-size: var(--step-1); margin: 0; }
.ident b { font-weight: 600; color: var(--ink); }

.vitals { display: grid; grid-template-columns: repeat(auto-fit, minmax(148px, 1fr)); gap: 1px; margin: 28px 0 4px; background: var(--line); border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; }
.vital { background: var(--bg); padding: 14px 16px; }
.vital dt { font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.07em; color: var(--ink-3); margin: 0 0 5px; font-weight: 600; }
.vital dd { margin: 0; font-size: var(--step-3); font-weight: 560; letter-spacing: -0.01em; }
.vital dd small { display: block; font-size: var(--step-0); font-weight: 400; color: var(--ink-2); letter-spacing: 0; margin-top: 2px; }
.vital.is-critical dd { color: var(--critical); }
.vital.is-warning dd { color: var(--warning); }

nav.bar { position: sticky; top: 0; z-index: 30; background: var(--bg); border-bottom: 1px solid var(--line); margin-top: 24px; }
.bar-inner { max-width: 1060px; margin: 0 auto; padding: 10px 32px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.tabs { display: flex; flex: 0 1 auto; gap: 2px; background: var(--surface); border-radius: var(--radius); padding: 3px; }
.tab { font: inherit; font-size: var(--step-1); font-weight: 520; color: var(--ink-2); background: none; border: 0; padding: 6px 14px; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 7px; white-space: nowrap; }
.tab:hover { color: var(--ink); }
.tab[aria-selected="true"] { background: var(--bg); color: var(--ink); box-shadow: 0 1px 2px rgba(0,0,0,0.09); }
.tab .n { font-size: var(--step-0); color: var(--ink-3); font-variant-numeric: tabular-nums; }
.tab[aria-selected="true"] .n { color: var(--ink-2); }
.spacer { flex: 1 1 auto; }
.field { position: relative; display: flex; align-items: center; }
.field input { font: inherit; font-size: var(--step-1); color: var(--ink); background: var(--surface); border: 1px solid transparent; border-radius: var(--radius); padding: 6px 30px 6px 11px; width: 210px; }
.field input::placeholder { color: var(--ink-3); }
.field input:focus { border-color: var(--line-2); background: var(--bg); outline: none; }
.field button { position: absolute; right: 4px; font: inherit; font-size: var(--step-0); line-height: 1; color: var(--ink-3); background: none; border: 0; cursor: pointer; padding: 5px 6px; border-radius: 4px; }
.field button:hover { color: var(--ink); }

main { padding: 8px 0 96px; }
.view[hidden] { display: none; }
.view-intro { color: var(--ink-2); font-size: var(--step-1); margin: 24px 0 4px; max-width: 68ch; }

.index { display: flex; flex-wrap: wrap; gap: 6px 8px; margin: 18px 0 34px; }
.chip { font-size: var(--step-0); color: var(--ink-2); text-decoration: none; border: 1px solid var(--line); border-radius: 100px; padding: 4px 11px; white-space: nowrap; }
.chip:hover { border-color: var(--line-2); color: var(--ink); }
.chip .n { color: var(--ink-3); margin-left: 5px; font-variant-numeric: tabular-nums; }

.group { margin: 0 0 34px; scroll-margin-top: 72px; }
.group > h3 { font-size: var(--step-3); font-weight: 600; margin: 0 0 2px; letter-spacing: -0.01em; display: flex; align-items: baseline; gap: 10px; }
.group > h3 .n { font-size: var(--step-0); font-weight: 400; color: var(--ink-3); }
.group-rule { height: 1px; background: var(--line); margin: 12px 0 0; }

.finding { padding: 22px 0; border-bottom: 1px solid var(--line); }
.finding:last-child { border-bottom: 0; }
.f-top { display: flex; align-items: baseline; gap: 14px; }
.f-title { font-size: var(--step-2); font-weight: 600; margin: 0; letter-spacing: -0.005em; flex: 1 1 auto; }
.f-tags { display: flex; align-items: center; gap: 10px; flex: none; font-size: var(--step-0); color: var(--ink-3); white-space: nowrap; }
.sev { font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
.sev::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; flex: none; }
.sev.critical { color: var(--critical); }
.sev.warning { color: var(--warning); }
.sev.info { color: var(--info); }
.f-why { color: var(--ink-2); font-size: var(--step-1); margin: 6px 0 0; max-width: 78ch; }
.f-row { display: grid; grid-template-columns: 78px 1fr; gap: 12px; align-items: start; margin-top: 12px; }
.f-label { font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.07em; color: var(--ink-3); font-weight: 600; padding-top: 7px; }
.f-evidence { font-family: var(--mono); font-size: var(--step-0); color: var(--ink-2); background: var(--surface); border-radius: var(--radius); padding: 7px 11px; word-break: break-word; white-space: pre-wrap; }
.cmd { display: flex; align-items: flex-start; gap: 8px; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: 7px 7px 7px 11px; }
.cmd code { flex: 1 1 auto; font-family: var(--mono); font-size: var(--step-0); white-space: pre-wrap; word-break: break-word; padding-top: 1px; }
.cmd button { flex: none; font: inherit; font-size: var(--step-0); font-weight: 500; color: var(--ink-2); background: var(--bg); border: 1px solid var(--line-2); border-radius: 4px; padding: 3px 10px; cursor: pointer; }
.cmd button:hover { color: var(--ink); border-color: var(--ink-3); }
.cmd button.done { color: var(--info); border-color: var(--info); }
.f-note { color: var(--ink-3); font-size: var(--step-1); font-style: italic; padding-top: 6px; }

.def { border-bottom: 1px dashed var(--line-2); cursor: help; }
.def:hover, .def:focus-visible { border-bottom-color: var(--ink-3); color: var(--ink); }
#tip { position: fixed; z-index: 60; max-width: 330px; background: var(--ink); color: var(--bg); font-size: var(--step-0); line-height: 1.5; padding: 10px 12px; border-radius: 7px; box-shadow: 0 8px 24px rgba(0,0,0,0.22), 0 2px 6px rgba(0,0,0,0.12); pointer-events: none; opacity: 0; transform: translateY(3px); transition: opacity 140ms ease-out, transform 140ms ease-out; }
#tip[data-show] { opacity: 1; transform: translateY(0); }
#tip b { display: block; font-weight: 600; margin-bottom: 3px; }
#tip .how { display: block; margin-top: 6px; opacity: 0.72; font-family: var(--mono); font-size: 0.75rem; }
.chart { margin: 2px 0 14px; }
.meter { display: flex; height: 9px; border-radius: 999px; overflow: hidden; background: var(--surface-2); print-color-adjust: exact; -webkit-print-color-adjust: exact; }
.meter span { display: block; height: 100%; }
.legend { display: flex; flex-wrap: wrap; gap: 3px 14px; margin-top: 9px; font-size: 0.75rem; color: var(--ink-2); }
.legend span { white-space: nowrap; }
.legend i { width: 8px; height: 8px; border-radius: 2px; display: inline-block; margin-right: 6px; font-style: normal; print-color-adjust: exact; -webkit-print-color-adjust: exact; }
.legend b { font-weight: 550; color: var(--ink); }
.fchart { margin: 26px 0 4px; }
.fchart h3 { font-size: var(--step-2); font-weight: 600; margin: 0 0 12px; letter-spacing: -0.008em; }
.fchart a { display: grid; grid-template-columns: minmax(120px, 190px) 1fr 62px; align-items: center; gap: 14px; padding: 6px 0; text-decoration: none; color: inherit; border-radius: 4px; }
.fchart a:hover .fname { color: var(--ink); }
.fname { font-size: var(--step-0); color: var(--ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fbar { height: 8px; border-radius: 999px; display: flex; overflow: hidden; background: var(--surface-2); print-color-adjust: exact; -webkit-print-color-adjust: exact; }
.fbar span { display: block; height: 100%; }
.fnum { font-size: 0.75rem; color: var(--ink-3); text-align: right; font-variant-numeric: tabular-nums; }
.fnum b { color: var(--warning); font-weight: 600; }
.lead { font-size: var(--step-3); line-height: 1.5; letter-spacing: -0.008em; margin: 26px 0 4px; max-width: 62ch; font-weight: 480; }
.lead a { color: inherit; text-decoration: none; border-bottom: 2px solid var(--line-2); }
.lead a:hover { border-bottom-color: var(--ink); }
.lead .c-critical { color: var(--critical); font-weight: 600; }
.lead .c-warning { color: var(--warning); font-weight: 600; }
.lead-sub { color: var(--ink-2); font-size: var(--step-1); margin: 6px 0 0; max-width: 68ch; }
.panels { column-width: 296px; column-gap: 44px; margin-top: 30px; }
.panel { padding: 20px 0 10px; border-top: 1px solid var(--line); break-inside: avoid; -webkit-column-break-inside: avoid; display: inline-block; width: 100%; vertical-align: top; }
.panel h3 { font-size: var(--step-2); font-weight: 600; margin: 0 0 8px; letter-spacing: -0.008em; display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.panel h3 a { font-size: var(--step-0); font-weight: 400; color: var(--ink-3); text-decoration: none; white-space: nowrap; }
.panel h3 a:hover { color: var(--ink); }
.panel .facts { grid-template-columns: minmax(112px, 152px) 1fr; margin: 0; }
.panel .facts dt, .panel .facts dd { font-size: var(--step-0); padding: 5px 12px 5px 0; }
.panel .facts dd { padding-right: 0; }
.panel .facts dt:first-of-type, .panel .facts dd:first-of-type { border-top: 0; padding-top: 0; }
.panel .degraded-note { font-size: var(--step-0); color: var(--ink-3); margin: 6px 0 0; }
.domain { margin: 0 0 12px; border-top: 1px solid var(--line); padding: 26px 0 4px; scroll-margin-top: 72px; }
.domain:first-of-type { border-top: 0; }
.d-head { display: flex; align-items: baseline; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.d-head h3 { font-size: var(--step-3); font-weight: 600; margin: 0; letter-spacing: -0.01em; }
.status { font-size: var(--step-0); color: var(--ink-2); border: 1px solid var(--line); border-radius: 100px; padding: 2px 10px; }
.status.degraded { color: var(--warning); border-color: color-mix(in srgb, var(--warning) 35%, transparent); }
.d-head a { font-size: var(--step-0); color: var(--ink-2); text-decoration: none; border-bottom: 1px solid var(--line-2); }
.d-head a:hover { color: var(--ink); }
.facts { display: grid; grid-template-columns: minmax(150px, 210px) 1fr; gap: 0; margin: 0 0 18px; }
.facts dt { font-size: var(--step-1); color: var(--ink-2); padding: 7px 16px 7px 0; border-top: 1px solid var(--line); }
.facts dd { font-size: var(--step-1); margin: 0; padding: 7px 0; border-top: 1px solid var(--line); word-break: break-word; }
.facts dd.is-critical { color: var(--critical); font-weight: 550; }
.facts dd.is-warning { color: var(--warning); font-weight: 550; }
.facts dd small { color: var(--ink-3); }

details.raw { border-top: 1px solid var(--line); }
details.raw > summary { cursor: pointer; padding: 11px 0; font-size: var(--step-1); color: var(--ink-2); list-style: none; display: flex; align-items: center; gap: 8px; }
details.raw > summary::-webkit-details-marker { display: none; }
details.raw > summary::before { content: "+"; font-family: var(--mono); color: var(--ink-3); }
details.raw[open] > summary::before { content: "\\2212"; }
details.raw > summary:hover { color: var(--ink); }
.raw-body { padding: 4px 0 22px; }

.tree { font-size: var(--step-0); }
.kv { display: grid; grid-template-columns: minmax(130px, 230px) 1fr; gap: 0; margin: 2px 0 10px; }
.kv > .k { color: var(--ink-3); padding: 5px 14px 5px 0; border-top: 1px solid var(--line); }
.kv > .v { padding: 5px 0; border-top: 1px solid var(--line); word-break: break-word; }
.tree table { border-collapse: collapse; width: 100%; font-size: var(--step-0); margin: 2px 0 12px; }
.tree th, .tree td { text-align: left; vertical-align: top; padding: 6px 14px 6px 0; border-top: 1px solid var(--line); }
.tree th { color: var(--ink-3); font-weight: 600; white-space: nowrap; font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.06em; }
.tree pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-family: var(--mono); }
.mono { font-family: var(--mono); }
.empty { color: var(--ink-3); }
.scroll { overflow-x: auto; max-width: 100%; }
.no-match { color: var(--ink-2); font-size: var(--step-1); padding: 40px 0; text-align: center; display: none; }
.no-match b { color: var(--ink); font-weight: 600; }

footer { border-top: 1px solid var(--line); padding: 22px 0 64px; color: var(--ink-3); font-size: var(--step-0); }

@media (max-width: 720px) {
  .wrap, .bar-inner { padding-left: 20px; padding-right: 20px; }
  .bar-inner { gap: 8px; }
  .tabs { max-width: 100%; overflow-x: auto; scrollbar-width: none; -webkit-overflow-scrolling: touch; }
  .tabs::-webkit-scrollbar { display: none; }
  .spacer { display: none; }
  .field { width: 100%; }
  .field input { width: 100%; }
  .fchart a { grid-template-columns: 1fr 52px; }
  .fchart .fbar { grid-column: 1 / -1; }
  header.page { padding-top: 40px; }
  .f-row { grid-template-columns: 1fr; gap: 5px; }
  .f-label { padding-top: 0; }
  .facts, .kv { grid-template-columns: 1fr; }
  .facts dd, .kv > .v { border-top: 0; padding-top: 0; padding-bottom: 9px; }
  .f-top { flex-wrap: wrap; }
}
@media print {
  #tip { display: none !important; }
  :root { color-scheme: light; --bg: #fff; --ink: #000; --ink-2: #333; --ink-3: #555; --line: #ddd; --surface: #f6f6f6; }
  body { font-size: 10.5pt; }
  .wrap, .bar-inner { max-width: none; padding: 0 10mm; }
  nav.bar, .field, .tabs, .index, .cmd button, .no-match { display: none !important; }
  .view[hidden] { display: block !important; }
  details.raw > summary { display: none; }
  .vitals { break-inside: avoid; }
  .finding, .domain, .group > h3 { break-inside: avoid; }
  .group > h3, .d-head { break-after: avoid; }
  a { text-decoration: none; }
}

.qf-tier { margin: 0 0 30px; scroll-margin-top: 72px; }
.qf-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; border-top: 1px solid var(--line); padding-top: 18px; }
.qf-head h3 { font-size: var(--step-3); font-weight: 600; margin: 0; letter-spacing: -0.01em; display: flex; align-items: baseline; gap: 10px; }
.qf-head h3 .n { font-size: var(--step-0); font-weight: 400; color: var(--ink-3); }
.qf-head .grow { flex: 1 1 auto; }
.qf-tier.t-inspect h3::before, .qf-tier.t-apply h3::before, .qf-tier.t-careful h3::before { content: ""; width: 7px; height: 7px; border-radius: 50%; flex: none; align-self: center; }
.qf-tier.t-inspect h3::before { background: var(--info); }
.qf-tier.t-apply h3::before { background: var(--f2); }
.qf-tier.t-careful h3::before { background: var(--warning); }
.qf-hint { color: var(--ink-2); font-size: var(--step-1); margin: 5px 0 12px; max-width: 74ch; }
.qf-item { padding: 13px 0; border-bottom: 1px solid var(--line); }
.qf-item:last-child { border-bottom: 0; }
.qf-for { font-size: var(--step-0); color: var(--ink-3); margin: 7px 0 0; max-width: 82ch; }
.qf-for b { color: var(--ink-2); font-weight: 550; }
.qf-note { font-size: var(--step-0); color: var(--ink-3); font-style: italic; margin: 4px 0 0; }
.badge { font-size: 0.625rem; text-transform: uppercase; letter-spacing: 0.07em; font-weight: 650; border-radius: 100px; padding: 2px 8px; border: 1px solid currentColor; color: var(--ink-3); margin-left: 8px; white-space: nowrap; }
.badge.sudo { color: var(--warning); }
.badge.oneway { color: var(--critical); }
.btn { font: inherit; font-size: var(--step-0); font-weight: 500; color: var(--ink-2); background: var(--bg); border: 1px solid var(--line-2); border-radius: 4px; padding: 4px 11px; cursor: pointer; }
.btn:hover { color: var(--ink); border-color: var(--ink-3); }
.btn.done { color: var(--info); border-color: var(--info); }
details.qf-manual { border-top: 1px solid var(--line); margin: 6px 0 0; }
details.qf-manual > summary { cursor: pointer; padding: 16px 0 6px; font-size: var(--step-3); font-weight: 600; letter-spacing: -0.01em; list-style: none; display: flex; align-items: center; gap: 9px; }
details.qf-manual > summary::-webkit-details-marker { display: none; }
details.qf-manual > summary::before { content: "+"; font-family: var(--mono); font-weight: 400; color: var(--ink-3); }
details.qf-manual[open] > summary::before { content: "\2212"; }
details.qf-manual > summary .n { font-size: var(--step-0); font-weight: 400; color: var(--ink-3); }
.step { padding: 12px 0; border-bottom: 1px solid var(--line); }
.step:last-child { border-bottom: 0; }
.step p { margin: 0; font-size: var(--step-1); }
.av { border: 1px solid var(--line); border-left: 3px solid var(--warning); border-radius: var(--radius); padding: 20px 22px; margin: 34px 0 0; background: var(--surface); break-inside: avoid; }
.av h3 { font-size: var(--step-3); font-weight: 600; margin: 0 0 6px; letter-spacing: -0.01em; }
.av p { color: var(--ink-2); font-size: var(--step-1); margin: 0 0 14px; max-width: 74ch; }
.av p:last-child { margin-bottom: 0; }
.av dl { display: grid; grid-template-columns: minmax(150px, 210px) 1fr; gap: 0; margin: 0 0 14px; }
.av dt { font-size: var(--step-1); font-weight: 560; padding: 8px 16px 8px 0; border-top: 1px solid var(--line-2); }
.av dd { font-size: var(--step-1); color: var(--ink-2); margin: 0; padding: 8px 0; border-top: 1px solid var(--line-2); }
.av dd code { font-family: var(--mono); font-size: var(--step-0); }
.av dd small { display: block; color: var(--ink-3); margin-top: 3px; }
details.scope { border-top: 1px solid var(--line); margin-top: 44px; }
details.scope > summary { cursor: pointer; padding: 16px 0 6px; font-size: var(--step-3); font-weight: 600; letter-spacing: -0.01em; list-style: none; display: flex; align-items: center; gap: 9px; }
details.scope > summary::-webkit-details-marker { display: none; }
details.scope > summary::before { content: "+"; font-family: var(--mono); font-weight: 400; color: var(--ink-3); }
details.scope[open] > summary::before { content: "\2212"; }
.scope-body { padding: 6px 0 14px; }
.scope-body h4 { font-size: var(--step-2); font-weight: 600; margin: 20px 0 8px; letter-spacing: -0.008em; }
.scope-body > p { color: var(--ink-2); font-size: var(--step-1); margin: 0; max-width: 76ch; }
.scope-body ul { margin: 0; padding-left: 19px; }
.scope-body li { color: var(--ink-2); font-size: var(--step-1); margin: 0 0 8px; max-width: 82ch; }
.compat { margin: 26px 0 0; border: 1px solid var(--line); border-radius: var(--radius); padding: 16px 18px; }
.compat h3 { font-size: var(--step-2); font-weight: 600; margin: 0 0 8px; letter-spacing: -0.008em; }
.compat ul { margin: 0; padding-left: 19px; }
.compat li { font-size: var(--step-0); color: var(--ink-2); margin: 0 0 6px; max-width: 84ch; }
.compat li b { color: var(--ink); font-weight: 600; }
.compat.has-warning { border-left: 3px solid var(--warning); }
@media (max-width: 720px) {
  .av dl { grid-template-columns: 1fr; }
  .av dd { border-top: 0; padding-top: 0; padding-bottom: 10px; }
}
@media print {
  details.scope, details.qf-manual { display: block; }
  details.scope > summary, details.qf-manual > summary { display: block; }
  .qf-head .btn { display: none !important; }
}
"""

SCRIPT = """
(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  var views = {};
  Array.prototype.forEach.call(document.querySelectorAll(".view"), function (view) { views[view.id] = view; });

  function select(name, remember) {
    tabs.forEach(function (tab) {
      var on = tab.getAttribute("data-view") === name;
      tab.setAttribute("aria-selected", on ? "true" : "false");
      tab.setAttribute("tabindex", on ? "0" : "-1");
    });
    Object.keys(views).forEach(function (key) { views[key].hidden = key !== name; });
    if (remember && history.replaceState) { history.replaceState(null, "", "#" + name); }
    applyFilter();
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () { select(tab.getAttribute("data-view"), true); });
    tab.addEventListener("keydown", function (event) {
      var index = tabs.indexOf(tab);
      var next = event.key === "ArrowRight" ? index + 1 : event.key === "ArrowLeft" ? index - 1 : -1;
      if (next < 0 || next >= tabs.length) { return; }
      event.preventDefault();
      tabs[next].focus();
      select(tabs[next].getAttribute("data-view"), true);
    });
  });

  var search = document.getElementById("filter");
  var clear = document.getElementById("filter-clear");

  function applyFilter() {
    var term = (search && search.value || "").trim().toLowerCase();
    if (clear) { clear.hidden = !term; }
    Object.keys(views).forEach(function (key) {
      var view = views[key];
      if (view.hidden) { return; }
      var shown = 0;
      Array.prototype.forEach.call(view.querySelectorAll("[data-search]"), function (item) {
        var hit = !term || item.getAttribute("data-search").indexOf(term) !== -1;
        item.hidden = !hit;
        if (hit) { shown += 1; }
      });
      Array.prototype.forEach.call(view.querySelectorAll(".group, .domain, .qf-tier"), function (group) {
        var visible = group.querySelectorAll("[data-search]:not([hidden])").length;
        group.hidden = term ? visible === 0 : false;
      });
      var note = view.querySelector(".no-match");
      if (note) {
        note.style.display = term && shown === 0 ? "block" : "none";
        var slot = note.querySelector("b");
        if (slot) { slot.textContent = term; }
      }
    });
  }

  if (search) {
    search.addEventListener("input", applyFilter);
    search.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { search.value = ""; applyFilter(); search.blur(); }
    });
  }
  if (clear) {
    clear.addEventListener("click", function () { search.value = ""; applyFilter(); search.focus(); });
  }
  document.addEventListener("keydown", function (event) {
    if (event.key === "/" && document.activeElement !== search) { event.preventDefault(); search.focus(); }
  });

  function copy(text, button) {
    var label = button.textContent;
    function done() {
      button.textContent = button.getAttribute("data-copied");
      button.classList.add("done");
      setTimeout(function () { button.textContent = label; button.classList.remove("done"); }, 1400);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
    } else { fallback(text, done); }
  }
  function fallback(text, done) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); done(); } catch (error) { button = null; }
    document.body.removeChild(area);
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest(".cmd button") : null;
    if (!button) { return; }
    var code = button.parentNode.querySelector("code");
    if (code) { copy(code.textContent, button); }
  });


  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-copy-block]") : null;
    if (!button) { return; }
    var list = document.getElementById(button.getAttribute("data-copy-block"));
    if (!list) { return; }
    var lines = Array.prototype.map.call(list.querySelectorAll(".qf-item:not([hidden]) code"), function (code) {
      return code.textContent;
    });
    if (lines.length) { copy(lines.join("\n") + "\n", button); }
  });

  document.addEventListener("click", function (event) {
    var link = event.target.closest ? event.target.closest("a[data-goto]") : null;
    if (!link) { return; }
    var view = link.getAttribute("data-goto");
    if (views[view] && views[view].hidden) { event.preventDefault(); select(view, true); location.hash = link.getAttribute("href").slice(1); }
  });

  window.addEventListener("beforeprint", function () {
    Array.prototype.forEach.call(document.querySelectorAll("details.raw, details.scope, details.qf-manual"), function (node) { node.open = true; });
  });


  var tip = document.getElementById("tip");
  var tipFor = null;
  function showTip(node) {
    if (!tip) { return; }
    tipFor = node;
    while (tip.firstChild) { tip.removeChild(tip.firstChild); }
    var title = document.createElement("b");
    title.textContent = node.textContent;
    var what = document.createElement("span");
    what.textContent = node.getAttribute("data-what") || "";
    var how = document.createElement("span");
    how.className = "how";
    how.textContent = node.getAttribute("data-how") || "";
    tip.appendChild(title);
    tip.appendChild(what);
    tip.appendChild(how);
    tip.setAttribute("data-show", "");
    tip.setAttribute("aria-hidden", "false");
    var box = node.getBoundingClientRect();
    var size = tip.getBoundingClientRect();
    var left = Math.min(Math.max(10, box.left), window.innerWidth - size.width - 10);
    var top = box.bottom + 9;
    if (top + size.height > window.innerHeight - 10) { top = Math.max(10, box.top - size.height - 9); }
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }
  function hideTip() {
    if (!tip) { return; }
    tipFor = null;
    tip.removeAttribute("data-show");
    tip.setAttribute("aria-hidden", "true");
  }
  document.addEventListener("mouseover", function (event) {
    var node = event.target.closest ? event.target.closest(".def") : null;
    if (node) { showTip(node); } else if (tipFor && !(event.target.closest && event.target.closest("#tip"))) { hideTip(); }
  });
  document.addEventListener("focusin", function (event) {
    var node = event.target.closest ? event.target.closest(".def") : null;
    if (node) { showTip(node); } else { hideTip(); }
  });
  document.addEventListener("keydown", function (event) { if (event.key === "Escape") { hideTip(); } });
  window.addEventListener("scroll", hideTip, true);
  window.addEventListener("resize", hideTip);

  var initial = (location.hash || "").replace("#", "");
  select(views[initial] ? initial : tabs[0].getAttribute("data-view"), false);
})();
"""


def _e(value):
    return html.escape(str(value), quote=True)


def _dig(payload, *path):
    node = payload
    for key in path:
        if isinstance(node, dict):
            node = node.get(key)
        elif isinstance(node, list) and isinstance(key, int) and len(node) > key:
            node = node[key]
        else:
            return None
    return node


def _clip(text, limit=96):
    if text is None:
        return None
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip(" ,;.") + "\u2026"


DEFINITIONS = {
    "Disk free": ("Space still writable on the volume macOS boots from.", "df -k on / : the available blocks, not total minus used, because APFS reserves and purgeable space differ."),
    "Reclaimable": ("Caches and build artefacts that regenerate themselves if deleted.", "du -sk over 17 known cache paths plus every node_modules found under $HOME."),
    "Memory pressure": ("How much of physical RAM is genuinely committed right now.", "(wired + active + compressed) / hw.memsize, from vm_stat page counts."),
    "Uptime": ("Time since the last boot.", "now minus sysctl kern.boottime. Pending updates only apply after a restart."),
    "Exposed ports": ("Sockets reachable from any host that can route to this Mac.", "lsof listening TCP sockets bound to 0.0.0.0 or :: rather than 127.0.0.1."),
    "Claude startup": ("Context consumed before you type anything in a Claude Code session.", "bytes of always-loaded config divided by 4."),
    "Session startup": ("Context loaded on every request in a session, before any work begins.", "CLAUDE.md bodies in scope + skill/agent/command name and description frontmatter, bytes / 4."),
    "Skills": ("Skills discoverable in this directory, across user, project and plugin scope.", "always-loaded cost counts only name + description; the body loads when the skill fires."),
    "Commands": ("Slash commands offered in this directory.", "always-loaded cost counts the name and description shown in the command list."),
    "Agents": ("Subagent types available to delegate to.", "always-loaded cost counts name + description, which appear in the agent list."),
    "CLAUDE.md in scope": ("Memory files loaded verbatim for this directory.", "user file plus any CLAUDE.md in the current directory or its ancestors, counted in full."),
    "MCP servers": ("Configured MCP servers whose tool schemas enter every request.", "read from config only. Measuring the schemas would mean starting the server, which this audit never does."),
    "Hooks": ("Shell commands Claude Code runs on lifecycle events.", "counted across every settings file, with the matcher that scopes each one."),
    "Dead permission rules": ("Permission rules a broader rule already covers, so they never change an outcome.", "a rule is dead when another rule in the same bucket strictly covers its pattern."),
    "Memory": ("Physical RAM committed right now.", "wired + active + compressed from vm_stat, against hw.memsize."),
    "Swap": ("Memory paged out to the internal SSD.", "sysctl vm.swapusage. Sustained swap means the working set exceeds RAM."),
    "Thermal limit": ("Ceiling the scheduler is currently imposing on CPU speed.", "pmset -g therm CPU_Speed_Limit. Below 100% means it is throttling now."),
    "Battery": ("Health of the internal battery.", "system_profiler SPPowerDataType: condition and maximum capacity against design."),
    "CPU temperature": ("Die temperature.", "only exposed by powermetrics and the SMC, both of which require root, so it is never read here."),
    "Startup volume": ("Free space on the volume macOS boots from.", "df -k. Below ~10% free, APFS cannot keep purgeable space available."),
    "node_modules": ("JavaScript dependency trees under your home directory.", "find to depth 6, then du -sk on each. Every one is reinstallable."),
    "APFS snapshots": ("Local Time Machine snapshots pinning deleted blocks.", "tmutil listlocalsnapshots /. Deleting files frees nothing until these expire."),
    "Exposed on all interfaces": ("Services accepting connections from any reachable host.", "lsof listeners bound to 0.0.0.0 or :: instead of loopback."),
    "Loopback only": ("Services reachable only from this machine.", "lsof listeners bound to 127.0.0.1 or ::1. These are not network exposure."),
    "Application firewall": ("macOS filter for inbound connections to apps.", "socketfilterfw --getglobalstate."),
    "System Integrity Protection": ("Kernel-level protection of system files from root.", "csrutil status. With it off, root can modify system binaries undetectably."),
    "FileVault": ("Full disk encryption at rest.", "fdesetup status. Without it, physical access reads every file."),
    "Gatekeeper": ("Signature and notarisation check before an app runs.", "spctl --status."),
    "XProtect": ("Apple's built-in malware signature version.", "CFBundleShortVersionString of the XProtect bundle."),
    "Pending updates": ("Updates Apple has queued for this Mac.", "the local SoftwareUpdate preference cache. No online check is made."),
    "sudoers NOPASSWD": ("Rules granting sudo without a password.", "/etc/sudoers is root-only, so presence cannot be checked without elevation."),
    "High-risk grants": ("Apps that can read every file or observe and synthesise input.", "TCC rows for full disk access, accessibility, screen recording, input monitoring."),
    "User TCC database": ("Per-user privacy grants.", "read only if this process already holds Full Disk Access, opened immutable and read-only."),
    "Credential-shaped values": ("Strings in config files that look like live credentials.", "12 provider patterns plus name heuristics. Only path, line and name are recorded, never the value."),
    "Shadowed by system copy": ("Commands where a system binary wins over your version-managed one.", "first PATH directory providing each executable name, compared against manager directories later in PATH."),
    "World-writable on PATH": ("PATH directories any local process can write to.", "stat mode with the world-write bit and no sticky bit. Anything here can hijack a command name."),
    "Duplicate entries": ("Directories listed more than once in PATH.", "normalised comparison in PATH order."),
    "Missing directories": ("PATH entries that do not exist.", "each PATH element stat-ed. Dead entries slow every command lookup."),
    "Unlinked kegs": ("Installed formulae with nothing linked into the prefix.", "brew info --json: installed versions present but linked_keg null."),
    "Duplicated across managers": ("Packages provided by more than one manager.", "name intersection across Homebrew, npm global, pipx and cargo. PATH order decides which runs."),
    "SSH private keys": ("Private keys in ~/.ssh.", "ssh-keygen -l for type and bits; ssh-keygen -y -P '' to detect a missing passphrase. No key material is stored."),
    "~/.ssh mode": ("Permissions on the ssh directory.", "expected 0700. Anything looser lets other local accounts read your keys."),
    "Orphaned jobs": ("launchd jobs whose target binary no longer exists.", "the Program or first ProgramArguments entry of each plist, checked for existence."),
    "Interpreters found": ("Distinct Python interpreters on this machine.", "PATH scan plus pyenv, Homebrew and framework locations, de-duplicated by real path."),
    "Homebrew formulae": ("Formulae installed, and how many are behind.", "brew outdated against already-downloaded local metadata. No network request is made."),
    "Plugins": ("Claude Code plugins installed and enabled.", "installed_plugins.json cross-referenced with enabledPlugins in settings."),
}


def _def_attrs(label):
    entry = DEFINITIONS.get(label)
    if not entry:
        return None
    return ' class="def" tabindex="0" data-what="%s" data-how="%s"' % (_e(entry[0]), _e(entry[1]))


def _label_html(label):
    attrs = _def_attrs(label)
    if not attrs:
        return _e(label)
    return "<span%s>%s</span>" % (attrs, _e(label))


NEUTRAL_RAMP = ("var(--f1)", "var(--f2)", "var(--f3)", "var(--f4)")


def _stacked(segments, labels):
    total = sum(max(0, value) for _, value, _ in segments)
    if not total:
        return ""
    bar = []
    legend = []
    for name, value, display in segments:
        if value <= 0:
            continue
        share = 100.0 * value / total
        fill = NEUTRAL_RAMP[len(bar) % len(NEUTRAL_RAMP)]
        bar.append('<span style="width:%.3f%%;background:%s"></span>' % (share, fill))
        legend.append('<span><i style="background:%s"></i>%s <b>%s</b></span>' % (fill, _e(name), _e(display)))
    return '<div class="chart"><div class="meter">%s</div><div class="legend">%s</div></div>' % ("".join(bar), "".join(legend))


def _fact(label, value, tone=None, hint=None):
    if value is None or value == "":
        return None
    return {"label": label, "value": _clip(value, 120), "tone": tone, "hint": _clip(hint)}


def _count(node):
    return len(node) if isinstance(node, list) else 0


def _yes_no(labels, value):
    return labels["yes"] if value else labels["no"]


def _facts_toolchain(payload, labels):
    tools = payload.get("tools") or {}
    python = payload.get("python") or {}
    clt = _dig(payload, "xcode", "command_line_tools") or {}
    interpreters = python.get("interpreters") or []
    active_path = python.get("active_python3")
    active = next((item for item in interpreters if active_path and active_path in (item.get("path"), item.get("real_path"))), None)
    active = active or (interpreters[0] if interpreters else None)
    out = [
        _fact("Active python3", "%s" % (active.get("version") or "unknown") if active else None,
              hint=active.get("path") if active else None),
        _fact("Interpreters found", "%d" % _count(interpreters)),
        _fact("Node", _dig(tools, "node", "version"), hint=_dig(tools, "node", "install_method")),
        _fact("Git", _dig(tools, "git", "version"), hint=_dig(tools, "git", "install_method")),
        _fact("Homebrew", _dig(payload, "homebrew", "version"), hint=_dig(payload, "homebrew", "prefix")),
        _fact("Xcode CLT", clt.get("version") if clt.get("installed") else "not installed", None if clt.get("installed") else "warning"),
        _fact("Node managers", ", ".join(sorted({item.get("manager") for item in (_dig(payload, "node", "managers") or []) if item.get("manager")})) or None),
    ]
    return out


def _facts_packages(payload, labels):
    installed = payload.get("installed") if isinstance(payload.get("installed"), dict) else {}
    outdated = payload.get("outdated") if isinstance(payload.get("outdated"), dict) else {}
    brew = payload.get("homebrew") if isinstance(payload.get("homebrew"), dict) else {}
    installed = brew.get("installed") if isinstance(brew.get("installed"), dict) else installed
    outdated = brew.get("outdated") if isinstance(brew.get("outdated"), dict) else outdated
    stale = (outdated.get("formula_count") or 0) + (outdated.get("cask_count") or 0)
    return [
        _fact("Homebrew formulae", "%s installed" % installed.get("formula_count") if installed.get("formula_count") is not None else None,
              hint="%s outdated" % stale if stale else None),
        _fact("Homebrew casks", "%s installed" % installed.get("cask_count") if installed.get("cask_count") is not None else None),
        _fact("Unlinked kegs", "%d" % _count(installed.get("unlinked_kegs")), "warning" if _count(installed.get("unlinked_kegs")) else None),
        _fact("Homebrew on disk", _dig(brew, "disk_footprint", "total_human")),
        _fact("brew doctor", "%s warnings" % _dig(brew, "doctor", "warning_count") if _dig(brew, "doctor", "warning_count") else "clean"),
        _fact("npm global", "%s packages" % _dig(payload, "npm_global", "package_count") if _dig(payload, "npm_global", "package_count") is not None else None),
        _fact("pip", "%s packages" % _dig(payload, "pip", "package_count") if _dig(payload, "pip", "package_count") is not None else None),
        _fact("Duplicated across managers", "%d" % _count(payload.get("cross_manager_duplicates")), "warning" if _count(payload.get("cross_manager_duplicates")) else None),
    ]


def _facts_shell(payload, labels):
    path = payload.get("path") or {}
    profiles = [item for item in (payload.get("profiles") or []) if item.get("status") != "unavailable"]
    aliases = sum(_count(item.get("aliases")) for item in profiles)
    functions = sum(_count(item.get("functions")) for item in profiles)
    exports = sum(_count(item.get("exports")) for item in profiles)
    shadow = _count(_dig(payload, "shadowed_commands", "system_shadows_manager"))
    return [
        _fact("Login shell", _dig(payload, "login_shell", "path")),
        _fact("PATH entries", "%s" % path.get("entry_count")),
        _fact("Duplicate entries", "%d" % _count(path.get("duplicates")), "warning" if _count(path.get("duplicates")) else None),
        _fact("Missing directories", "%d" % _count(path.get("missing_directories")), "warning" if _count(path.get("missing_directories")) else None),
        _fact("World-writable on PATH", "%d" % _count(path.get("world_writable_directories")), "critical" if _count(path.get("world_writable_directories")) else None),
        _fact("Shadowed by system copy", "%d" % shadow, "warning" if shadow else None),
        _fact("Profiles read", "%d" % len(profiles), hint="%d aliases, %d functions, %d exports" % (aliases, functions, exports)),
        _fact("Alias conflicts", "%d" % _count(payload.get("alias_conflicts")), "warning" if _count(payload.get("alias_conflicts")) else None),
    ]


def _facts_hardware(payload, labels):
    memory = payload.get("memory") or {}
    battery = _dig(payload, "power", "battery") or {}
    pressure = memory.get("memory_pressure_percent")
    swap = _dig(memory, "swap", "used_bytes") or 0
    uptime = _dig(payload, "uptime", "uptime_days")
    cpu = payload.get("cpu") or {}
    thermal_limit = _dig(payload, "thermal_pressure", "values", "CPU_Speed_Limit")
    return [
        _fact("Model", _dig(payload, "profile", "model_name"), hint=_dig(payload, "profile", "model_identifier")),
        _fact("Processor", cpu.get("brand") or _dig(payload, "profile", "chip"), hint="%s cores" % cpu.get("logical_cores") if cpu.get("logical_cores") else None),
        _fact("Memory", "%s of %s in use" % (memory.get("used_human"), memory.get("total_human")) if memory.get("used_human") else None,
              "warning" if (pressure or 0) >= 85 else None, hint="%.0f%% pressure" % pressure if pressure else None),
        _fact("Swap", _dig(memory, "swap", "used_human"), "warning" if swap > 4 * 1024 ** 3 else None),
        _fact("Uptime", "%.1f days" % uptime if uptime else None),
        _fact("Battery", ", ".join([part for part in [
            battery.get("condition"),
            "%s of design" % battery.get("maximum_capacity_percent") if battery.get("maximum_capacity_percent") else None,
        ] if part]) or "present" if battery.get("present") else "none",
              "warning" if battery.get("present") and str(battery.get("condition") or "").lower() not in ("normal", "good", "") else None,
              hint="%s cycles" % battery.get("cycle_count") if battery.get("cycle_count") else None),
        _fact("Power source", payload.get("power", {}).get("power_source") if isinstance(payload.get("power"), dict) else None),
        _fact("Thermal limit", "%s%%" % thermal_limit if thermal_limit is not None else "nominal", "warning" if thermal_limit is not None and thermal_limit < 100 else None),
        _fact("CPU temperature", labels["requires_privileges"] if _dig(payload, "cpu_temperature", "status") == "requires_privileges" else _dig(payload, "cpu_temperature", "reading")),
    ]


def _facts_storage(payload, labels):
    volumes = payload.get("volumes") if isinstance(payload.get("volumes"), list) else []
    root = next((item for item in volumes if item.get("mount_point") == "/"), None) or (volumes[0] if volumes else None)
    reclaim = payload.get("reclaimable") or {}
    node_modules = payload.get("node_modules") or {}
    biggest = (payload.get("largest_home_directories") or [{}])[0]
    free_percent = root.get("free_percent") if root else None
    tone = "critical" if (free_percent is not None and free_percent < 5) else ("warning" if (free_percent is not None and free_percent < 10) else None)
    return [
        _fact("Startup volume", "%s free of %s" % (root.get("free_human"), root.get("total_human")) if root else None, tone,
              hint="%.1f%% free" % free_percent if free_percent is not None else None),
        _fact("Reclaimable", reclaim.get("total_human"), hint="caches and build artefacts, nothing deleted"),
        _fact("node_modules", "%s in %s directories" % (node_modules.get("total_human"), node_modules.get("count")) if node_modules.get("count") else None),
        _fact("Largest under home", "%s  %s" % (biggest.get("human"), biggest.get("path")) if biggest.get("path") else None),
        _fact("APFS snapshots", "%s" % _dig(payload, "apfs_snapshots", "count")),
    ]


def _facts_services(payload, labels):
    total_orphans = 0
    counts = {}
    for key, title in (("user_agents", "User agents"), ("system_agents", "System agents"), ("system_daemons", "System daemons")):
        section = payload.get(key) or {}
        entries = section.get("entries") or []
        counts[title] = len(entries)
        total_orphans += sum(1 for item in entries if item.get("orphaned"))
    login = payload.get("login_items") or {}
    return [
        _fact("User agents", "%d" % counts.get("User agents", 0), hint="~/Library/LaunchAgents"),
        _fact("System agents", "%d" % counts.get("System agents", 0)),
        _fact("System daemons", "%d" % counts.get("System daemons", 0)),
        _fact("Orphaned jobs", "%d" % total_orphans, "warning" if total_orphans else None),
        _fact("Login items", "%s" % login.get("count") if login.get("status") == "ok" else labels["requires_privileges"]),
        _fact("Cron jobs", "%s" % _dig(payload, "crontab", "entry_count")),
    ]


def _facts_containers(payload, labels):
    out = []
    for key, title in (("docker", "Docker"), ("podman", "Podman"), ("colima", "Colima"), ("orbstack", "OrbStack")):
        section = payload.get(key) or {}
        if section.get("status") == "ok" and key in ("docker", "podman"):
            containers = section.get("containers") or {}
            out.append(_fact(title, "%d running, %d stopped" % (_count(containers.get("running")), _count(containers.get("stopped"))),
                             hint="%s dangling images, %s unused volumes" % (_dig(section, "images", "dangling"), _dig(section, "volumes", "unused"))))
        elif section.get("status") == "ok":
            out.append(_fact(title, "installed"))
        else:
            out.append(_fact(title, labels["unavailable"], hint=section.get("reason")))
    return out


def _facts_network(payload, labels):
    sockets = payload.get("listening_sockets") or {}
    counts = sockets.get("counts") or {}
    firewall = payload.get("firewall") or {}
    proxy = payload.get("system_proxy") or {}
    vpn = payload.get("vpn_configurations") or {}
    dns = payload.get("dns") or {}
    exposed = counts.get("all_interfaces") or 0
    proxy_on = any(proxy.get(key) for key in ("http_enabled", "https_enabled", "socks_enabled")) if isinstance(proxy, dict) else False
    return [
        _fact("Exposed on all interfaces", "%d listeners" % exposed, "warning" if exposed else None),
        _fact("Loopback only", "%d listeners" % (counts.get("loopback") or 0)),
        _fact("Application firewall", labels["yes"] if firewall.get("enabled") else labels["no"], None if firewall.get("enabled") else "warning",
              hint=None if firewall.get("enabled") else "incoming connections are not filtered"),
        _fact("DNS resolvers", ", ".join((dns.get("unique_nameservers") or [])[:4]) if dns.get("unique_nameservers") else None),
        _fact("System proxy", "enabled" if proxy_on else "none"),
        _fact("VPN configurations", "%s configured, %s connected" % (vpn.get("count"), _count(vpn.get("active"))) if isinstance(vpn, dict) and vpn.get("count") is not None else None),
        _fact("Custom /etc/hosts entries", "%s" % _dig(payload, "hosts_file", "custom_entry_count")),
    ]


def _facts_security(payload, labels):
    def state(section, key, good_label, bad_label):
        node = payload.get(section) or {}
        value = node.get(key)
        if value is None:
            return None, None
        return (good_label if value else bad_label), (None if value else "critical")

    sip_value, sip_tone = state("sip", "enabled", "enabled", "disabled")
    fv_value, fv_tone = state("filevault", "enabled", "on", "off")
    gk_value, gk_tone = state("gatekeeper", "assessments_enabled", "enabled", "disabled")
    updates = payload.get("software_updates") or {}
    pending = updates.get("pending_count") or 0
    guest = _dig(payload, "guest_account", "guest_enabled")
    remote_on = [entry.get("description") for entry in (_dig(payload, "remote_access", "services") or {}).values() if entry.get("state") == "enabled"]
    return [
        _fact("System Integrity Protection", sip_value, sip_tone),
        _fact("FileVault", fv_value, fv_tone),
        _fact("Gatekeeper", gk_value, gk_tone),
        _fact("XProtect", _dig(payload, "malware_definitions", "xprotect_definitions", "version")),
        _fact("Pending updates", "%d" % pending if updates.get("status") == "ok" else labels["unavailable"], "warning" if pending else None,
              hint="from the local cache; no online check"),
        _fact("Guest account", labels["yes"] if guest else labels["no"], "warning" if guest else None),
        _fact("Remote access enabled", ", ".join(remote_on) if remote_on else "none", "warning" if remote_on else None),
        _fact("sudoers NOPASSWD", labels["requires_privileges"] if _dig(payload, "sudoers", "status") == "requires_privileges" else "%s entries" % _dig(payload, "sudoers", "nopasswd_entry_count")),
    ]


def _facts_identity(payload, labels):
    ssh = payload.get("ssh") or {}
    gpg = payload.get("gpg") or {}
    agent = _dig(payload, "ssh_agent", "identities") or {}
    keys = ssh.get("keys") or []
    weak = sum(1 for key in keys if key.get("permissive_mode") or key.get("passphrase") == "no_passphrase")
    return [
        _fact("SSH private keys", "%s" % ssh.get("key_count") if ssh.get("status") == "ok" else labels["unavailable"],
              "warning" if weak else None, hint="%d need attention" % weak if weak else None),
        _fact("~/.ssh mode", ssh.get("directory_mode")),
        _fact("known_hosts entries", "%s" % ssh.get("known_hosts_entries") if ssh.get("status") == "ok" else None),
        _fact("ssh config hosts", "%s" % ssh.get("config_host_count") if ssh.get("status") == "ok" else None),
        _fact("Agent identities", "%s" % agent.get("count") if isinstance(agent, dict) and agent.get("count") is not None else labels["unavailable"]),
        _fact("GPG keys", "%s" % gpg.get("public_key_count") if gpg.get("status") == "ok" else labels["unavailable"]),
    ]


def _facts_secrets(payload, labels):
    matches = payload.get("match_count") or 0
    remotes = payload.get("git_remotes") or []
    embedded = sum(1 for item in remotes if item.get("embedded_credentials"))
    loose = sum(1 for item in (payload.get("sensitive_file_permissions") or []) if item.get("group_or_world_readable"))
    return [
        _fact("Files scanned", "%s" % payload.get("files_scanned")),
        _fact("Credential-shaped values", "%d" % matches, "critical" if matches else None,
              hint="names and line numbers only; no value is ever read into the report"),
        _fact("Git remotes checked", "%d" % len(remotes), "critical" if embedded else None,
              hint="%d with embedded credentials" % embedded if embedded else None),
        _fact("Loose credential files", "%d" % loose, "warning" if loose else None),
    ]


def _facts_permissions(payload, labels):
    user_db = payload.get("user_database") or {}
    system_db = payload.get("system_database") or {}
    high = 0
    for section in (user_db, system_db):
        for grant in (section.get("grants") or []):
            if grant.get("granted") and grant.get("service") in ("kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility", "kTCCServiceScreenCapture", "kTCCServiceListenEvent", "kTCCServicePostEvent"):
                high += 1
    return [
        _fact("User TCC database", "%s grants" % user_db.get("grant_count") if user_db.get("status") == "ok" else labels["requires_privileges"]),
        _fact("System TCC database", "%s grants" % system_db.get("grant_count") if system_db.get("status") == "ok" else labels["requires_privileges"]),
        _fact("High-risk grants", "%d" % high, "warning" if high else None,
              hint="full disk access, accessibility, screen recording, input monitoring"),
        _fact("Candidate apps installed", "%d" % _count(payload.get("installed_candidate_apps"))),
    ]


def _facts_claude(payload, labels):
    budget = payload.get("context_budget") or {}
    inventory = payload.get("inventory") or {}
    analysis = payload.get("analysis") or {}
    by_kind = budget.get("by_kind") or {}

    def kind(name):
        node = by_kind.get(name) or {}
        if not node.get("total"):
            return None
        return "%s active of %s" % (node.get("active"), node.get("total"))

    startup = budget.get("session_startup_tokens_estimate")
    return [
        _fact("Session startup", "~%s tokens" % "{:,}".format(startup) if startup else None,
              "warning" if (startup or 0) > 12000 else None, hint="loaded before any work begins"),
        _fact("Skills", kind("skill"), hint="%s tokens always loaded" % (by_kind.get("skill") or {}).get("always_loaded_tokens_estimate")),
        _fact("Commands", kind("command"), hint="%s tokens always loaded" % (by_kind.get("command") or {}).get("always_loaded_tokens_estimate")),
        _fact("Agents", kind("agent"), hint="%s tokens always loaded" % (by_kind.get("agent") or {}).get("always_loaded_tokens_estimate")),
        _fact("CLAUDE.md in scope", kind("claude_md"), hint="%s tokens always loaded" % (by_kind.get("claude_md") or {}).get("always_loaded_tokens_estimate")),
        _fact("MCP servers", "%d" % _count(inventory.get("mcp_servers")), hint="tool schemas are not measurable offline"),
        _fact("Hooks", "%d" % _count(inventory.get("hooks")), hint="%d fire on every event" % _count(analysis.get("hooks_firing_on_every_event")) if _count(analysis.get("hooks_firing_on_every_event")) else None),
        _fact("Plugins", "%s enabled of %s" % (_dig(inventory, "plugins", "enabled_count"), _dig(inventory, "plugins", "count")) if _dig(inventory, "plugins", "count") is not None else None),
        _fact("Dead permission rules", "%d" % _count(analysis.get("dead_permission_rules")), "warning" if _count(analysis.get("dead_permission_rules")) else None),
    ]


def _chart_for(domain, payload, labels):
    if not isinstance(payload, dict):
        return ""
    if domain == "storage":
        volumes = payload.get("volumes") if isinstance(payload.get("volumes"), list) else []
        root = next((item for item in volumes if item.get("mount_point") == "/"), None)
        if not root or not root.get("total_bytes"):
            return ""
        free = root.get("free_bytes") or 0
        occupied = max(0, (root.get("total_bytes") or 0) - free)
        reclaim = min(_dig(payload, "reclaimable", "total_bytes") or 0, occupied)
        used = max(0, occupied - reclaim)
        return _stacked([
            ("In use", used, _human(used)),
            ("Reclaimable", reclaim, _human(reclaim)),
            ("Free", free, _human(free)),
        ], labels)
    if domain == "hardware":
        memory = payload.get("memory") or {}
        breakdown = memory.get("breakdown") or {}
        raw = {key: _unhuman(breakdown.get(key)) for key in ("wired", "active", "compressed", "inactive", "free")}
        if not any(raw.values()):
            return ""
        return _stacked([
            ("Wired", raw["wired"], breakdown.get("wired") or ""),
            ("Active", raw["active"], breakdown.get("active") or ""),
            ("Compressed", raw["compressed"], breakdown.get("compressed") or ""),
            ("Inactive + free", (raw["inactive"] or 0) + (raw["free"] or 0), _human((raw["inactive"] or 0) + (raw["free"] or 0))),
        ], labels)
    if domain == "claude_code":
        by_kind = _dig(payload, "context_budget", "by_kind") or {}
        segments = []
        for key, name in (("skill", "Skills"), ("command", "Commands"), ("agent", "Agents"), ("claude_md", "CLAUDE.md")):
            tokens = (by_kind.get(key) or {}).get("always_loaded_tokens_estimate") or 0
            if tokens:
                segments.append((name, tokens, "{:,}".format(tokens)))
        return _stacked(segments, labels) if segments else ""
    return ""


def _human(value):
    if not value:
        return "0 B"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0 or unit == "TB":
            return "%d %s" % (int(size), unit) if unit == "B" else "%.1f %s" % (size, unit)
        size /= 1024.0
    return None


def _unhuman(text):
    if not text:
        return 0
    parts = str(text).split()
    if len(parts) != 2:
        return 0
    try:
        value = float(parts[0])
    except ValueError:
        return 0
    scale = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}.get(parts[1].upper())
    return int(value * scale) if scale else 0


def _facts_copilot(payload, labels):
    inventory = payload.get("inventory") or {}
    install = inventory.get("installation") or {}
    return [
        _fact("Instruction files", (payload.get("analysis") or {}).get("instruction_files_found")),
        _fact("Always-loaded tokens", "{:,}".format(_dig(payload, "context_budget", "session_startup_tokens_estimate") or 0)),
        _fact("Copilot extensions", install.get("copilot_extensions_installed")),
        _fact("Editors with settings", ", ".join(install.get("vscode_user_settings_present") or []) or "none"),
        _fact("JetBrains config", "present" if install.get("jetbrains_configuration_present") else "absent"),
    ]


def _facts_codex(payload, labels):
    inventory = payload.get("inventory") or {}
    config = inventory.get("configuration") or {}
    analysis = payload.get("analysis") or {}
    return [
        _fact("AGENTS.md files", analysis.get("agents_md_found")),
        _fact("Always-loaded tokens", "{:,}".format(_dig(payload, "context_budget", "session_startup_tokens_estimate") or 0)),
        _fact("Approval policy", config.get("approval", {}).get("value"), "warning" if analysis.get("approval_is_permissive") else None),
        _fact("Sandbox", config.get("sandbox", {}).get("value"), "warning" if analysis.get("sandbox_is_permissive") else None),
        _fact("MCP servers", len(inventory.get("mcp_servers") or [])),
        _fact("Session files", analysis.get("session_file_count")),
    ]


def _facts_ai_assistants(payload, labels):
    analysis = payload.get("analysis") or {}
    inventory = payload.get("inventory") or {}
    overlaps = analysis.get("instruction_file_overlaps") or []
    return [
        _fact("Assistants configured", len(inventory.get("tools_with_instruction_files") or [])),
        _fact("Instruction files", analysis.get("instruction_file_count")),
        _fact("Active files", analysis.get("active_instruction_file_count")),
        _fact("Combined active tokens", "{:,}".format(analysis.get("combined_active_tokens_estimate") or 0)),
        _fact("Overlapping pairs", len(overlaps), "warning" if overlaps else None),
    ]


FACT_BUILDERS = {
    "toolchain": _facts_toolchain,
    "packages": _facts_packages,
    "shell_env": _facts_shell,
    "hardware": _facts_hardware,
    "storage": _facts_storage,
    "services": _facts_services,
    "containers": _facts_containers,
    "network": _facts_network,
    "security": _facts_security,
    "identity": _facts_identity,
    "secrets": _facts_secrets,
    "permissions": _facts_permissions,
    "claude_code": _facts_claude,
    "github_copilot": _facts_copilot,
    "openai_codex": _facts_codex,
    "ai_assistants": _facts_ai_assistants,
}


def _facts(domain, payload, labels):
    builder = FACT_BUILDERS.get(domain)
    if not builder or not isinstance(payload, dict):
        return []
    try:
        return [item for item in builder(payload, labels) if item]
    except Exception:
        return []


def _vitals(dataset, labels):
    domains = dataset.get("domains") or {}
    out = []
    storage = domains.get("storage") or {}
    volumes = storage.get("volumes") if isinstance(storage.get("volumes"), list) else []
    root = next((item for item in volumes if item.get("mount_point") == "/"), None)
    if root:
        percent = root.get("free_percent")
        out.append(_fact(labels["v_disk"], root.get("free_human"),
                         "critical" if (percent or 100) < 5 else ("warning" if (percent or 100) < 10 else None),
                         hint="%.1f%% of %s" % (percent, root.get("total_human")) if percent is not None else None))
    reclaim = _dig(storage, "reclaimable", "total_human")
    if reclaim:
        out.append(_fact(labels["v_reclaim"], reclaim, hint=labels["v_reclaim_hint"]))
    hardware = domains.get("hardware") or {}
    pressure = _dig(hardware, "memory", "memory_pressure_percent")
    if pressure is not None:
        out.append(_fact(labels["v_memory"], "%.0f%%" % pressure, "warning" if pressure >= 85 else None,
                         hint="%s of %s" % (_dig(hardware, "memory", "used_human"), _dig(hardware, "memory", "total_human"))))
    uptime = _dig(hardware, "uptime", "uptime_days")
    if uptime is not None:
        out.append(_fact(labels["v_uptime"], "%.0f d" % uptime, hint=_dig(hardware, "power", "power_source")))
    network = domains.get("network") or {}
    exposed = _dig(network, "listening_sockets", "counts", "all_interfaces")
    if exposed is not None:
        out.append(_fact(labels["v_exposed"], "%d" % exposed, "warning" if exposed else None, hint=labels["v_exposed_hint"]))
    startup = _dig(domains.get("claude_code") or {}, "context_budget", "session_startup_tokens_estimate")
    if startup:
        out.append(_fact(labels["v_startup"], "{:,}".format(startup), "warning" if startup > 12000 else None, hint=labels["v_startup_hint"]))
    return [item for item in out if item]


def _scalar(value, labels):
    if value is None:
        return '<span class="empty">%s</span>' % _e(labels["empty"])
    if isinstance(value, bool):
        return _e(labels["yes"] if value else labels["no"])
    text = str(value)
    if len(text) > 4000:
        text = text[:4000] + " ..."
    if "\n" in text:
        return "<pre>%s</pre>" % _e(text)
    return _e(text)


def _render(value, labels, depth=0):
    if depth > MAX_DEPTH:
        return '<span class="empty">...</span>'
    if isinstance(value, dict):
        if not value:
            return '<span class="empty">%s</span>' % _e(labels["empty"])
        parts = ['<div class="kv">']
        for key in value:
            parts.append('<div class="k">%s</div><div class="v">%s</div>' % (_e(key), _render(value[key], labels, depth + 1)))
        parts.append("</div>")
        return "".join(parts)
    if isinstance(value, (list, tuple)):
        items = list(value)
        if not items:
            return '<span class="empty">%s</span>' % _e(labels["empty"])
        truncated = len(items) > MAX_ROWS
        items = items[:MAX_ROWS]
        if all(isinstance(item, dict) for item in items):
            columns = []
            for item in items:
                for key in item:
                    if key not in columns:
                        columns.append(key)
            head = "".join("<th>%s</th>" % _e(column) for column in columns)
            rows = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % _render(item.get(column), labels, depth + 1) for column in columns) for item in items)
            table = '<div class="scroll"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (head, rows)
            if truncated:
                table += '<p class="empty">%s</p>' % _e(labels["truncated"] % (len(value) - MAX_ROWS))
            return table
        if all(not isinstance(item, (dict, list, tuple)) for item in items):
            body = ", ".join(_scalar(item, labels) for item in items)
            if truncated:
                body += ' <span class="empty">(+%d)</span>' % (len(value) - MAX_ROWS)
            return body
        return "".join('<div class="v">%s</div>' % _render(item, labels, depth + 1) for item in items)
    return _scalar(value, labels)


def _finding_html(item, labels, lang):
    severity = item.get("severity", "info")
    haystack = " ".join(str(item.get(key) or "") for key in ("title", "why_it_matters", "evidence", "suggested_action", "domain")).lower()
    parts = ['<article class="finding" data-search="%s">' % _e(haystack)]
    parts.append('<div class="f-top"><h4 class="f-title">%s</h4><div class="f-tags">' % _e(item.get("title", "")))
    parts.append('<span class="sev %s">%s</span>' % (_e(severity), _e(labels.get(severity, severity))))
    parts.append("<span>%s</span>" % _e(i18n.domain_label(lang, item.get("domain", ""))))
    parts.append("<span>%s</span>" % _e(labels["reversible_yes"] if item.get("reversible") else labels["reversible_no"]))
    parts.append("</div></div>")
    parts.append('<p class="f-why">%s</p>' % _e(item.get("why_it_matters", "")))
    action = item.get("suggested_action")
    if action:
        parts.append('<div class="f-row"><div class="f-label">%s</div><div class="cmd"><code>%s</code><button type="button" data-copied="%s">%s</button></div></div>' % (
            _e(labels["fix"]), _e(action), _e(labels["copied"]), _e(labels["copy"])))
    else:
        parts.append('<div class="f-row"><div class="f-label">%s</div><div class="f-note">%s</div></div>' % (_e(labels["fix"]), _e(labels["no_command"])))
    parts.append('<div class="f-row"><div class="f-label">%s</div><div class="f-evidence">%s</div></div>' % (_e(labels["evidence"]), _e(item.get("evidence", ""))))
    parts.append("</article>")
    return "".join(parts)


def _grouped_view(view_id, findings, dataset, labels, lang, intro):
    domains = dataset.get("run", {}).get("domains", [])
    grouped = {}
    for item in findings:
        grouped.setdefault(item.get("domain"), []).append(item)
    ordered = [name for name in domains if name in grouped]
    parts = ['<section class="view" id="%s" role="tabpanel" hidden>' % view_id]
    parts.append('<p class="view-intro">%s</p>' % _e(intro))
    if not findings:
        parts.append('<p class="view-intro">%s</p></section>' % _e(labels["nothing_here"]))
        return "".join(parts)
    parts.append('<div class="index">')
    for name in ordered:
        parts.append('<a class="chip" href="#%s-%s">%s<span class="n">%d</span></a>' % (_e(view_id), _e(name), _e(i18n.domain_label(lang, name)), len(grouped[name])))
    parts.append("</div>")
    for name in ordered:
        items = grouped[name]
        parts.append('<div class="group" id="%s-%s">' % (_e(view_id), _e(name)))
        parts.append('<h3>%s<span class="n">%s</span></h3><div class="group-rule"></div>' % (_e(i18n.domain_label(lang, name)), _e(labels["n_findings"] % len(items))))
        for item in items:
            parts.append(_finding_html(item, labels, lang))
        parts.append("</div>")
    parts.append('<p class="no-match">%s</p>' % labels["no_match"])
    parts.append("</section>")
    return "".join(parts)


TIER_LABELS = (("inspect", "tier_inspect", "tier_inspect_hint"),
               ("apply", "tier_apply", "tier_apply_hint"),
               ("careful", "tier_careful", "tier_careful_hint"))


def _quickfix_view(dataset, labels, lang):
    plan = dataset.get("quick_fixes") or {}
    commands = plan.get("commands") or []
    manual = plan.get("manual_steps") or []
    parts = ['<section class="view" id="quickfix" role="tabpanel" hidden>']
    parts.append('<p class="view-intro">%s</p>' % _e(labels["quickfix_intro"]))

    if not commands and not manual:
        parts.append('<p class="view-intro">%s</p>' % _e(labels["quickfix_none"]))
        parts.append(_antivirus_html(labels, lang))
        parts.append("</section>")
        return "".join(parts)

    for tier, heading_key, hint_key in TIER_LABELS:
        items = [entry for entry in commands if entry["tier"] == tier]
        if not items:
            continue
        list_id = "qf-list-%s" % tier
        parts.append('<div class="qf-tier t-%s" id="qf-%s">' % (_e(tier), _e(tier)))
        parts.append('<div class="qf-head"><h3>%s<span class="n">%s</span></h3><div class="grow"></div>'
                     '<button class="btn" type="button" data-copy-block="%s" data-copied="%s">%s</button></div>' % (
                         _e(labels[heading_key]), _e(labels["n_commands"] % len(items)),
                         _e(list_id), _e(labels["copied"]), _e(labels["copy_block"])))
        parts.append('<p class="qf-hint">%s</p>' % _e(labels[hint_key]))
        parts.append('<div class="qf-list" id="%s">' % _e(list_id))
        for entry in items:
            haystack = " ".join([entry["command"]] + entry["titles"] + entry["domains"]).lower()
            parts.append('<div class="qf-item" data-search="%s">' % _e(haystack))
            parts.append('<div class="cmd"><code>%s</code><button type="button" data-copied="%s">%s</button></div>' % (
                _e(entry["command"]), _e(labels["copied"]), _e(labels["copy"])))
            if entry.get("note"):
                parts.append('<p class="qf-note">%s</p>' % _e(entry["note"]))
            badges = ""
            if entry.get("needs_elevation"):
                badges += '<span class="badge sudo">%s</span>' % _e(labels["needs_sudo"])
            if not entry.get("reversible"):
                badges += '<span class="badge oneway">%s</span>' % _e(labels["reversible_no"])
            titles = "; ".join(_clip(title, 90) for title in entry["titles"][:4])
            if len(entry["titles"]) > 4:
                titles += " (+%d)" % (len(entry["titles"]) - 4)
            parts.append('<p class="qf-for"><b>%s</b> %s%s</p>' % (
                _e(labels["quickfix_addresses"]), _e(titles), badges))
            parts.append("</div>")
        parts.append("</div></div>")

    if manual:
        parts.append('<details class="qf-manual"><summary>%s <span class="n">%s</span></summary>' % (
            _e(labels["manual_heading"]), _e(labels["n_steps"] % len(manual))))
        parts.append('<p class="qf-hint">%s</p>' % _e(labels["manual_hint"]))
        for entry in manual:
            haystack = " ".join([entry["manual_step"]] + entry["titles"] + entry["domains"]).lower()
            titles = "; ".join(_clip(title, 90) for title in entry["titles"][:4])
            if len(entry["titles"]) > 4:
                titles += " (+%d)" % (len(entry["titles"]) - 4)
            parts.append('<div class="step" data-search="%s"><p>%s</p><p class="qf-for"><b>%s</b> %s</p></div>' % (
                _e(haystack), _e(entry["manual_step"]), _e(labels["quickfix_addresses"]), _e(titles)))
        parts.append("</details>")

    parts.append(_antivirus_html(labels, lang))
    parts.append('<p class="no-match">%s</p>' % labels["no_match"])
    parts.append("</section>")
    return "".join(parts)


def _antivirus_html(labels, lang):
    text = scope_mod.scope(lang)
    parts = ['<div class="av"><h3>%s</h3>' % _e(text["av_heading"])]
    parts.append("<p>%s</p>" % _e(text["av_intro"]))
    parts.append("<dl>")
    for tool in text["av_tools"]:
        parts.append("<dt>%s</dt><dd>%s<small>%s</small></dd>" % (
            _e(tool["name"]), _e(tool["finds"]), _e(tool["how"])))
    parts.append("</dl>")
    parts.append("<p>%s</p>" % _e(text["av_builtin"]))
    parts.append("<p>%s</p>" % _e(text["av_order"]))
    parts.append("</div>")
    return "".join(parts)


def _scope_html(labels, lang):
    text = scope_mod.scope(lang)
    parts = ['<details class="scope"><summary>%s</summary><div class="scope-body">' % _e(text["heading"])]
    parts.append("<p>%s</p>" % _e(text["summary"]))
    parts.append("<h4>%s</h4><ul>" % _e(text["does_heading"]))
    for line in text["does"]:
        parts.append("<li>%s</li>" % _e(line))
    parts.append("</ul>")
    parts.append("<h4>%s</h4><ul>" % _e(text["not_heading"]))
    for line in text["not"]:
        parts.append("<li>%s</li>" % _e(line))
    parts.append("</ul>")
    parts.append(_antivirus_html(labels, lang))
    parts.append("</div></details>")
    return "".join(parts)


def _compat_html(dataset, labels):
    report = dataset.get("compatibility") or {}
    warnings = report.get("warnings") or []
    notes = report.get("capability_notes") or []
    if not warnings and not notes:
        return ""
    parts = ['<div class="compat%s">' % (" has-warning" if warnings else "")]
    parts.append("<h3>%s</h3><ul>" % _e(labels["compat_warning"] if warnings else labels["compat_note"]))
    for line in warnings:
        parts.append("<li><b>%s</b></li>" % _e(line))
    for note in notes:
        parts.append("<li>%s &middot; %s</li>" % (_e(note.get("domain", "")), _e(note.get("detail", ""))))
    parts.append("</ul></div>")
    return "".join(parts)


def _overview_view(dataset, labels, lang):
    domains = dataset.get("run", {}).get("domains", [])
    payloads = dataset.get("domains") or {}
    findings = dataset.get("findings") or []
    critical = [item for item in findings if item.get("severity") == "critical"]
    warning = [item for item in findings if item.get("severity") == "warning"]
    info = [item for item in findings if item.get("severity") == "info"]

    parts = ['<section class="view" id="overview" role="tabpanel" hidden>']

    attention = critical + warning
    if attention:
        tally = {}
        for item in attention:
            tally[item.get("domain")] = tally.get(item.get("domain"), 0) + 1
        top = [name for name, _ in sorted(tally.items(), key=lambda pair: (-pair[1], pair[0]))[:3]]
        lead = '<a href="#attention" data-goto="attention"><span class="c-%s">%s</span></a>' % (
            "critical" if critical else "warning", _e(labels["lead_attention"] % len(attention)))
        if top:
            lead += _e(labels["lead_across"] % ", ".join(i18n.domain_label(lang, name) for name in top))
        lead += "."
    else:
        lead = _e(labels["lead_clean"])
    parts.append('<p class="lead">%s</p>' % lead)
    parts.append('<p class="lead-sub">%s <a href="#information" data-goto="information">%s</a> '
                 '<a href="#quickfix" data-goto="quickfix">%s</a></p>' % (
                     _e(labels["overview_intro"]), _e(labels["lead_info"] % len(info)),
                     _e(labels["tab_quickfix"])))

    vitals = _vitals(dataset, labels)
    if vitals:
        parts.append('<dl class="vitals">')
        for fact in vitals:
            tone = " is-%s" % fact["tone"] if fact["tone"] else ""
            hint = "<small>%s</small>" % _e(fact["hint"]) if fact["hint"] else ""
            parts.append('<div class="vital%s"><dt>%s</dt><dd>%s%s</dd></div>' % (tone, _label_html(fact["label"]), _e(fact["value"]), hint))
        parts.append("</dl>")

    tally = {}
    for item in findings:
        bucket = tally.setdefault(item.get("domain"), {"warning": 0, "info": 0})
        bucket["warning" if item.get("severity") in ("critical", "warning") else "info"] += 1
    if tally:
        peak = max(entry["warning"] + entry["info"] for entry in tally.values()) or 1
        parts.append('<div class="fchart"><h3>%s</h3>' % _e(labels["by_area"]))
        for name, entry in sorted(tally.items(), key=lambda pair: (-(pair[1]["warning"] * 1000 + pair[1]["info"]), pair[0])):
            total = entry["warning"] + entry["info"]
            target = "attention" if entry["warning"] else "information"
            width = 100.0 * total / peak
            segments = ""
            if entry["warning"]:
                segments += '<span style="width:%.2f%%;background:var(--warning)"></span>' % (100.0 * entry["warning"] / total)
            if entry["info"]:
                segments += '<span style="width:%.2f%%;background:var(--info);opacity:0.55"></span>' % (100.0 * entry["info"] / total)
            count = ("<b>%d</b>&thinsp;/&thinsp;%d" % (entry["warning"], total)) if entry["warning"] else str(total)
            parts.append('<a href="#%s-%s" data-goto="%s"><span class="fname">%s</span><span class="fbar" style="width:%.2f%%">%s</span><span class="fnum">%s</span></a>' % (
                _e(target), _e(name), _e(target), _e(i18n.domain_label(lang, name)), width, segments, count))
        parts.append("</div>")

    parts.append('<div class="panels">')
    for name in domains:
        payload = payloads.get(name) or {}
        facts = _facts(name, payload, labels)
        own = [item for item in findings if item.get("domain") == name]
        parts.append('<section class="panel" data-search="%s">' % _e(("%s %s %s" % (
            name, i18n.domain_label(lang, name),
            " ".join("%s %s" % (fact["label"], fact["value"]) for fact in facts))).lower()))
        head = "<h3>%s" % _e(i18n.domain_label(lang, name))
        if own:
            target = "attention" if any(item.get("severity") in ("critical", "warning") for item in own) else "information"
            head += '<a href="#%s-%s" data-goto="%s">%s</a>' % (_e(target), _e(name), _e(target), _e(labels["panel_findings"] % len(own)))
        parts.append(head + "</h3>")
        parts.append(_chart_for(name, payload, labels))
        if facts:
            parts.append('<dl class="facts">')
            for fact in facts:
                tone = " is-%s" % fact["tone"] if fact["tone"] else ""
                hint = "<small> &middot; %s</small>" % _e(fact["hint"]) if fact["hint"] else ""
                parts.append('<dt>%s</dt><dd class="%s">%s%s</dd>' % (_label_html(fact["label"]), tone.strip(), _e(fact["value"]), hint))
            parts.append("</dl>")
        if payload.get("status") != "ok":
            parts.append('<p class="degraded-note">%s &middot; %s</p>' % (_e(labels.get(payload.get("status"), payload.get("status"))), _e(payload.get("reason") or "")))
        parts.append("</section>")
    parts.append("</div>")
    parts.append(_compat_html(dataset, labels))
    parts.append(_scope_html(labels, lang))
    parts.append('<p class="no-match">%s</p>' % labels["no_match"])
    parts.append("</section>")
    return "".join(parts)


def _data_view(dataset, labels, lang):
    domains = dataset.get("run", {}).get("domains", [])
    payloads = dataset.get("domains") or {}
    parts = ['<section class="view" id="data" role="tabpanel" hidden>']
    parts.append('<p class="view-intro">%s</p>' % _e(labels["data_intro"]))
    parts.append('<div class="index">')
    for name in domains:
        parts.append('<a class="chip" href="#domain-%s">%s</a>' % (_e(name), _e(i18n.domain_label(lang, name))))
    parts.append("</div>")
    for name in domains:
        payload = payloads.get(name) or {}
        status = payload.get("status", "unavailable")
        parts.append('<section class="domain" id="domain-%s" data-search="%s">' % (_e(name), _e(("%s %s" % (name, i18n.domain_label(lang, name))).lower())))
        parts.append('<div class="d-head"><h3>%s</h3><span class="status%s">%s</span></div>' % (
            _e(i18n.domain_label(lang, name)), "" if status == "ok" else " degraded", _e(labels.get(status, status))))
        data = {key: value for key, value in payload.items() if key != "findings"}
        parts.append('<details class="raw"><summary>%s</summary><div class="raw-body tree">%s</div></details>' % (_e(labels["raw_data"]), _render(data, labels)))
        parts.append("</section>")
    parts.append('<p class="no-match">%s</p>' % labels["no_match"])
    parts.append("</section>")
    return "".join(parts)


def render(dataset, lang="en"):
    labels = dict(i18n.labels(lang))
    labels["lang"] = lang
    system = dataset.get("system") or {}
    macos = system.get("macos") or {}
    arch = system.get("architecture") or {}
    findings = dataset.get("findings") or []
    attention = [item for item in findings if item.get("severity") in ("critical", "warning")]
    information = [item for item in findings if item.get("severity") == "info"]
    model = _dig(dataset, "domains", "hardware", "profile", "model_name") or system.get("hostname")

    parts = ["<!doctype html>", '<html lang="%s">' % _e(lang), "<head>", '<meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             "<title>%s &middot; %s</title>" % (_e(labels["title"]), _e(system.get("hostname") or "")),
             "<style>%s</style>" % STYLE, "</head>", "<body>"]

    parts.append('<div class="wrap"><header class="page">')
    parts.append("<h1>%s</h1>" % _e(labels["title"]))
    parts.append('<p class="ident"><b>%s</b> &middot; %s %s &middot; %s &middot; %s %s</p>' % (
        _e(model or ""), _e(macos.get("product") or "macOS"), _e(macos.get("version") or ""),
        _e(arch.get("native_arch") or ""), _e(labels["generated"].lower()), _e(dataset.get("generated_at") or "")))
    parts.append("</header></div>")

    parts.append('<nav class="bar"><div class="bar-inner"><div class="tabs" role="tablist">')
    quick_total = len((dataset.get("quick_fixes") or {}).get("commands") or [])
    for view_id, label, count in (("overview", labels["tab_overview"], len(dataset.get("run", {}).get("domains", []))),
                                  ("quickfix", labels["tab_quickfix"], quick_total),
                                  ("attention", labels["tab_attention"], len(attention)),
                                  ("information", labels["tab_information"], len(information)),
                                  ("data", labels["tab_system"], len(dataset.get("run", {}).get("domains", [])))):
        parts.append('<button class="tab" type="button" role="tab" data-view="%s" aria-selected="false" aria-controls="%s">%s<span class="n">%d</span></button>' % (
            _e(view_id), _e(view_id), _e(label), count))
    parts.append('</div><div class="spacer"></div>')
    parts.append('<div class="field"><input id="filter" type="search" placeholder="%s" aria-label="%s" autocomplete="off"><button id="filter-clear" type="button" hidden aria-label="%s">&times;</button></div>' % (
        _e(labels["filter"]), _e(labels["filter"]), _e(labels["clear"])))
    parts.append("</div></nav>")

    parts.append('<main class="wrap">')
    parts.append(_overview_view(dataset, labels, lang))
    parts.append(_quickfix_view(dataset, labels, lang))
    parts.append(_grouped_view("attention", attention, dataset, labels, lang, labels["attention_intro"]))
    parts.append(_grouped_view("information", information, dataset, labels, lang, labels["information_intro"]))
    parts.append(_data_view(dataset, labels, lang))
    parts.append("</main>")

    parts.append('<div class="wrap"><footer>%s &middot; macverify %s &middot; %s</footer></div>' % (
        _e(labels["offline_note"]), _e((dataset.get("tool") or {}).get("version") or ""), _e(labels["commands_note"])))
    parts.append('<div id="tip" role="tooltip" aria-hidden="true"></div>')
    parts.append("<script>%s</script>" % SCRIPT)
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"
