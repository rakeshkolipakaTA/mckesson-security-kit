export function render(el, html) {
  el.innerHTML = html;                                                 // DOM XSS
}
