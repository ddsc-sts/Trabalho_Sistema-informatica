// Seleciona o body e o checkbox
const body = document.body;
const toggle = document.getElementById('theme-toggle');


// Função para aplicar tema
function applyTheme(theme) {
  if (theme === 'dark') {
    body.classList.add('dark');
    toggle.checked = true;
  } else {
    body.classList.remove('dark');
    toggle.checked = false;
  }
}

// Checa se o usuário já tem preferência salva
const savedTheme = localStorage.getItem('theme') || 'light';
applyTheme(savedTheme);

// Alterna o tema quando clicar no checkbox
toggle.addEventListener('change', () => {
  const theme = toggle.checked ? 'dark' : 'light';
  applyTheme(theme);
  localStorage.setItem('theme', theme);
});

