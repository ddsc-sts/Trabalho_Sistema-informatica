// Filtro de busca e ordenação
document.addEventListener('DOMContentLoaded', () => {
    const search = document.getElementById('search');
    const sort = document.getElementById('sort');
    const products = Array.from(document.querySelectorAll('.products-grid .card'));
    const container = document.getElementById('product-list');
  
    function render(list) {
      container.innerHTML = '';
      list.forEach(p => container.appendChild(p));
    }
  
    search.addEventListener('input', () => {
      const term = search.value.toLowerCase();
      const filtered = products.filter(p => p.dataset.name.toLowerCase().includes(term));
      render(filtered);
    });
  
    sort.addEventListener('change', () => {
      let sorted = [...products];
      if (sort.value === 'asc') sorted.sort((a, b) => a.dataset.price - b.dataset.price);
      if (sort.value === 'desc') sorted.sort((a, b) => b.dataset.price - a.dataset.price);
      render(sorted);
    });
  });
  